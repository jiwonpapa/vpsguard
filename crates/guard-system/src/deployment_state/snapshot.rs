//! Legacy v1 deployment snapshot의 bounded serialization과 정확 복원을 구현합니다.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use super::snapshot_files::{
    copy_file, create_private_dir, create_private_dir_all, hash_file, lines_to_bytes,
    remove_owned_directory_if_present, remove_owned_file_if_present, replace_file, replace_symlink,
    snapshot_timestamp, sync_dir, write_private,
};
use super::snapshot_format::{
    LoadedSnapshot, collect_payloads, collect_regular_files, parse_allowed_set,
    parse_directory_state, parse_key_values, parse_service_state, parse_symlinks,
    read_metadata_lines, validate_complete_file_state, validate_field, validate_symlink_target,
    verify_checksums,
};
use super::{
    DEPLOYMENT_SNAPSHOT_SCHEMA_VERSION, DeploymentStateError, DeploymentStateStore,
    OWNED_DIRECTORIES, OWNED_FILES, OWNED_SERVICES, io_error,
};

static SNAPSHOT_SEQUENCE: AtomicU32 = AtomicU32::new(0);

impl DeploymentStateStore {
    /// 현재 VPSGuard-owned 배포 상태를 v1 호환 snapshot으로 원자 확정합니다.
    ///
    /// # Errors
    ///
    /// authority, bounded path, filesystem 또는 read-back 오류를 반환합니다.
    pub fn create_snapshot(&mut self) -> Result<PathBuf, DeploymentStateError> {
        self.validate_runtime_boundary()?;
        create_private_dir_all(&self.config.snapshot_root)?;
        let timestamp = snapshot_timestamp();
        let sequence = SNAPSHOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let suffix = format!("{}{:06}", std::process::id(), sequence % 1_000_000);
        let final_name = format!("deploy-{timestamp}-{suffix}");
        let pending_name = format!(".pending-{timestamp}-{suffix}");
        let final_path = self.config.snapshot_root.join(final_name);
        let pending_path = self.config.snapshot_root.join(pending_name);
        if final_path.exists() || pending_path.exists() {
            return Err(DeploymentStateError::Contract(format!(
                "같은 초의 snapshot path가 이미 존재합니다: {}",
                final_path.display()
            )));
        }
        create_private_dir(&pending_path)?;
        let result = self.populate_snapshot(&pending_path);
        if let Err(error) = result {
            let _ignored = fs::remove_dir_all(&pending_path);
            return Err(error);
        }
        sync_dir(&pending_path)?;
        fs::rename(&pending_path, &final_path)
            .map_err(|source| io_error("commit_snapshot", &final_path, source))?;
        sync_dir(&self.config.snapshot_root)?;
        Ok(final_path)
    }

    /// checksum, machine identity와 protected read-back을 검증합니다.
    ///
    /// # Errors
    ///
    /// snapshot 변조, 다른 machine 또는 protected drift를 반환합니다.
    pub fn verify_snapshot(&mut self, path: &Path) -> Result<(), DeploymentStateError> {
        self.validate_runtime_boundary()?;
        let snapshot = self.load_snapshot(path)?;
        self.verify_protected_state(&snapshot)
    }

    /// 복구 후 VPSGuard-owned 상태와 protected boundary를 모두 read-back합니다.
    ///
    /// # Errors
    ///
    /// file·symlink·directory·service·account 또는 protected 상태 drift를 반환합니다.
    pub fn verify_restored_snapshot(&mut self, path: &Path) -> Result<(), DeploymentStateError> {
        self.validate_runtime_boundary()?;
        let snapshot = self.load_snapshot(path)?;
        self.verify_owned_state(&snapshot)?;
        self.verify_protected_state(&snapshot)
    }

    /// 검증된 snapshot으로 VPSGuard-owned 상태만 복구합니다.
    ///
    /// # Errors
    ///
    /// 복구 전 검증, bounded mutation, service/account 또는 사후 read-back 오류를 반환합니다.
    pub fn restore_snapshot(&mut self, path: &Path) -> Result<(), DeploymentStateError> {
        self.validate_runtime_boundary()?;
        let snapshot = self.load_snapshot(path)?;
        self.verify_protected_state(&snapshot)?;

        for service in &snapshot.services {
            self.stop_service(&service.unit)?;
        }
        let mut present_directories: Vec<_> = snapshot
            .directories
            .iter()
            .filter_map(|(path, present)| present.then_some(path.as_str()))
            .collect();
        present_directories.sort_by_key(|path| path.matches('/').count());
        for logical in present_directories {
            let path = self.logical_path(logical)?;
            self.ensure_safe_parent(&path.join(".vpsguard-boundary-check"))?;
        }
        for logical in &snapshot.absent_paths {
            let destination = self.logical_path(logical)?;
            self.ensure_safe_parent(&destination)?;
            remove_owned_file_if_present(&destination)?;
            self.test_fault_after_mutation()?;
        }
        for (logical, target) in &snapshot.symlinks {
            let destination = self.logical_path(logical)?;
            self.ensure_safe_parent(&destination)?;
            replace_symlink(&destination, target)?;
            self.test_fault_after_mutation()?;
        }
        for (logical, source) in &snapshot.payloads {
            let destination = self.logical_path(logical)?;
            self.ensure_safe_parent(&destination)?;
            replace_file(source, &destination, self.config.test_root.is_none())?;
            self.test_fault_after_mutation()?;
        }

        self.daemon_reload()?;
        for service in &snapshot.services {
            self.set_service_state(service)?;
        }
        let mut absent_directories: Vec<_> = snapshot
            .directories
            .iter()
            .filter_map(|(path, present)| (!present).then_some(path.as_str()))
            .collect();
        absent_directories.sort_by_key(|path| std::cmp::Reverse(path.matches('/').count()));
        for logical in absent_directories {
            let path = self.logical_path(logical)?;
            self.ensure_safe_parent(&path.join(".vpsguard-boundary-check"))?;
            remove_owned_directory_if_present(&path)?;
        }
        if !snapshot.account_present {
            self.remove_account_if_present()?;
        }
        self.verify_owned_state(&snapshot)?;
        self.verify_protected_state(&snapshot)
    }

    fn populate_snapshot(&mut self, snapshot: &Path) -> Result<(), DeploymentStateError> {
        let payload_root = snapshot.join("payload");
        create_private_dir(&payload_root)?;
        let account_state = if self.account_exists()? {
            "present"
        } else {
            "absent"
        };
        write_private(
            &snapshot.join("manifest.tsv"),
            format!(
                "schema_version|{DEPLOYMENT_SNAPSHOT_SCHEMA_VERSION}\nmachine_id_sha256|{}\naccount_vps_guard|{account_state}\n",
                self.machine_id_hash()?
            )
            .as_bytes(),
        )?;

        let mut absent = String::new();
        let mut symlinks = String::new();
        for logical in OWNED_FILES {
            let source = self.logical_path(logical)?;
            let metadata = match fs::symlink_metadata(&source) {
                Ok(metadata) => Some(metadata),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(source_error) => {
                    return Err(io_error("snapshot_metadata", &source, source_error));
                }
            };
            match metadata {
                Some(metadata) if metadata.file_type().is_symlink() => {
                    let target = fs::read_link(&source)
                        .map_err(|error| io_error("snapshot_read_link", &source, error))?;
                    validate_symlink_target(&target)?;
                    let target_text = target.to_str().ok_or_else(|| {
                        DeploymentStateError::Contract(format!(
                            "symlink target이 UTF-8이 아닙니다: {logical}"
                        ))
                    })?;
                    symlinks.push_str(logical);
                    symlinks.push('|');
                    symlinks.push_str(target_text);
                    symlinks.push('\n');
                }
                Some(metadata) if metadata.is_file() => {
                    let destination = payload_root.join(logical.trim_start_matches('/'));
                    copy_file(
                        &source,
                        &destination,
                        &metadata,
                        self.config.test_root.is_none(),
                    )?;
                }
                Some(_) => {
                    return Err(DeploymentStateError::Contract(format!(
                        "owned path가 regular file 또는 symlink가 아닙니다: {logical}"
                    )));
                }
                None => {
                    absent.push_str(logical);
                    absent.push('\n');
                }
            }
        }
        write_private(&snapshot.join("absent-paths.txt"), absent.as_bytes())?;
        write_private(&snapshot.join("symlink-state.tsv"), symlinks.as_bytes())?;

        let mut directories = String::new();
        for logical in OWNED_DIRECTORIES {
            let path = self.logical_path(logical)?;
            let state = match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(DeploymentStateError::Contract(format!(
                        "owned directory가 symlink입니다: {logical}"
                    )));
                }
                Ok(metadata) if metadata.is_dir() => "present",
                Ok(_) => {
                    return Err(DeploymentStateError::Contract(format!(
                        "owned directory path가 directory가 아닙니다: {logical}"
                    )));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => "absent",
                Err(source) => return Err(io_error("directory_state", &path, source)),
            };
            directories.push_str(&format!("{logical}|{state}\n"));
        }
        write_private(
            &snapshot.join("directory-state.tsv"),
            directories.as_bytes(),
        )?;

        let mut services = String::new();
        for unit in OWNED_SERVICES {
            let state = self.service_state(unit)?;
            validate_field(&state.enabled, "service enablement")?;
            validate_field(&state.active, "service activity")?;
            services.push_str(&format!(
                "{}|{}|{}\n",
                state.unit, state.enabled, state.active
            ));
        }
        write_private(&snapshot.join("service-state.tsv"), services.as_bytes())?;
        write_private(
            &snapshot.join("protected.tsv"),
            lines_to_bytes(&self.protected_state()?).as_slice(),
        )?;
        write_private(
            &snapshot.join("listeners.txt"),
            lines_to_bytes(&self.listener_state()?).as_slice(),
        )?;
        let files = collect_regular_files(snapshot, false)?;
        let mut sums = String::new();
        for file in files {
            let relative = file.strip_prefix(snapshot).map_err(|_| {
                DeploymentStateError::Contract(
                    "snapshot checksum path가 root를 벗어났습니다".to_owned(),
                )
            })?;
            sums.push_str(&format!(
                "{}  ./{}\n",
                hash_file(&file)?,
                relative.display()
            ));
        }
        write_private(&snapshot.join("SHA256SUMS"), sums.as_bytes())
    }

    fn load_snapshot(&mut self, path: &Path) -> Result<LoadedSnapshot, DeploymentStateError> {
        self.validate_snapshot_path(path)?;
        verify_checksums(path)?;
        let manifest = read_metadata_lines(&path.join("manifest.tsv"))?;
        let manifest = parse_key_values(&manifest, "manifest")?;
        let schema = manifest.get("schema_version").ok_or_else(|| {
            DeploymentStateError::Contract("manifest schema_version이 없습니다".to_owned())
        })?;
        if schema != &DEPLOYMENT_SNAPSHOT_SCHEMA_VERSION.to_string() {
            return Err(DeploymentStateError::Contract(format!(
                "지원하지 않는 deployment snapshot schema입니다: {schema}"
            )));
        }
        let machine_id_sha256 = manifest
            .get("machine_id_sha256")
            .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .cloned()
            .ok_or_else(|| {
                DeploymentStateError::Contract("machine identity hash가 잘못됐습니다".to_owned())
            })?;
        if self.machine_id_hash()? != machine_id_sha256 {
            return Err(DeploymentStateError::Contract(
                "snapshot이 다른 server에 속합니다".to_owned(),
            ));
        }
        let account_present = match manifest.get("account_vps_guard").map(String::as_str) {
            Some("present") => true,
            Some("absent") => false,
            _ => {
                return Err(DeploymentStateError::Contract(
                    "account_vps_guard 상태가 잘못됐습니다".to_owned(),
                ));
            }
        };
        if manifest.len() != 3 {
            return Err(DeploymentStateError::Contract(
                "manifest에 알 수 없는 field가 있습니다".to_owned(),
            ));
        }

        let absent_paths = parse_allowed_set(
            &read_metadata_lines(&path.join("absent-paths.txt"))?,
            &OWNED_FILES,
            "absent path",
        )?;
        let symlinks = parse_symlinks(&read_metadata_lines(&path.join("symlink-state.tsv"))?)?;
        let payloads = collect_payloads(path)?;
        validate_complete_file_state(&absent_paths, &symlinks, &payloads)?;
        let directories =
            parse_directory_state(&read_metadata_lines(&path.join("directory-state.tsv"))?)?;
        let services = parse_service_state(&read_metadata_lines(&path.join("service-state.tsv"))?)?;
        let protected = read_metadata_lines(&path.join("protected.tsv"))?;
        super::snapshot_format::validate_protected_state(&protected)?;
        let listeners: BTreeSet<_> = read_metadata_lines(&path.join("listeners.txt"))?
            .into_iter()
            .filter(|line| !line.is_empty())
            .collect();
        Ok(LoadedSnapshot {
            machine_id_sha256,
            account_present,
            absent_paths,
            symlinks,
            payloads,
            directories,
            services,
            protected,
            listeners,
        })
    }

    fn verify_protected_state(
        &mut self,
        snapshot: &LoadedSnapshot,
    ) -> Result<(), DeploymentStateError> {
        if self.machine_id_hash()? != snapshot.machine_id_sha256 {
            return Err(DeploymentStateError::Contract(
                "snapshot이 다른 server에 속합니다".to_owned(),
            ));
        }
        if self.protected_state()? != snapshot.protected {
            return Err(DeploymentStateError::Contract(
                "protected directory identity 또는 service state가 drift했습니다".to_owned(),
            ));
        }
        let current: BTreeSet<_> = self.listener_state()?.into_iter().collect();
        let missing: Vec<_> = snapshot.listeners.difference(&current).cloned().collect();
        if !missing.is_empty() {
            return Err(DeploymentStateError::Contract(format!(
                "protected listener가 사라졌습니다: {}",
                missing.join(",")
            )));
        }
        Ok(())
    }

    fn validate_snapshot_path(&self, path: &Path) -> Result<(), DeploymentStateError> {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        let valid_name = name.starts_with("deploy-")
            && name.len() <= 128
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
        if path.parent() != Some(self.config.snapshot_root.as_path()) || !valid_name {
            return Err(DeploymentStateError::Contract(format!(
                "snapshot은 {}의 deploy-* direct child여야 합니다",
                self.config.snapshot_root.display()
            )));
        }
        let metadata = fs::symlink_metadata(path)
            .map_err(|source| io_error("snapshot_metadata", path, source))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(DeploymentStateError::Contract(
                "snapshot path가 실제 directory가 아닙니다".to_owned(),
            ));
        }
        Ok(())
    }

    fn ensure_safe_parent(&self, destination: &Path) -> Result<(), DeploymentStateError> {
        let parent = destination.parent().ok_or_else(|| {
            DeploymentStateError::Contract("restore destination parent가 없습니다".to_owned())
        })?;
        let (mut current, relative) = if let Some(root) = &self.config.test_root {
            let relative = parent.strip_prefix(root).map_err(|_| {
                DeploymentStateError::Contract(
                    "fixture restore path가 root를 벗어났습니다".to_owned(),
                )
            })?;
            (root.clone(), relative)
        } else {
            (
                PathBuf::from("/"),
                parent.strip_prefix("/").unwrap_or(parent),
            )
        };
        for component in relative.components() {
            current.push(component);
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(DeploymentStateError::Contract(format!(
                        "symlink parent를 통한 restore를 거부했습니다: {}",
                        current.display()
                    )));
                }
                Ok(metadata) if !metadata.is_dir() => {
                    return Err(DeploymentStateError::Contract(format!(
                        "restore parent가 directory가 아닙니다: {}",
                        current.display()
                    )));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&current)
                        .map_err(|source| io_error("create_restore_parent", &current, source))?;
                }
                Err(source) => return Err(io_error("restore_parent_metadata", &current, source)),
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn test_fault_after_mutation(&mut self) -> Result<(), DeploymentStateError> {
        if self.fail_after_first_mutation {
            self.fail_after_first_mutation = false;
            return Err(DeploymentStateError::Contract(
                "fault fixture: first mutation 이후 실패".to_owned(),
            ));
        }
        Ok(())
    }

    #[cfg(not(test))]
    fn test_fault_after_mutation(&mut self) -> Result<(), DeploymentStateError> {
        Ok(())
    }
}
