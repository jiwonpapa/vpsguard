//! Ingress snapshot의 bounded 생성, exact restore와 read-back을 구현합니다.

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use super::files::{
    copy_snapshot_file, create_private_dir, create_private_dir_all, remove_file_if_present,
    replace_file, replace_symlink, sync_dir, timestamp, write_checksums, write_private,
};
use super::format::{
    FileRecord, IngressManifest, Presence, ServiceRecord, hash_file, load_manifest,
};
use super::{
    DEFAULT_DENY, DEFAULT_DENY_TARGET, FILE_SPECS, INGRESS_SNAPSHOT_SCHEMA_VERSION,
    IngressStateError, IngressStateStore, io_error,
};
use crate::IngressTopology;

static SNAPSHOT_SEQUENCE: AtomicU32 = AtomicU32::new(0);

impl IngressStateStore {
    /// 현재 public ingress 상태를 checksum snapshot으로 원자 확정합니다.
    ///
    /// # Errors
    ///
    /// authority, bounded path, filesystem 또는 read-back 오류를 반환합니다.
    pub fn create_snapshot(&mut self, label: &str) -> Result<PathBuf, IngressStateError> {
        self.validate_runtime_boundary()?;
        if !matches!(label, "direct" | "rollback") {
            return Err(IngressStateError::Contract(
                "snapshot label은 direct 또는 rollback이어야 합니다".to_owned(),
            ));
        }
        create_private_dir_all(&self.config.snapshot_root)?;
        let timestamp = timestamp();
        let sequence = SNAPSHOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let suffix = format!("{}{:06}", std::process::id(), sequence % 1_000_000);
        let final_path = self
            .config
            .snapshot_root
            .join(format!("direct-{timestamp}-{suffix}-{label}"));
        let pending = self
            .config
            .snapshot_root
            .join(format!(".pending-{timestamp}-{suffix}-{label}"));
        if final_path.exists() || pending.exists() {
            return Err(IngressStateError::Contract(format!(
                "snapshot path가 이미 존재합니다: {}",
                final_path.display()
            )));
        }
        create_private_dir(&pending)?;
        if let Err(error) = self.populate_snapshot(&pending, label) {
            let _ignored = fs::remove_dir_all(&pending);
            return Err(error);
        }
        sync_dir(&pending)?;
        fs::rename(&pending, &final_path)
            .map_err(|source| io_error("commit_snapshot", &final_path, source))?;
        sync_dir(&self.config.snapshot_root)?;
        Ok(final_path)
    }

    /// checksum, machine과 non-web listener 경계를 검증합니다.
    ///
    /// # Errors
    ///
    /// snapshot 변조, 다른 machine 또는 protected listener drift를 반환합니다.
    pub fn verify_snapshot(&mut self, path: &Path) -> Result<(), IngressStateError> {
        self.validate_runtime_boundary()?;
        let manifest = self.load_snapshot(path)?;
        self.verify_protected(&manifest)
    }

    /// snapshot target topology를 반환합니다.
    ///
    /// # Errors
    ///
    /// snapshot 검증 실패를 반환합니다.
    pub fn snapshot_topology(&mut self, path: &Path) -> Result<IngressTopology, IngressStateError> {
        let manifest = self.load_snapshot(path)?;
        Ok(if manifest.edge_public {
            IngressTopology::VpsGuardPublic
        } else {
            IngressTopology::NginxPublic
        })
    }

    /// target VPSGuard·Nginx 후보를 public 변경 전에 검사합니다.
    ///
    /// # Errors
    ///
    /// checksum, config 또는 Nginx 후보 검증 실패를 반환합니다.
    pub fn validate_candidate(&mut self, path: &Path) -> Result<(), IngressStateError> {
        let manifest = self.load_snapshot(path)?;
        self.verify_protected(&manifest)?;
        self.validate_candidate_manifest(path, &manifest)
    }

    /// 검증된 snapshot으로 ingress-owned 상태를 복구하고 순단 milliseconds를 반환합니다.
    ///
    /// # Errors
    ///
    /// bounded file·service mutation 또는 topology 계약 오류를 반환합니다.
    pub fn restore_snapshot(&mut self, path: &Path) -> Result<u64, IngressStateError> {
        self.validate_runtime_boundary()?;
        let manifest = self.load_snapshot(path)?;
        self.verify_protected(&manifest)?;
        validate_target_services(&manifest)?;

        for record in &manifest.files {
            let destination = self.logical_path(&record.logical)?;
            self.ensure_safe_parent(&destination)?;
            match record.presence {
                Presence::Present => {
                    replace_file(
                        &path.join(&record.payload),
                        &destination,
                        record,
                        self.config.test_root.is_none(),
                    )?;
                }
                Presence::Absent => remove_file_if_present(&destination)?,
            }
            self.test_fault_after_mutation()?;
        }
        let deny = self.logical_path(DEFAULT_DENY)?;
        self.ensure_safe_parent(&deny)?;
        match manifest.default_deny {
            Presence::Present => replace_symlink(&deny, Path::new(DEFAULT_DENY_TARGET))?,
            Presence::Absent => remove_file_if_present(&deny)?,
        }

        for state in &manifest.services {
            self.set_service_enablement(state)?;
        }
        self.daemon_reload()?;

        let started = Instant::now();
        let edge = service(&manifest.services, super::EDGE_SERVICE)?;
        let nginx = service(&manifest.services, super::NGINX_SERVICE)?;
        let edge_stopped = ServiceRecord {
            unit: edge.unit.clone(),
            enabled: edge.enabled.clone(),
            active: "inactive".to_owned(),
        };
        self.set_service_activity(&edge_stopped)?;
        self.set_service_activity(nginx)?;
        self.set_service_activity(edge)?;
        self.set_fixture_topology(manifest.edge_public)?;
        let measured: u64 = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        Ok(if self.config.test_root.is_some() {
            self.config.fixture_cutover_ms
        } else {
            measured
        })
    }

    /// 복구된 file·service·TLS·listener와 public topology를 read-back합니다.
    ///
    /// # Errors
    ///
    /// target snapshot과 실제 상태 drift를 반환합니다.
    pub fn verify_restored_snapshot(&mut self, path: &Path) -> Result<(), IngressStateError> {
        let manifest = self.load_snapshot(path)?;
        self.verify_owned_files(path, &manifest)?;
        self.verify_services(&manifest)?;
        self.verify_protected(&manifest)?;
        let expected = if manifest.edge_public {
            IngressTopology::VpsGuardPublic
        } else {
            IngressTopology::NginxPublic
        };
        if self.current_topology()? != expected {
            return Err(IngressStateError::Contract(
                "public 443 process owner가 snapshot topology와 다릅니다".to_owned(),
            ));
        }
        if self.public_edge_header()? != manifest.public_edge_header {
            return Err(IngressStateError::Contract(
                "public x-vps-guard header가 snapshot topology와 다릅니다".to_owned(),
            ));
        }
        let file = self.certificate_fingerprint()?;
        let served = self.served_certificate_fingerprint()?;
        if file != served {
            return Err(IngressStateError::Contract(
                "제공 중인 인증서와 현재 certificate file이 다릅니다".to_owned(),
            ));
        }
        Ok(())
    }

    fn populate_snapshot(&mut self, snapshot: &Path, label: &str) -> Result<(), IngressStateError> {
        let mut files = Vec::new();
        for spec in FILE_SPECS {
            let source = self.logical_path(spec.logical)?;
            let metadata = match fs::symlink_metadata(&source) {
                Ok(metadata) => Some(metadata),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(source_error) => {
                    return Err(io_error("snapshot_metadata", &source, source_error));
                }
            };
            match metadata {
                Some(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                    copy_snapshot_file(&source, &snapshot.join(spec.payload), &metadata)?;
                    files.push(FileRecord {
                        logical: spec.logical.to_owned(),
                        payload: spec.payload.to_owned(),
                        presence: Presence::Present,
                        mode: metadata.mode() & 0o7777,
                        uid: Some(metadata.uid()),
                        gid: Some(metadata.gid()),
                    });
                }
                Some(_) => {
                    return Err(IngressStateError::Contract(format!(
                        "ingress path가 regular file이 아닙니다: {}",
                        spec.logical
                    )));
                }
                None if spec.required => {
                    return Err(IngressStateError::Contract(format!(
                        "필수 ingress file이 없습니다: {}",
                        spec.logical
                    )));
                }
                None => files.push(FileRecord {
                    logical: spec.logical.to_owned(),
                    payload: spec.payload.to_owned(),
                    presence: Presence::Absent,
                    mode: 0,
                    uid: None,
                    gid: None,
                }),
            }
        }
        let (default_deny, default_deny_target) = self.default_deny_state()?;
        let topology = self.current_topology()?;
        let manifest = IngressManifest {
            schema_version: INGRESS_SNAPSHOT_SCHEMA_VERSION,
            machine_id_sha256: self.machine_id_hash()?,
            label: label.to_owned(),
            files,
            default_deny,
            default_deny_target,
            services: vec![
                self.service_state(super::EDGE_SERVICE)?,
                self.service_state(super::NGINX_SERVICE)?,
            ],
            edge_public: topology == IngressTopology::VpsGuardPublic,
            public_edge_header: self.public_edge_header()?,
            certificate_fingerprint: self.certificate_fingerprint()?,
            protected_listeners: Some(self.protected_listeners()?),
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        write_private(&snapshot.join("manifest.json"), &manifest_bytes)?;
        write_checksums(snapshot)
    }

    fn load_snapshot(&mut self, path: &Path) -> Result<IngressManifest, IngressStateError> {
        self.validate_snapshot_path(path)?;
        let manifest = load_manifest(&self.config, path)?;
        if self.machine_id_hash()? != manifest.machine_id_sha256 {
            return Err(IngressStateError::Contract(
                "snapshot이 다른 server에 속합니다".to_owned(),
            ));
        }
        Ok(manifest)
    }

    fn validate_snapshot_path(&self, path: &Path) -> Result<(), IngressStateError> {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        let valid_name = name.starts_with("direct-")
            && name.len() <= 160
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
        if path.parent() != Some(self.config.snapshot_root.as_path()) || !valid_name {
            return Err(IngressStateError::Contract(format!(
                "snapshot은 {}의 direct-* direct child여야 합니다",
                self.config.snapshot_root.display()
            )));
        }
        let metadata = fs::symlink_metadata(path)
            .map_err(|source| io_error("snapshot_metadata", path, source))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(IngressStateError::Contract(
                "snapshot path가 실제 directory가 아닙니다".to_owned(),
            ));
        }
        Ok(())
    }

    fn default_deny_state(&self) -> Result<(Presence, String), IngressStateError> {
        let path = self.logical_path(DEFAULT_DENY)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                let target = fs::read_link(&path)
                    .map_err(|source| io_error("read_default_deny", &path, source))?;
                if target != Path::new(DEFAULT_DENY_TARGET) {
                    return Err(IngressStateError::Contract(
                        "unexpected default deny symlink target".to_owned(),
                    ));
                }
                Ok((Presence::Present, DEFAULT_DENY_TARGET.to_owned()))
            }
            Ok(_) => Err(IngressStateError::Contract(
                "default deny path는 symlink 또는 absent여야 합니다".to_owned(),
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok((Presence::Absent, String::new()))
            }
            Err(source) => Err(io_error("default_deny_metadata", &path, source)),
        }
    }

    fn verify_owned_files(
        &self,
        snapshot: &Path,
        manifest: &IngressManifest,
    ) -> Result<(), IngressStateError> {
        for record in &manifest.files {
            let destination = self.logical_path(&record.logical)?;
            match record.presence {
                Presence::Absent if destination.exists() => {
                    return Err(IngressStateError::Contract(format!(
                        "absent ingress path가 남았습니다: {}",
                        record.logical
                    )));
                }
                Presence::Absent => {}
                Presence::Present => {
                    let metadata = fs::symlink_metadata(&destination)
                        .map_err(|source| io_error("restored_metadata", &destination, source))?;
                    let actual_hash = hash_file(&destination)?;
                    let expected_hash = hash_file(&snapshot.join(&record.payload))?;
                    let actual_mode = metadata.mode() & 0o7777;
                    let wrong_type = !metadata.is_file() || metadata.file_type().is_symlink();
                    let wrong_owner = record.uid.is_some_and(|uid| uid != metadata.uid())
                        || record.gid.is_some_and(|gid| gid != metadata.gid());
                    if wrong_type
                        || actual_hash != expected_hash
                        || actual_mode != record.mode
                        || wrong_owner
                    {
                        return Err(IngressStateError::Contract(format!(
                            "restored ingress file이 snapshot과 다릅니다: {}, type={}, hash={}, mode={:04o}/{:04o}, owner={}:{} expected={:?}:{:?}",
                            record.logical,
                            !wrong_type,
                            actual_hash == expected_hash,
                            actual_mode,
                            record.mode,
                            metadata.uid(),
                            metadata.gid(),
                            record.uid,
                            record.gid
                        )));
                    }
                }
            }
        }
        let (presence, target) = self.default_deny_state()?;
        if presence != manifest.default_deny || target != manifest.default_deny_target {
            return Err(IngressStateError::Contract(
                "default deny symlink가 snapshot과 다릅니다".to_owned(),
            ));
        }
        Ok(())
    }

    fn verify_services(&mut self, manifest: &IngressManifest) -> Result<(), IngressStateError> {
        for expected in &manifest.services {
            let actual = self.service_state(&expected.unit)?;
            if actual.enabled != expected.enabled
                || active_class(&actual.active) != active_class(&expected.active)
            {
                return Err(IngressStateError::Contract(format!(
                    "service state가 snapshot과 다릅니다: {}",
                    expected.unit
                )));
            }
        }
        Ok(())
    }

    fn verify_protected(&mut self, manifest: &IngressManifest) -> Result<(), IngressStateError> {
        if let Some(expected) = &manifest.protected_listeners {
            let current = self.protected_listeners()?;
            let missing: BTreeSet<_> = expected.difference(&current).collect();
            if !missing.is_empty() {
                return Err(IngressStateError::Contract(format!(
                    "protected non-web listener가 사라졌습니다: {}",
                    missing.into_iter().cloned().collect::<Vec<_>>().join(",")
                )));
            }
        }
        let _current_certificate = self.certificate_fingerprint()?;
        Ok(())
    }

    #[cfg(test)]
    fn test_fault_after_mutation(&mut self) -> Result<(), IngressStateError> {
        if self.fail_after_first_mutation {
            self.fail_after_first_mutation = false;
            return Err(IngressStateError::Contract(
                "fault fixture: first mutation 이후 실패".to_owned(),
            ));
        }
        Ok(())
    }

    #[cfg(not(test))]
    fn test_fault_after_mutation(&mut self) -> Result<(), IngressStateError> {
        Ok(())
    }
}

fn validate_target_services(manifest: &IngressManifest) -> Result<(), IngressStateError> {
    let edge = service(&manifest.services, super::EDGE_SERVICE)?;
    let nginx = service(&manifest.services, super::NGINX_SERVICE)?;
    if manifest.edge_public && !is_active(&edge.active) {
        return Err(IngressStateError::Contract(
            "VPSGuard-public snapshot의 edge service가 inactive입니다".to_owned(),
        ));
    }
    if !manifest.edge_public && !is_active(&nginx.active) {
        return Err(IngressStateError::Contract(
            "Nginx-public snapshot의 Nginx service가 inactive입니다".to_owned(),
        ));
    }
    Ok(())
}

fn service<'a>(
    states: &'a [ServiceRecord],
    unit: &str,
) -> Result<&'a ServiceRecord, IngressStateError> {
    states
        .iter()
        .find(|state| state.unit == unit)
        .ok_or_else(|| IngressStateError::Contract(format!("service state가 없습니다: {unit}")))
}

fn is_active(value: &str) -> bool {
    matches!(value, "active" | "activating" | "reloading")
}

fn active_class(value: &str) -> bool {
    is_active(value)
}
