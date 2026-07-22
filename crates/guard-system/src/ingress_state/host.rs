//! Linux systemd·Nginx·TLS·listener public ingress adapter입니다.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use super::format::{IngressManifest, ServiceRecord};
use super::{
    ACTIVE_CONFIG, EDGE_SERVICE, IngressStateError, IngressStateStore, NGINX_SERVICE, io_error,
};
use crate::OwnedProgram;

impl IngressStateStore {
    pub(super) fn validate_runtime_boundary(&self) -> Result<(), IngressStateError> {
        if !self.config.snapshot_root.is_absolute() {
            return Err(IngressStateError::Contract(
                "snapshot root는 절대 경로여야 합니다".to_owned(),
            ));
        }
        if let Some(root) = &self.config.test_root {
            if !root.is_absolute()
                || self
                    .config
                    .test_state_root
                    .as_ref()
                    .is_none_or(|state| !state.is_absolute())
            {
                return Err(IngressStateError::Contract(
                    "fixture root와 state root는 절대 경로여야 합니다".to_owned(),
                ));
            }
        } else if !rustix::process::geteuid().is_root() {
            return Err(IngressStateError::Contract(
                "ingress snapshot과 restore에는 root 권한이 필요합니다".to_owned(),
            ));
        }
        Ok(())
    }

    pub(super) fn logical_path(&self, logical: &str) -> Result<PathBuf, IngressStateError> {
        let path = Path::new(logical);
        if !path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        {
            return Err(IngressStateError::Contract(format!(
                "logical path가 절대 정규 경로가 아닙니다: {logical}"
            )));
        }
        Ok(self.config.test_root.as_ref().map_or_else(
            || path.to_path_buf(),
            |root| root.join(path.strip_prefix("/").unwrap_or(path)),
        ))
    }

    pub(super) fn ensure_safe_parent(&self, destination: &Path) -> Result<(), IngressStateError> {
        let parent = destination.parent().ok_or_else(|| {
            IngressStateError::Contract("restore destination parent가 없습니다".to_owned())
        })?;
        let (mut current, relative) = if let Some(root) = &self.config.test_root {
            let relative = parent.strip_prefix(root).map_err(|_| {
                IngressStateError::Contract("fixture path가 root를 벗어났습니다".to_owned())
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
                    return Err(IngressStateError::Contract(format!(
                        "symlink parent를 통한 restore를 거부했습니다: {}",
                        current.display()
                    )));
                }
                Ok(metadata) if !metadata.is_dir() => {
                    return Err(IngressStateError::Contract(format!(
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

    pub(super) fn machine_id_hash(&self) -> Result<String, IngressStateError> {
        let machine_id = self.logical_path("/etc/machine-id")?;
        if machine_id.is_file() {
            return hash_file(&machine_id);
        }
        if self.config.test_root.is_some() {
            return Ok(hex_digest(b"test-machine\n"));
        }
        Ok(hex_digest(b"missing"))
    }

    pub(super) fn service_state(&mut self, unit: &str) -> Result<ServiceRecord, IngressStateError> {
        validate_unit(unit)?;
        if let Some(root) = &self.config.test_state_root {
            return Ok(ServiceRecord {
                unit: unit.to_owned(),
                enabled: read_first_line(&root.join(format!("{unit}.enabled")))?
                    .unwrap_or_else(|| "disabled".to_owned()),
                active: read_first_line(&root.join(format!("{unit}.active")))?
                    .unwrap_or_else(|| "inactive".to_owned()),
            });
        }
        let enabled = self.runner.run_accepting(
            OwnedProgram::Systemctl,
            &["is-enabled".to_owned(), unit.to_owned()],
            None,
            &[],
            &[0, 1, 3, 4],
        )?;
        let enabled_value = first_line_or(&enabled.stdout, "not-found");
        self.record_audit(enabled.audit);
        let active = self.runner.run_accepting(
            OwnedProgram::Systemctl,
            &["is-active".to_owned(), unit.to_owned()],
            None,
            &[],
            &[0, 3, 4],
        )?;
        let active_value = first_line_or(&active.stdout, "inactive");
        self.record_audit(active.audit);
        Ok(ServiceRecord {
            unit: unit.to_owned(),
            enabled: enabled_value,
            active: active_value,
        })
    }

    pub(super) fn set_service_enablement(
        &mut self,
        state: &ServiceRecord,
    ) -> Result<(), IngressStateError> {
        validate_unit(&state.unit)?;
        if let Some(root) = &self.config.test_state_root {
            write_state(
                &root.join(format!("{}.enabled", state.unit)),
                &state.enabled,
            )?;
            return Ok(());
        }
        let action = match state.enabled.as_str() {
            "enabled" | "enabled-runtime" | "linked" | "linked-runtime" | "alias" => "enable",
            "masked" | "masked-runtime" => "mask",
            "disabled" | "indirect" | "static" | "generated" | "transient" | "not-found" | "" => {
                "disable"
            }
            other => {
                return Err(IngressStateError::Contract(format!(
                    "지원하지 않는 service enablement입니다: unit={}, state={other}",
                    state.unit
                )));
            }
        };
        let output = self.runner.run_accepting(
            OwnedProgram::Systemctl,
            &[action.to_owned(), state.unit.clone()],
            None,
            &[],
            &[0, 1],
        )?;
        self.record_audit(output.audit);
        Ok(())
    }

    pub(super) fn set_service_activity(
        &mut self,
        state: &ServiceRecord,
    ) -> Result<(), IngressStateError> {
        validate_unit(&state.unit)?;
        let active = matches!(state.active.as_str(), "active" | "activating" | "reloading");
        if !active
            && !matches!(
                state.active.as_str(),
                "inactive" | "failed" | "deactivating" | "unknown" | ""
            )
        {
            return Err(IngressStateError::Contract(format!(
                "지원하지 않는 service activity입니다: unit={}, state={}",
                state.unit, state.active
            )));
        }
        if let Some(root) = &self.config.test_state_root {
            write_state(
                &root.join(format!("{}.active", state.unit)),
                if active { "active" } else { "inactive" },
            )?;
            return Ok(());
        }
        let action = if active && state.unit == NGINX_SERVICE {
            "restart"
        } else if active {
            "start"
        } else {
            "stop"
        };
        let output = self.runner.run_accepting(
            OwnedProgram::Systemctl,
            &[action.to_owned(), state.unit.clone()],
            None,
            &[],
            &[0, 1, 5],
        )?;
        self.record_audit(output.audit);
        Ok(())
    }

    pub(super) fn daemon_reload(&mut self) -> Result<(), IngressStateError> {
        if self.config.test_root.is_some() {
            return Ok(());
        }
        let output = self.runner.run(
            OwnedProgram::Systemctl,
            &["daemon-reload".to_owned()],
            None,
            &[],
        )?;
        self.record_audit(output.audit);
        Ok(())
    }

    pub(super) fn validate_candidate_manifest(
        &mut self,
        snapshot: &Path,
        manifest: &IngressManifest,
    ) -> Result<(), IngressStateError> {
        if self.config.test_root.is_some() {
            return Ok(());
        }
        let config_record = manifest
            .files
            .iter()
            .find(|record| record.logical == ACTIVE_CONFIG)
            .ok_or_else(|| IngressStateError::Contract("config payload가 없습니다".to_owned()))?;
        let config_path = snapshot.join(&config_record.payload);
        let checked = self.runner.run(
            OwnedProgram::VpsGuard,
            &[
                "check-config".to_owned(),
                "--config".to_owned(),
                config_path.display().to_string(),
            ],
            None,
            &[],
        )?;
        self.record_audit(checked.audit);
        let nginx_record = manifest.files.first().ok_or_else(|| {
            IngressStateError::Contract("Nginx candidate payload가 없습니다".to_owned())
        })?;
        let candidate = snapshot.join(&nginx_record.payload);
        self.validate_nginx_file(&candidate)
    }

    pub(super) fn validate_nginx_file(
        &mut self,
        candidate: &Path,
    ) -> Result<(), IngressStateError> {
        let source = fs::read_to_string("/etc/nginx/nginx.conf").map_err(|error| {
            io_error(
                "read_nginx_config",
                Path::new("/etc/nginx/nginx.conf"),
                error,
            )
        })?;
        let marker = "include /etc/nginx/sites-enabled/*;";
        if !source.contains(marker) {
            return Err(IngressStateError::Contract(
                "Nginx site include marker가 없습니다".to_owned(),
            ));
        }
        let rendered = source.replacen(marker, &format!("include {};", candidate.display()), 1);
        let path = PathBuf::from(format!(
            "/etc/nginx/vpsguard-ingress-restore-{}.conf",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        let mut file = options
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|source| io_error("create_nginx_candidate", &path, source))?;
        file.write_all(rendered.as_bytes())
            .map_err(|source| io_error("write_nginx_candidate", &path, source))?;
        file.sync_all()
            .map_err(|source| io_error("sync_nginx_candidate", &path, source))?;
        let result = self.runner.run(
            OwnedProgram::Nginx,
            &[
                "-t".to_owned(),
                "-p".to_owned(),
                "/etc/nginx/".to_owned(),
                "-c".to_owned(),
                path.display().to_string(),
            ],
            None,
            &[],
        );
        let _ignored = fs::remove_file(&path);
        let output = result?;
        self.record_audit(output.audit);
        Ok(())
    }
}

fn validate_unit(unit: &str) -> Result<(), IngressStateError> {
    if matches!(unit, EDGE_SERVICE | NGINX_SERVICE) {
        Ok(())
    } else {
        Err(IngressStateError::Contract(format!(
            "허용되지 않은 service입니다: {unit}"
        )))
    }
}

pub(super) fn read_first_line(path: &Path) -> Result<Option<String>, IngressStateError> {
    match fs::read_to_string(path) {
        Ok(value) => Ok(value.lines().next().map(str::to_owned)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(io_error("read_state", path, source)),
    }
}

pub(super) fn write_state(path: &Path, value: &str) -> Result<(), IngressStateError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|source| io_error("create_state_root", parent, source))?;
    }
    fs::write(path, format!("{value}\n")).map_err(|source| io_error("write_state", path, source))
}

fn first_line_or(value: &str, fallback: &str) -> String {
    value
        .lines()
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .unwrap_or(fallback)
        .to_owned()
}

fn hash_file(path: &Path) -> Result<String, IngressStateError> {
    let bytes = fs::read(path).map_err(|source| io_error("read_machine_id", path, source))?;
    Ok(hex_digest(&bytes))
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut value = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ignored = write!(&mut value, "{byte:02x}");
    }
    value
}
