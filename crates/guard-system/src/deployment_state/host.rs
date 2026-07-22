//! Linux service·account·listener와 protected boundary read-back adapter입니다.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use super::{
    DeploymentStateError, DeploymentStateStore, PROTECTED_PATHS, PROTECTED_SERVICES, io_error,
};
use crate::OwnedProgram;

impl DeploymentStateStore {
    pub(crate) fn validate_runtime_boundary(&self) -> Result<(), DeploymentStateError> {
        if !self.config.snapshot_root.is_absolute() {
            return Err(DeploymentStateError::Contract(
                "snapshot root는 절대 경로여야 합니다".to_owned(),
            ));
        }
        if let Some(root) = &self.config.test_root {
            if !root.is_absolute() {
                return Err(DeploymentStateError::Contract(
                    "fixture root는 절대 경로여야 합니다".to_owned(),
                ));
            }
        } else if !rustix::process::geteuid().is_root() {
            return Err(DeploymentStateError::Contract(
                "deployment snapshot과 restore에는 root 권한이 필요합니다".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn logical_path(&self, logical: &str) -> Result<PathBuf, DeploymentStateError> {
        let path = Path::new(logical);
        if !path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        {
            return Err(DeploymentStateError::Contract(format!(
                "logical path가 절대 정규 경로가 아닙니다: {logical}"
            )));
        }
        Ok(self.config.test_root.as_ref().map_or_else(
            || path.to_path_buf(),
            |root| root.join(path.strip_prefix("/").unwrap_or(path)),
        ))
    }

    pub(crate) fn machine_id_hash(&self) -> Result<String, DeploymentStateError> {
        let machine_id = self.logical_path("/etc/machine-id")?;
        if machine_id.is_file() {
            return hash_file(&machine_id);
        }
        if self.config.test_root.is_some() {
            return Ok(hex_digest(b"test-machine\n"));
        }
        Ok("missing".to_owned())
    }

    pub(crate) fn account_exists(&mut self) -> Result<bool, DeploymentStateError> {
        if let Some(root) = &self.config.test_root {
            return Ok(root.join(".vpsguard-test/account-vps-guard").is_file());
        }
        let output = self.runner.run_accepting(
            OwnedProgram::Getent,
            &["passwd".to_owned(), "vps-guard".to_owned()],
            None,
            &[],
            &[0, 2],
        )?;
        let exists = output.audit.exit_code == Some(0) && !output.stdout.trim().is_empty();
        self.record_audit(output.audit);
        Ok(exists)
    }

    pub(crate) fn remove_account_if_present(&mut self) -> Result<(), DeploymentStateError> {
        if let Some(root) = &self.config.test_root {
            let marker = root.join(".vpsguard-test/account-vps-guard");
            if marker.exists() {
                fs::remove_file(&marker)
                    .map_err(|source| io_error("remove_account", &marker, source))?;
            }
            return Ok(());
        }
        let passwd = self.runner.run_accepting(
            OwnedProgram::Getent,
            &["passwd".to_owned(), "vps-guard".to_owned()],
            None,
            &[],
            &[0, 2],
        )?;
        let exists = passwd.audit.exit_code == Some(0);
        let account_line = passwd.stdout.trim().to_owned();
        self.record_audit(passwd.audit);
        if !exists {
            return Ok(());
        }
        validate_owned_account(&account_line)?;

        let processes = self.runner.run_accepting(
            OwnedProgram::Pgrep,
            &["-u".to_owned(), "vps-guard".to_owned()],
            None,
            &[],
            &[0, 1],
        )?;
        let processes_remain = processes.audit.exit_code == Some(0);
        self.record_audit(processes.audit);
        if processes_remain {
            return Err(DeploymentStateError::Contract(
                "vps-guard process가 남아 있어 account를 제거하지 않습니다".to_owned(),
            ));
        }

        let removed =
            self.runner
                .run(OwnedProgram::Userdel, &["vps-guard".to_owned()], None, &[])?;
        self.record_audit(removed.audit);
        let group = self.runner.run_accepting(
            OwnedProgram::Getent,
            &["group".to_owned(), "vps-guard".to_owned()],
            None,
            &[],
            &[0, 2],
        )?;
        let group_exists = group.audit.exit_code == Some(0);
        self.record_audit(group.audit);
        if group_exists {
            let removed =
                self.runner
                    .run(OwnedProgram::Groupdel, &["vps-guard".to_owned()], None, &[])?;
            self.record_audit(removed.audit);
        }
        Ok(())
    }

    pub(crate) fn service_state(
        &mut self,
        unit: &str,
    ) -> Result<ServiceSnapshot, DeploymentStateError> {
        if let Some(root) = &self.config.test_root {
            let state_root = root.join(".vpsguard-test/systemd");
            return Ok(ServiceSnapshot {
                unit: unit.to_owned(),
                enabled: read_first_line(&state_root.join(format!("{unit}.enabled")))?
                    .unwrap_or_else(|| "not-found".to_owned()),
                active: read_first_line(&state_root.join(format!("{unit}.active")))?
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
        let enabled_value = first_output_line(&enabled.stdout, "not-found");
        self.record_audit(enabled.audit);
        let active = self.runner.run_accepting(
            OwnedProgram::Systemctl,
            &["is-active".to_owned(), unit.to_owned()],
            None,
            &[],
            &[0, 3, 4],
        )?;
        let active_value = first_output_line(&active.stdout, "inactive");
        self.record_audit(active.audit);
        Ok(ServiceSnapshot {
            unit: unit.to_owned(),
            enabled: enabled_value,
            active: active_value,
        })
    }

    pub(crate) fn stop_service(&mut self, unit: &str) -> Result<(), DeploymentStateError> {
        if let Some(root) = &self.config.test_root {
            let path = root
                .join(".vpsguard-test/systemd")
                .join(format!("{unit}.active"));
            write_state(&path, "inactive")?;
            return Ok(());
        }
        let output = self.runner.run_accepting(
            OwnedProgram::Systemctl,
            &["stop".to_owned(), unit.to_owned()],
            None,
            &[],
            &[0, 1, 5],
        )?;
        self.record_audit(output.audit);
        Ok(())
    }

    pub(crate) fn set_service_state(
        &mut self,
        state: &ServiceSnapshot,
    ) -> Result<(), DeploymentStateError> {
        if let Some(root) = &self.config.test_root {
            let state_root = root.join(".vpsguard-test/systemd");
            write_state(
                &state_root.join(format!("{}.enabled", state.unit)),
                &state.enabled,
            )?;
            write_state(
                &state_root.join(format!("{}.active", state.unit)),
                &state.active,
            )?;
            return Ok(());
        }
        let enable_action = match state.enabled.as_str() {
            "enabled" | "enabled-runtime" | "linked" | "linked-runtime" | "alias" => "enable",
            "masked" | "masked-runtime" => "mask",
            "disabled" | "indirect" | "static" | "generated" | "transient" | "not-found" | "" => {
                "disable"
            }
            other => {
                return Err(DeploymentStateError::Contract(format!(
                    "지원하지 않는 service enablement입니다: unit={}, state={other}",
                    state.unit
                )));
            }
        };
        if enable_action != "mask" {
            let output = self.runner.run_accepting(
                OwnedProgram::Systemctl,
                &["unmask".to_owned(), state.unit.clone()],
                None,
                &[],
                &[0, 1],
            )?;
            self.record_audit(output.audit);
        }
        let output = self.runner.run_accepting(
            OwnedProgram::Systemctl,
            &[enable_action.to_owned(), state.unit.clone()],
            None,
            &[],
            if enable_action == "disable" {
                &[0, 1, 5]
            } else {
                &[0]
            },
        )?;
        self.record_audit(output.audit);

        let activity_action = match state.active.as_str() {
            "active" | "activating" | "reloading" => "start",
            "inactive" | "failed" | "deactivating" | "unknown" | "" => "stop",
            other => {
                return Err(DeploymentStateError::Contract(format!(
                    "지원하지 않는 service activity입니다: unit={}, state={other}",
                    state.unit
                )));
            }
        };
        let output = self.runner.run_accepting(
            OwnedProgram::Systemctl,
            &[activity_action.to_owned(), state.unit.clone()],
            None,
            &[],
            if activity_action == "stop" {
                &[0, 1, 5]
            } else {
                &[0]
            },
        )?;
        self.record_audit(output.audit);
        Ok(())
    }

    pub(crate) fn daemon_reload(&mut self) -> Result<(), DeploymentStateError> {
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

    pub(crate) fn protected_state(&mut self) -> Result<Vec<String>, DeploymentStateError> {
        let mut lines = Vec::with_capacity(PROTECTED_PATHS.len() + PROTECTED_SERVICES.len());
        for (name, logical) in PROTECTED_PATHS {
            lines.push(format!("{name}|{logical}|{}", self.path_identity(logical)?));
        }
        for unit in PROTECTED_SERVICES {
            let state = self.service_state(unit)?;
            lines.push(format!(
                "service:{unit}|enabled={}|activity={}",
                state.enabled,
                normalized_activity(&state.active)
            ));
        }
        Ok(lines)
    }

    pub(crate) fn listener_state(&mut self) -> Result<Vec<String>, DeploymentStateError> {
        let lines = if let Some(root) = &self.config.test_root {
            let fixture = root.join(".vpsguard-test/listeners");
            if fixture.is_file() {
                fs::read_to_string(&fixture)
                    .map_err(|source| io_error("read_listeners", &fixture, source))?
                    .lines()
                    .map(str::to_owned)
                    .collect()
            } else {
                Vec::new()
            }
        } else {
            let output = self.runner.run(
                OwnedProgram::Ss,
                &["-H".to_owned(), "-ltn".to_owned()],
                None,
                &[],
            )?;
            let lines = output
                .stdout
                .lines()
                .filter_map(|line| line.split_whitespace().nth(3))
                .filter(|address| !address.ends_with(":7727") && !address.ends_with(":18080"))
                .map(str::to_owned)
                .collect();
            self.record_audit(output.audit);
            lines
        };
        Ok(lines
            .into_iter()
            .filter(|line| !line.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect())
    }

    fn path_identity(&self, logical: &str) -> Result<String, DeploymentStateError> {
        let path = self.logical_path(logical)?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(format!("absent:{logical}"));
            }
            Err(source) => return Err(io_error("protected_metadata", &path, source)),
        };
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path)
                .map_err(|source| io_error("protected_read_link", &path, source))?;
            return Ok(format!("symlink:{}", target.display()));
        }
        if metadata.is_dir() {
            return Ok(format!(
                "directory:{}:{}:{:o}:{}:{}",
                metadata.dev(),
                metadata.ino(),
                metadata.mode() & 0o7777,
                metadata.uid(),
                metadata.gid()
            ));
        }
        if metadata.is_file() {
            return Ok(format!(
                "file:{:o}:{}",
                metadata.mode() & 0o7777,
                hash_file(&path)?
            ));
        }
        Ok(format!("absent:{logical}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServiceSnapshot {
    pub(crate) unit: String,
    pub(crate) enabled: String,
    pub(crate) active: String,
}

fn validate_owned_account(line: &str) -> Result<(), DeploymentStateError> {
    let fields: Vec<_> = line.split(':').collect();
    if fields.len() != 7 {
        return Err(DeploymentStateError::Contract(
            "vps-guard passwd row 형식이 잘못됐습니다".to_owned(),
        ));
    }
    let uid = fields[2].parse::<u32>().map_err(|_| {
        DeploymentStateError::Contract("vps-guard uid가 숫자가 아닙니다".to_owned())
    })?;
    let owned_shell = matches!(
        fields[6],
        "/usr/sbin/nologin" | "/sbin/nologin" | "/bin/false"
    );
    if fields[0] != "vps-guard" || uid >= 1_000 || fields[5] != "/var/lib/vps-guard" || !owned_shell
    {
        return Err(DeploymentStateError::Contract(
            "소유권이 확인되지 않은 vps-guard account를 제거하지 않습니다".to_owned(),
        ));
    }
    Ok(())
}

fn normalized_activity(value: &str) -> &'static str {
    match value {
        "active" | "activating" | "reloading" => "up",
        "failed" => "failed",
        _ => "down",
    }
}

fn read_first_line(path: &Path) -> Result<Option<String>, DeploymentStateError> {
    match fs::read_to_string(path) {
        Ok(value) => Ok(value.lines().next().map(str::to_owned)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(io_error("read_state", path, source)),
    }
}

fn write_state(path: &Path, value: &str) -> Result<(), DeploymentStateError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|source| io_error("create_state_parent", parent, source))?;
    }
    fs::write(path, format!("{value}\n")).map_err(|source| io_error("write_state", path, source))
}

fn first_output_line(output: &str, fallback: &str) -> String {
    output
        .lines()
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_owned()
}

fn hash_file(path: &Path) -> Result<String, DeploymentStateError> {
    let mut file = File::open(path).map_err(|source| io_error("hash_open", path, source))?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 16 * 1_024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| io_error("hash_read", path, source))?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(hex_bytes(&hash.finalize()))
}

fn hex_digest(bytes: &[u8]) -> String {
    hex_bytes(&Sha256::digest(bytes))
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ignored = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}
