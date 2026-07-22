//! OPS-009 배포 상태 snapshot·검증·복원을 Rust 운영 transaction에 연결합니다.
//!
//! 이 모듈은 고정된 VPSGuard-owned 경로만 변경합니다. SSH, Nginx, 인증서와
//! G7 site는 내용 대신 boundary identity만 읽고 복구 대상에 포함하지 않습니다.

mod host;
mod snapshot;
mod snapshot_files;
mod snapshot_format;
mod snapshot_readback;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AtomicJsonStore, CommandAudit, CommandError, IngressTopology, OperationDriver, OperationIssue,
    OperationKind, OperationPhase, OperationPlan, PhaseReport, SnapshotResource, StoreError,
    SystemCommandRunner,
};

/// 기존 Shell snapshot과 호환되는 deployment snapshot schema입니다.
pub const DEPLOYMENT_SNAPSHOT_SCHEMA_VERSION: u32 = 1;

pub(crate) const OWNED_FILES: [&str; 16] = [
    "/usr/local/bin/vps-guard",
    "/usr/local/bin/vps-guard-control",
    "/usr/local/bin/vps-guard-edge",
    "/usr/local/lib/vps-guard/current",
    "/usr/local/libexec/vps-guard/deployment-state",
    "/usr/local/libexec/vps-guard/state-common.sh",
    "/etc/systemd/system/vps-guard-control.service",
    "/etc/systemd/system/vps-guard-edge.service",
    "/etc/systemd/system/vps-guard-control.service.d/20-cloudflare-credential.conf",
    "/etc/systemd/system/vps-guard-control.service.d/20-service-credentials.conf",
    "/etc/systemd/system/vps-guard-control.service.d/30-tls-certificate.conf",
    "/etc/systemd/system/vps-guard-edge.service.d/30-tls-credentials.conf",
    "/usr/lib/tmpfiles.d/vps-guard.conf",
    "/etc/vps-guard/config.toml",
    "/etc/vps-guard/secrets/cloudflare-token",
    "/var/lib/vps-guard/ownership-manifest.txt",
];

pub(crate) const OWNED_DIRECTORIES: [&str; 9] = [
    "/usr/local/lib/vps-guard/releases",
    "/usr/local/lib/vps-guard",
    "/usr/local/libexec/vps-guard",
    "/etc/systemd/system/vps-guard-control.service.d",
    "/etc/systemd/system/vps-guard-edge.service.d",
    "/etc/vps-guard/secrets",
    "/etc/vps-guard",
    "/run/vps-guard",
    "/var/lib/vps-guard",
];

pub(crate) const OWNED_SERVICES: [&str; 2] =
    ["vps-guard-control.service", "vps-guard-edge.service"];

pub(crate) const PROTECTED_SERVICES: [&str; 7] = [
    "nginx.service",
    "php8.5-fpm.service",
    "mysql.service",
    "redis-server.service",
    "g7-queue.service",
    "g7-scheduler.service",
    "g7-reverb.service",
];

pub(crate) const PROTECTED_PATHS: [(&str, &str); 4] = [
    ("ssh-boundary", "/etc/ssh"),
    ("nginx-boundary", "/etc/nginx"),
    ("certificate-boundary", "/etc/letsencrypt"),
    ("site-boundary", "/home/g7devops/public_html"),
];

/// 배포 snapshot의 filesystem 경계입니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentStateConfig {
    /// fixture에서는 logical `/`를 이 directory 아래로 변환합니다.
    pub test_root: Option<PathBuf>,
    /// `deploy-*` snapshot의 정확한 parent입니다.
    pub snapshot_root: PathBuf,
}

impl DeploymentStateConfig {
    /// 실제 Linux 서버용 기본 경계를 만듭니다.
    #[must_use]
    pub fn production(snapshot_root: impl Into<PathBuf>) -> Self {
        Self {
            test_root: None,
            snapshot_root: snapshot_root.into(),
        }
    }

    /// OS mutation 없는 격리 fixture 경계를 만듭니다.
    #[must_use]
    pub fn fixture(test_root: impl Into<PathBuf>, snapshot_root: impl Into<PathBuf>) -> Self {
        Self {
            test_root: Some(test_root.into()),
            snapshot_root: snapshot_root.into(),
        }
    }
}

/// snapshot과 복원 경계 위반입니다.
#[derive(Debug, Error)]
pub enum DeploymentStateError {
    /// 고정 경로·schema·상태 계약이 맞지 않습니다.
    #[error("deployment snapshot 계약 위반: {0}")]
    Contract(String),
    /// bounded filesystem 작업이 실패했습니다.
    #[error("deployment snapshot I/O 실패: operation={operation}, path={path}, cause={source}")]
    Io {
        /// 실패한 작업입니다.
        operation: &'static str,
        /// 실패한 경로입니다.
        path: String,
        /// 원본 I/O 오류입니다.
        source: std::io::Error,
    },
    /// allowlist OS command가 실패했습니다.
    #[error(transparent)]
    Command(#[from] CommandError),
    /// 원자 rollback checkpoint 저장이 실패했습니다.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// legacy v1 snapshot을 typed model로 읽고 쓰는 저장소입니다.
#[derive(Debug)]
pub struct DeploymentStateStore {
    pub(crate) config: DeploymentStateConfig,
    pub(crate) runner: SystemCommandRunner,
    command_audits: Vec<CommandAudit>,
    #[cfg(test)]
    pub(crate) fail_after_first_mutation: bool,
}

impl DeploymentStateStore {
    /// filesystem·command adapter를 만듭니다.
    #[must_use]
    pub fn new(config: DeploymentStateConfig) -> Self {
        Self {
            config,
            runner: SystemCommandRunner,
            command_audits: Vec::new(),
            #[cfg(test)]
            fail_after_first_mutation: false,
        }
    }

    /// 실행 중 수집된 비밀 제거 command 감사를 반환합니다.
    #[must_use]
    pub fn command_audits(&self) -> &[CommandAudit] {
        &self.command_audits
    }

    pub(crate) fn record_audit(&mut self, audit: CommandAudit) {
        self.command_audits.push(audit);
    }
}

/// 실제 first-install restore 단계를 수행하는 OPS-010 driver입니다.
#[derive(Debug)]
pub struct DeploymentRestoreDriver {
    store: DeploymentStateStore,
    target_snapshot: PathBuf,
    rollback_snapshot: Option<PathBuf>,
    checkpoint: Option<AtomicJsonStore<DeploymentRollbackCheckpoint>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeploymentRollbackCheckpoint {
    schema_version: u32,
    target_snapshot: PathBuf,
    rollback_snapshot: PathBuf,
}

impl DeploymentRestoreDriver {
    /// 검증된 snapshot path와 adapter를 묶습니다.
    #[must_use]
    pub fn new(store: DeploymentStateStore, target_snapshot: impl Into<PathBuf>) -> Self {
        Self {
            store,
            target_snapshot: target_snapshot.into(),
            rollback_snapshot: None,
            checkpoint: None,
        }
    }

    /// process 재시작 뒤에도 pre-attempt rollback snapshot을 재개하는 driver를 만듭니다.
    ///
    /// # Errors
    ///
    /// checkpoint JSON이 손상됐거나 다른 target snapshot을 가리키면 거부합니다.
    pub fn with_checkpoint(
        store: DeploymentStateStore,
        target_snapshot: impl Into<PathBuf>,
        checkpoint_path: impl Into<PathBuf>,
    ) -> Result<Self, DeploymentStateError> {
        let target_snapshot = target_snapshot.into();
        let checkpoint = AtomicJsonStore::new(checkpoint_path.into());
        let rollback_snapshot = if checkpoint.path().exists() {
            let record: DeploymentRollbackCheckpoint = checkpoint.read()?;
            if record.schema_version != DEPLOYMENT_SNAPSHOT_SCHEMA_VERSION
                || record.target_snapshot != target_snapshot
            {
                return Err(DeploymentStateError::Contract(
                    "rollback checkpoint가 다른 schema 또는 target을 가리킵니다".to_owned(),
                ));
            }
            Some(record.rollback_snapshot)
        } else {
            None
        };
        Ok(Self {
            store,
            target_snapshot,
            rollback_snapshot,
            checkpoint: Some(checkpoint),
        })
    }

    /// 자동 rollback용으로 생성한 pre-attempt snapshot입니다.
    #[must_use]
    pub fn rollback_snapshot(&self) -> Option<&Path> {
        self.rollback_snapshot.as_deref()
    }

    /// driver가 수집한 비밀 제거 command 감사를 반환합니다.
    #[must_use]
    pub fn command_audits(&self) -> &[CommandAudit] {
        self.store.command_audits()
    }

    fn execute_phase(&mut self, phase: OperationPhase) -> Result<(), DeploymentStateError> {
        match phase {
            OperationPhase::Preflight => self.store.verify_snapshot(&self.target_snapshot),
            OperationPhase::Snapshot => {
                let rollback_snapshot = self.store.create_snapshot()?;
                if let Some(checkpoint) = &self.checkpoint {
                    checkpoint.write(&DeploymentRollbackCheckpoint {
                        schema_version: DEPLOYMENT_SNAPSHOT_SCHEMA_VERSION,
                        target_snapshot: self.target_snapshot.clone(),
                        rollback_snapshot: rollback_snapshot.clone(),
                    })?;
                }
                self.rollback_snapshot = Some(rollback_snapshot);
                Ok(())
            }
            OperationPhase::ValidateCandidate => self.store.verify_snapshot(&self.target_snapshot),
            OperationPhase::RestoreOwnedState => self.store.restore_snapshot(&self.target_snapshot),
            OperationPhase::VerifyTarget => {
                self.store.verify_restored_snapshot(&self.target_snapshot)
            }
            OperationPhase::Commit => Ok(()),
            other => Err(DeploymentStateError::Contract(format!(
                "deployment restore가 지원하지 않는 phase입니다: {other:?}"
            ))),
        }
    }
}

impl OperationDriver for DeploymentRestoreDriver {
    fn run_phase(
        &mut self,
        plan: &OperationPlan,
        phase: OperationPhase,
        _timeout: Duration,
    ) -> Result<PhaseReport, OperationIssue> {
        if plan.operation != OperationKind::Restore {
            return Err(operation_issue(
                "DEPLOYMENT_OPERATION_KIND_INVALID",
                format!("expected=restore, actual={:?}", plan.operation),
            ));
        }
        let started = Instant::now();
        self.execute_phase(phase).map_err(|error| {
            operation_issue("DEPLOYMENT_RESTORE_PHASE_FAILED", error.to_string())
        })?;
        Ok(PhaseReport::new(phase, elapsed_ms(started), 0))
    }

    fn rollback(
        &mut self,
        _plan: &OperationPlan,
        _timeout: Duration,
    ) -> Result<PhaseReport, OperationIssue> {
        let started = Instant::now();
        let snapshot = self.rollback_snapshot.clone().ok_or_else(|| {
            operation_issue(
                "DEPLOYMENT_ROLLBACK_SNAPSHOT_MISSING",
                "pre-attempt snapshot이 생성되지 않았습니다".to_owned(),
            )
        })?;
        self.store
            .restore_snapshot(&snapshot)
            .map_err(|error| operation_issue("DEPLOYMENT_ROLLBACK_FAILED", error.to_string()))?;
        Ok(PhaseReport::new(
            OperationPhase::Rollback,
            elapsed_ms(started),
            0,
        ))
    }
}

/// deployment restore가 변경·검증할 bounded resource plan을 만듭니다.
#[must_use]
pub fn deployment_restore_plan(
    operation_id: impl Into<String>,
    snapshot_id: impl Into<String>,
) -> OperationPlan {
    let mut resources: Vec<SnapshotResource> = OWNED_FILES
        .iter()
        .map(|path| SnapshotResource::OwnedPath {
            path: PathBuf::from(path),
        })
        .collect();
    resources.extend(OWNED_DIRECTORIES.iter().map(|path| {
        SnapshotResource::OwnedDirectoryPresence {
            path: PathBuf::from(path),
        }
    }));
    resources.extend(PROTECTED_PATHS.iter().map(|(_, path)| {
        SnapshotResource::ProtectedPathIdentity {
            path: PathBuf::from(path),
        }
    }));
    resources.push(SnapshotResource::SystemAccount {
        name: "vps-guard".to_owned(),
    });
    resources.extend(
        OWNED_SERVICES
            .iter()
            .chain(PROTECTED_SERVICES.iter())
            .map(|unit| SnapshotResource::Service {
                unit: (*unit).to_owned(),
            }),
    );
    resources.push(SnapshotResource::ListenerInventory);
    OperationPlan::new(
        operation_id,
        OperationKind::Restore,
        snapshot_id,
        IngressTopology::NginxPublic,
        IngressTopology::NginxPublic,
        resources,
    )
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

fn operation_issue(code: &str, cause: String) -> OperationIssue {
    OperationIssue {
        code: code.to_owned(),
        problem: "VPSGuard-owned 배포 상태 작업이 실패했습니다.".to_owned(),
        cause,
        impact: "사용자 Nginx·인증서·site는 변경하지 않고 작업을 중단했습니다.".to_owned(),
        next_action: "transaction ledger와 rollback snapshot을 확인하십시오.".to_owned(),
    }
}

pub(crate) fn io_error(
    operation: &'static str,
    path: &Path,
    source: std::io::Error,
) -> DeploymentStateError {
    DeploymentStateError::Io {
        operation,
        path: path.display().to_string(),
        source,
    }
}

#[cfg(test)]
#[path = "deployment_state/tests.rs"]
mod tests;
