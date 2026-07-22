//! OPS-003 public ingress 상태의 bounded snapshot·복원 transaction입니다.
//!
//! 승인된 Nginx ingress 파일, VPSGuard 설정·drop-in·Certbot hook과
//! Nginx/VPSGuard service만 변경합니다. 인증서는 fingerprint만 읽고 SSH, site와
//! 80/443 외 listener는 복원 전후 동일해야 합니다.

mod apache;
mod apply;
mod candidate;
mod files;
mod format;
mod host;
mod probe;
mod snapshot;
mod switch;
mod switch_contract;
mod switch_snapshot;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AtomicJsonStore, CommandAudit, CommandError, IngressTopology, OperationDriver, OperationIssue,
    OperationKind, OperationPhase, OperationPlan, PhaseReport, SnapshotResource, StoreError,
    SystemCommandRunner,
};

/// 현재 Rust ingress snapshot schema입니다. Legacy Shell schema 1도 읽습니다.
pub const INGRESS_SNAPSHOT_SCHEMA_VERSION: u32 = 2;

pub(crate) const ACTIVE_NGINX: &str = "/etc/nginx/sites-available/g7.conf";
pub(crate) const ACTIVE_CONFIG: &str = "/etc/vps-guard/config.toml";
pub(crate) const EDGE_DROPIN: &str =
    "/etc/systemd/system/vps-guard-edge.service.d/30-g7devops-tls.conf";
pub(crate) const DEFAULT_DENY: &str = "/etc/nginx/sites-enabled/g7-default-deny.conf";
pub(crate) const DEFAULT_DENY_TARGET: &str = "/etc/nginx/sites-available/g7-default-deny.conf";
pub(crate) const GENERIC_CERTBOT_HOOK: &str = "/usr/local/libexec/vps-guard/certbot-deploy-hook";
pub(crate) const SITE_CERTBOT_HOOK: &str = "/etc/letsencrypt/renewal-hooks/deploy/vps-guard";
pub(crate) const CERTIFICATE: &str = "/etc/letsencrypt/live/g7devops.com/fullchain.pem";
pub(crate) const EDGE_SERVICE: &str = "vps-guard-edge.service";
pub(crate) const NGINX_SERVICE: &str = "nginx.service";
pub(crate) const APACHE_SERVICE: &str = "apache2.service";

pub(crate) const FILE_SPECS: [FileSpec; 5] = [
    FileSpec::required(ACTIVE_NGINX, "g7.conf"),
    FileSpec::required(ACTIVE_CONFIG, "config.toml"),
    FileSpec::optional(EDGE_DROPIN, "edge-tls.conf"),
    FileSpec::optional(GENERIC_CERTBOT_HOOK, "certbot-deploy-hook"),
    FileSpec::optional(SITE_CERTBOT_HOOK, "g7-certbot-deploy-hook"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileSpec {
    pub(crate) logical: &'static str,
    pub(crate) payload: &'static str,
    pub(crate) required: bool,
}

impl FileSpec {
    const fn required(logical: &'static str, payload: &'static str) -> Self {
        Self {
            logical,
            payload,
            required: true,
        }
    }

    const fn optional(logical: &'static str, payload: &'static str) -> Self {
        Self {
            logical,
            payload,
            required: false,
        }
    }
}

/// ingress snapshot의 filesystem과 public probe 경계입니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressStateConfig {
    /// fixture에서는 logical `/`를 이 directory 아래로 변환합니다.
    pub test_root: Option<PathBuf>,
    /// fixture service 상태 directory입니다.
    pub test_state_root: Option<PathBuf>,
    /// `direct-*` snapshot의 정확한 parent입니다.
    pub snapshot_root: PathBuf,
    /// public HTTPS read-back URL입니다.
    pub public_probe_url: String,
    /// TLS SNI와 Host read-back 이름입니다.
    pub server_name: String,
    /// fixture에서 강제할 public 전환 측정값입니다.
    pub fixture_cutover_ms: u64,
}

impl IngressStateConfig {
    /// 실제 g7devops pilot 서버용 경계를 만듭니다.
    #[must_use]
    pub fn production(snapshot_root: impl Into<PathBuf>) -> Self {
        Self {
            test_root: None,
            test_state_root: None,
            snapshot_root: snapshot_root.into(),
            public_probe_url: "https://www.g7devops.com/".to_owned(),
            server_name: "www.g7devops.com".to_owned(),
            fixture_cutover_ms: 0,
        }
    }

    /// OS mutation 없는 격리 fixture 경계를 만듭니다.
    #[must_use]
    pub fn fixture(
        test_root: impl Into<PathBuf>,
        state_root: impl Into<PathBuf>,
        snapshot_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            test_root: Some(test_root.into()),
            test_state_root: Some(state_root.into()),
            snapshot_root: snapshot_root.into(),
            public_probe_url: "https://fixture.invalid/".to_owned(),
            server_name: "fixture.invalid".to_owned(),
            fixture_cutover_ms: 0,
        }
    }
}

/// ingress snapshot과 복원 경계 위반입니다.
#[derive(Debug, Error)]
pub enum IngressStateError {
    /// 고정 경로·schema·상태 계약이 맞지 않습니다.
    #[error("ingress snapshot 계약 위반: {0}")]
    Contract(String),
    /// bounded filesystem 작업이 실패했습니다.
    #[error("ingress snapshot I/O 실패: operation={operation}, path={path}, cause={source}")]
    Io {
        /// 실패한 작업입니다.
        operation: &'static str,
        /// 실패한 경로입니다.
        path: String,
        /// 원본 I/O 오류입니다.
        source: std::io::Error,
    },
    /// JSON manifest 처리가 실패했습니다.
    #[error("ingress manifest JSON 실패: {0}")]
    Json(#[from] serde_json::Error),
    /// allowlist OS command가 실패했습니다.
    #[error(transparent)]
    Command(#[from] CommandError),
    /// 원자 rollback checkpoint 저장이 실패했습니다.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// ingress snapshot filesystem·command adapter입니다.
#[derive(Debug)]
pub struct IngressStateStore {
    pub(crate) config: IngressStateConfig,
    pub(crate) runner: SystemCommandRunner,
    command_audits: Vec<CommandAudit>,
    #[cfg(test)]
    pub(crate) fail_after_first_mutation: bool,
}

pub use apache::{
    ApacheIngressConfig, ApacheIngressDirection, ApacheIngressDriver, apache_ingress_plan,
};
pub use apply::IngressApplyDriver;
pub use switch::{
    IngressSwitchConfig, IngressSwitchDirection, IngressSwitchDriver, ingress_switch_plan,
};

impl IngressStateStore {
    /// adapter를 만듭니다.
    #[must_use]
    pub fn new(config: IngressStateConfig) -> Self {
        Self {
            config,
            runner: SystemCommandRunner,
            command_audits: Vec::new(),
            #[cfg(test)]
            fail_after_first_mutation: false,
        }
    }

    /// 비밀값이 제거된 command 감사 row입니다.
    #[must_use]
    pub fn command_audits(&self) -> &[CommandAudit] {
        &self.command_audits
    }

    pub(crate) fn record_audit(&mut self, audit: CommandAudit) {
        self.command_audits.push(audit);
    }
}

/// 실제 direct ingress restore 단계를 수행하는 OPS-010 driver입니다.
#[derive(Debug)]
pub struct IngressRestoreDriver {
    store: IngressStateStore,
    target_snapshot: PathBuf,
    rollback_snapshot: Option<PathBuf>,
    checkpoint: Option<AtomicJsonStore<IngressRollbackCheckpoint>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IngressRollbackCheckpoint {
    schema_version: u32,
    target_snapshot: PathBuf,
    rollback_snapshot: PathBuf,
}

impl IngressRestoreDriver {
    /// 검증할 target snapshot과 adapter를 묶습니다.
    #[must_use]
    pub fn new(store: IngressStateStore, target_snapshot: impl Into<PathBuf>) -> Self {
        Self {
            store,
            target_snapshot: target_snapshot.into(),
            rollback_snapshot: None,
            checkpoint: None,
        }
    }

    /// process 재시작 뒤에도 pre-attempt rollback snapshot을 재개합니다.
    ///
    /// # Errors
    ///
    /// checkpoint가 손상됐거나 다른 target을 가리키면 거부합니다.
    pub fn with_checkpoint(
        store: IngressStateStore,
        target_snapshot: impl Into<PathBuf>,
        checkpoint_path: impl Into<PathBuf>,
    ) -> Result<Self, IngressStateError> {
        let target_snapshot = target_snapshot.into();
        let checkpoint = AtomicJsonStore::new(checkpoint_path.into());
        let rollback_snapshot = if checkpoint.path().exists() {
            let record: IngressRollbackCheckpoint = checkpoint.read()?;
            if record.schema_version != INGRESS_SNAPSHOT_SCHEMA_VERSION
                || record.target_snapshot != target_snapshot
            {
                return Err(IngressStateError::Contract(
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

    /// 자동 rollback용 pre-attempt snapshot입니다.
    #[must_use]
    pub fn rollback_snapshot(&self) -> Option<&Path> {
        self.rollback_snapshot.as_deref()
    }

    fn execute_phase(&mut self, phase: OperationPhase) -> Result<u64, IngressStateError> {
        match phase {
            OperationPhase::Preflight => {
                self.store.verify_snapshot(&self.target_snapshot)?;
                Ok(0)
            }
            OperationPhase::Snapshot => {
                let rollback_snapshot = self.store.create_snapshot("rollback")?;
                if let Some(checkpoint) = &self.checkpoint {
                    checkpoint.write(&IngressRollbackCheckpoint {
                        schema_version: INGRESS_SNAPSHOT_SCHEMA_VERSION,
                        target_snapshot: self.target_snapshot.clone(),
                        rollback_snapshot: rollback_snapshot.clone(),
                    })?;
                }
                self.rollback_snapshot = Some(rollback_snapshot);
                Ok(0)
            }
            OperationPhase::ValidateCandidate => {
                self.store.validate_candidate(&self.target_snapshot)?;
                Ok(0)
            }
            OperationPhase::RestoreOwnedState => self.store.restore_snapshot(&self.target_snapshot),
            OperationPhase::VerifyTarget => {
                self.store.verify_restored_snapshot(&self.target_snapshot)?;
                Ok(0)
            }
            OperationPhase::Commit => Ok(0),
            other => Err(IngressStateError::Contract(format!(
                "ingress restore driver가 지원하지 않는 단계입니다: {other:?}"
            ))),
        }
    }
}

impl OperationDriver for IngressRestoreDriver {
    fn run_phase(
        &mut self,
        plan: &OperationPlan,
        phase: OperationPhase,
        _timeout: Duration,
    ) -> Result<PhaseReport, OperationIssue> {
        if plan.operation != OperationKind::Restore {
            return Err(issue("INGRESS_KIND_INVALID", "restore plan이 아닙니다"));
        }
        let started = Instant::now();
        let interruption = self
            .execute_phase(phase)
            .map_err(|error| issue("INGRESS_PHASE_FAILED", &error.to_string()))?;
        Ok(PhaseReport::new(
            phase,
            elapsed_ms(started.elapsed()),
            interruption,
        ))
    }

    fn rollback(
        &mut self,
        _plan: &OperationPlan,
        _timeout: Duration,
    ) -> Result<PhaseReport, OperationIssue> {
        let started = Instant::now();
        let snapshot = self.rollback_snapshot.clone().ok_or_else(|| {
            issue(
                "INGRESS_ROLLBACK_SNAPSHOT_MISSING",
                "pre-attempt snapshot이 없습니다",
            )
        })?;
        let interruption = self
            .store
            .restore_snapshot(&snapshot)
            .map_err(|error| issue("INGRESS_ROLLBACK_FAILED", &error.to_string()))?;
        self.store
            .verify_restored_snapshot(&snapshot)
            .map_err(|error| issue("INGRESS_ROLLBACK_VERIFY_FAILED", &error.to_string()))?;
        Ok(PhaseReport::new(
            OperationPhase::Rollback,
            elapsed_ms(started.elapsed()),
            interruption,
        ))
    }
}

/// exact ingress restore transaction plan을 만듭니다.
#[must_use]
pub fn ingress_restore_plan(
    operation_id: &str,
    snapshot_id: &str,
    source: IngressTopology,
    target: IngressTopology,
) -> OperationPlan {
    OperationPlan::new(
        operation_id,
        OperationKind::Restore,
        snapshot_id,
        source,
        target,
        ingress_resources(),
    )
}

/// staged direct ingress 후보를 적용하는 transaction plan을 만듭니다.
#[must_use]
pub fn ingress_apply_plan(operation_id: &str, candidate_id: &str) -> OperationPlan {
    OperationPlan::new(
        operation_id,
        OperationKind::Apply,
        candidate_id,
        IngressTopology::NginxPublic,
        IngressTopology::VpsGuardPublic,
        ingress_resources(),
    )
}

fn ingress_resources() -> Vec<SnapshotResource> {
    [SnapshotResource::IngressFile {
        path: PathBuf::from(ACTIVE_NGINX),
    }]
    .into_iter()
    .chain(
        FILE_SPECS
            .iter()
            .skip(1)
            .map(|spec| SnapshotResource::OwnedPath {
                path: PathBuf::from(spec.logical),
            }),
    )
    .chain([SnapshotResource::IngressSymlink {
        path: PathBuf::from(DEFAULT_DENY),
    }])
    .chain(
        [EDGE_SERVICE, NGINX_SERVICE]
            .into_iter()
            .map(|unit| SnapshotResource::Service {
                unit: unit.to_owned(),
            }),
    )
    .chain([
        SnapshotResource::CertificateFingerprint {
            path: PathBuf::from(CERTIFICATE),
        },
        SnapshotResource::ListenerInventory,
    ])
    .collect()
}

pub(crate) fn io_error(
    operation: &'static str,
    path: &Path,
    source: std::io::Error,
) -> IngressStateError {
    IngressStateError::Io {
        operation,
        path: path.display().to_string(),
        source,
    }
}

fn issue(code: &str, cause: &str) -> OperationIssue {
    OperationIssue {
        code: code.to_owned(),
        problem: "public ingress 상태 작업을 완료하지 못했습니다.".to_owned(),
        cause: cause.to_owned(),
        impact: "검증된 target을 완료하지 않고 이전 snapshot 복구를 시도합니다.".to_owned(),
        next_action:
            "operation state와 command audit을 확인한 뒤 같은 operation ID로 재개하십시오."
                .to_owned(),
    }
}

fn elapsed_ms(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests;
