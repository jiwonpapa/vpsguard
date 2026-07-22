//! apply·restore의 단일 실행 lock, 단계 상태, 시간 예산과 자동 rollback 엔진입니다.
//!
//! OPS-010에 따라 사이트 tree를 snapshot 대상으로 받지 않으며, 각 단계 결과를
//! 원자 저장한 뒤 다음 단계로 진행합니다. 실제 OS 변경은 [`OperationDriver`] adapter가
//! 수행하고 이 module은 순서·재개·시간 예산·rollback 불변조건을 소유합니다.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use rustix::fs::{FlockOperation, flock};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::{AtomicJsonStore, StoreError};

/// 운영 transaction schema 버전입니다.
pub const OPERATION_SCHEMA_VERSION: u32 = 1;

const MAX_PREFLIGHT_MS: u64 = 60_000;
const MAX_PUBLIC_INTERRUPTION_MS: u64 = 5_000;
const MAX_ROLLBACK_MS: u64 = 10_000;
const MAX_APPLY_MS: u64 = 60_000;
const MAX_RESTORE_MS: u64 = 30_000;

/// 운영 작업 종류입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    /// 새 release와 public ingress를 적용합니다.
    Apply,
    /// 저장된 snapshot topology로 복구합니다.
    Restore,
    /// 현재 topology를 유지하면서 release를 교체합니다.
    Update,
    /// Nginx가 public ingress를 회수합니다.
    BypassEnable,
    /// VPSGuard가 public ingress를 다시 소유합니다.
    BypassDisable,
}

impl OperationKind {
    /// 작업이 따라야 하는 결정적 단계 순서입니다.
    #[must_use]
    pub fn phases(self) -> Vec<OperationPhase> {
        match self {
            Self::Restore => vec![
                OperationPhase::Preflight,
                OperationPhase::Snapshot,
                OperationPhase::ValidateCandidate,
                OperationPhase::RestoreOwnedState,
                OperationPhase::VerifyTarget,
                OperationPhase::Commit,
            ],
            Self::Update => vec![
                OperationPhase::Preflight,
                OperationPhase::Snapshot,
                OperationPhase::StageRelease,
                OperationPhase::ValidateCandidate,
                OperationPhase::ActivateRelease,
                OperationPhase::VerifyTarget,
                OperationPhase::Commit,
            ],
            Self::Apply | Self::BypassEnable | Self::BypassDisable => vec![
                OperationPhase::Preflight,
                OperationPhase::Snapshot,
                OperationPhase::StageRelease,
                OperationPhase::ValidateCandidate,
                OperationPhase::SwitchIngress,
                OperationPhase::VerifyTarget,
                OperationPhase::Commit,
            ],
        }
    }

    fn maximum_operation_ms(self) -> u64 {
        match self {
            Self::Restore | Self::BypassEnable | Self::BypassDisable => MAX_RESTORE_MS,
            Self::Apply | Self::Update => MAX_APPLY_MS,
        }
    }
}

/// public 80/443 소유 topology입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IngressTopology {
    /// 기존 Nginx가 public HTTP/TLS를 소유합니다.
    NginxPublic,
    /// VPSGuard가 public HTTP/TLS를 소유합니다.
    VpsGuardPublic,
    /// 기존 Apache가 public TLS와 application origin을 직접 제공합니다.
    ApachePublic,
    /// Apache가 public TLS를 유지하고 loopback VPSGuard를 요청 경로에 편입합니다.
    ApacheGuarded,
}

/// transaction snapshot에 포함할 bounded resource입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SnapshotResource {
    /// VPSGuard가 소유하는 단일 파일 또는 symlink입니다.
    OwnedPath {
        /// 절대 경로입니다. directory 재귀 snapshot은 허용하지 않습니다.
        path: PathBuf,
    },
    /// VPSGuard-owned directory의 존재 여부만 보존합니다.
    OwnedDirectoryPresence {
        /// 재귀 내용을 읽지 않는 정확한 directory 경로입니다.
        path: PathBuf,
    },
    /// 사용자 소유 tree는 읽지 않고 boundary identity만 보존합니다.
    ProtectedPathIdentity {
        /// 허용된 SSH, Nginx, 인증서 또는 site boundary입니다.
        path: PathBuf,
    },
    /// VPSGuard system account의 배포 전 존재 여부입니다.
    SystemAccount {
        /// 정확히 `vps-guard`인 account 이름입니다.
        name: String,
    },
    /// 운영자가 승인한 단일 Nginx ingress 파일입니다.
    IngressFile {
        /// `/etc/nginx/sites-available` 또는 `sites-enabled` 아래 파일입니다.
        path: PathBuf,
    },
    /// 승인된 ingress symlink입니다.
    IngressSymlink {
        /// `/etc/nginx/sites-enabled` 아래 symlink 경로입니다.
        path: PathBuf,
    },
    /// 운영자가 승인한 단일 Apache ingress 파일입니다.
    ApacheIngressFile {
        /// `/etc/apache2`의 site 또는 conf allowlist 아래 파일입니다.
        path: PathBuf,
    },
    /// 승인된 Apache ingress symlink입니다.
    ApacheIngressSymlink {
        /// `/etc/apache2`의 enabled allowlist 아래 symlink 경로입니다.
        path: PathBuf,
    },
    /// VPSGuard 또는 Nginx service 상태입니다.
    Service {
        /// 허용된 systemd unit입니다.
        unit: String,
    },
    /// 공개 인증서 fingerprint만 읽습니다.
    CertificateFingerprint {
        /// `/etc/letsencrypt/live` 아래 `cert.pem` 또는 `fullchain.pem`입니다.
        path: PathBuf,
    },
    /// VPSGuard가 소유하지 않는 listener의 전후 inventory입니다.
    ListenerInventory,
}

/// 단계별·전체 작업 시간 예산입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationBudgets {
    /// 변경 전 검사 최대 시간입니다.
    pub preflight_ms: u64,
    /// 일반 비공개 단계 하나의 최대 시간입니다.
    pub phase_ms: u64,
    /// public ingress가 정상 target을 제공하지 못하는 누적 최대 시간입니다.
    pub public_interruption_ms: u64,
    /// rollback 최대 시간입니다.
    pub rollback_ms: u64,
    /// rollback을 제외한 전체 작업 최대 시간입니다.
    pub operation_ms: u64,
}

impl OperationBudgets {
    fn for_kind(kind: OperationKind) -> Self {
        Self {
            preflight_ms: MAX_PREFLIGHT_MS,
            phase_ms: 15_000,
            public_interruption_ms: MAX_PUBLIC_INTERRUPTION_MS,
            rollback_ms: MAX_ROLLBACK_MS,
            operation_ms: kind.maximum_operation_ms(),
        }
    }

    fn timeout_for(self, phase: OperationPhase) -> Duration {
        let milliseconds = match phase {
            OperationPhase::Preflight => self.preflight_ms,
            OperationPhase::SwitchIngress | OperationPhase::ActivateRelease => {
                self.public_interruption_ms
            }
            OperationPhase::Rollback => self.rollback_ms,
            _ => self.phase_ms,
        };
        Duration::from_millis(milliseconds)
    }
}

/// 실행 전 서명 가능한 운영 plan입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationPlan {
    /// plan schema 버전입니다.
    pub schema_version: u32,
    /// 재개와 lock 보고에 사용하는 실행 식별자입니다.
    pub operation_id: String,
    /// 작업 종류입니다.
    pub operation: OperationKind,
    /// 검증된 release 또는 snapshot 식별자입니다.
    pub release_id: String,
    /// 현재 public ingress topology입니다.
    pub source_topology: IngressTopology,
    /// 완료 후 public ingress topology입니다.
    pub target_topology: IngressTopology,
    /// snapshot할 bounded resource 목록입니다.
    pub resources: Vec<SnapshotResource>,
    /// 단계별 시간 예산입니다.
    pub budgets: OperationBudgets,
}

impl OperationPlan {
    /// 기본 hard limit을 가진 plan을 만듭니다.
    #[must_use]
    pub fn new(
        operation_id: impl Into<String>,
        operation: OperationKind,
        release_id: impl Into<String>,
        source_topology: IngressTopology,
        target_topology: IngressTopology,
        resources: Vec<SnapshotResource>,
    ) -> Self {
        Self {
            schema_version: OPERATION_SCHEMA_VERSION,
            operation_id: operation_id.into(),
            operation,
            release_id: release_id.into(),
            source_topology,
            target_topology,
            resources,
            budgets: OperationBudgets::for_kind(operation),
        }
    }

    /// schema, 식별자, topology, 시간 예산과 snapshot 범위를 검증합니다.
    ///
    /// # Errors
    ///
    /// 미래 schema, 과대한 시간 예산, 사이트 tree 또는 허용되지 않은 OS 경로를 반환합니다.
    pub fn validate(&self) -> Result<(), OperationContractError> {
        if self.schema_version != OPERATION_SCHEMA_VERSION {
            return Err(OperationContractError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        validate_identifier("operation_id", &self.operation_id)?;
        validate_identifier("release_id", &self.release_id)?;
        if !matches!(
            self.operation,
            OperationKind::Update | OperationKind::Restore
        ) && self.source_topology == self.target_topology
        {
            return Err(OperationContractError::UnchangedTopology);
        }
        validate_budgets(self.operation, self.budgets)?;
        if self.resources.is_empty() {
            return Err(OperationContractError::EmptySnapshot);
        }
        let mut listener_inventory = false;
        for resource in &self.resources {
            resource.validate()?;
            listener_inventory |= matches!(resource, SnapshotResource::ListenerInventory);
        }
        if !listener_inventory {
            return Err(OperationContractError::MissingListenerInventory);
        }
        Ok(())
    }

    /// 정규 JSON plan의 SHA-256 확인 hash를 반환합니다.
    ///
    /// # Errors
    ///
    /// plan 검증 또는 JSON encode 실패를 반환합니다.
    pub fn sha256(&self) -> Result<String, OperationContractError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        Ok(hex_digest(&bytes))
    }
}

impl SnapshotResource {
    fn validate(&self) -> Result<(), OperationContractError> {
        match self {
            Self::OwnedPath { path } => validate_owned_path(path),
            Self::OwnedDirectoryPresence { path } => validate_owned_directory(path),
            Self::ProtectedPathIdentity { path } => validate_protected_path(path),
            Self::SystemAccount { name } => {
                if name == "vps-guard" {
                    Ok(())
                } else {
                    Err(OperationContractError::ForeignSystemAccount(name.clone()))
                }
            }
            Self::IngressFile { path } => validate_ingress_path(path, false),
            Self::IngressSymlink { path } => validate_ingress_path(path, true),
            Self::ApacheIngressFile { path } => validate_apache_ingress_path(path, false),
            Self::ApacheIngressSymlink { path } => validate_apache_ingress_path(path, true),
            Self::Service { unit } => {
                if matches!(
                    unit.as_str(),
                    "nginx.service"
                        | "apache2.service"
                        | "php8.5-fpm.service"
                        | "mysql.service"
                        | "redis-server.service"
                        | "g7-queue.service"
                        | "g7-scheduler.service"
                        | "g7-reverb.service"
                        | "vps-guard-control.service"
                        | "vps-guard-privileged.service"
                        | "vps-guard-privileged.socket"
                        | "vps-guard-edge.service"
                ) {
                    Ok(())
                } else {
                    Err(OperationContractError::ForeignService(unit.clone()))
                }
            }
            Self::CertificateFingerprint { path } => {
                validate_absolute_file(path)?;
                let letsencrypt_name = matches!(
                    path.file_name().and_then(|name| name.to_str()),
                    Some("cert.pem" | "fullchain.pem")
                );
                let letsencrypt = path.starts_with("/etc/letsencrypt/live/") && letsencrypt_name;
                let local_certificate = path.starts_with("/etc/ssl/")
                    && matches!(
                        path.extension().and_then(|extension| extension.to_str()),
                        Some("pem" | "crt")
                    );
                if letsencrypt || local_certificate {
                    Ok(())
                } else {
                    Err(OperationContractError::ForeignSnapshotPath(
                        path.display().to_string(),
                    ))
                }
            }
            Self::ListenerInventory => Ok(()),
        }
    }
}

/// 운영 단계입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationPhase {
    /// 현재 상태와 필수 dependency를 변경 없이 검사합니다.
    Preflight,
    /// 변경 대상만 transaction directory에 보존합니다.
    Snapshot,
    /// versioned release directory를 준비합니다.
    StageRelease,
    /// config, Nginx와 service 후보를 검사합니다.
    ValidateCandidate,
    /// 검증된 deployment snapshot의 VPSGuard-owned 상태를 복구합니다.
    RestoreOwnedState,
    /// public ingress 소유자를 짧게 전환합니다.
    SwitchIngress,
    /// 활성 release symlink 또는 service를 교체합니다.
    ActivateRelease,
    /// listener, HTTP/TLS와 보존 항목을 read-back합니다.
    VerifyTarget,
    /// 완료 상태와 release 식별자를 확정합니다.
    Commit,
    /// 저장된 snapshot으로 역순 복구합니다.
    Rollback,
}

/// 한 단계의 측정 결과입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseReport {
    /// 완료한 단계입니다.
    pub phase: OperationPhase,
    /// 단계 전체 실행 시간입니다.
    pub elapsed_ms: u64,
    /// 이 단계 중 public 정상 응답이 없었던 시간입니다.
    pub public_interruption_ms: u64,
}

impl PhaseReport {
    /// 측정값을 만듭니다.
    #[must_use]
    pub fn new(phase: OperationPhase, elapsed_ms: u64, public_interruption_ms: u64) -> Self {
        Self {
            phase,
            elapsed_ms,
            public_interruption_ms,
        }
    }
}

/// 운영 실패의 사용자용 구조화 정보입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationIssue {
    /// 안정적인 오류 code입니다.
    pub code: String,
    /// 발생한 문제입니다.
    pub problem: String,
    /// 관측된 원인입니다.
    pub cause: String,
    /// 적용 또는 복구에 미친 영향입니다.
    pub impact: String,
    /// 운영자가 취할 다음 조치입니다.
    pub next_action: String,
}

/// persisted transaction 상태입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    /// 정상 단계를 실행 중입니다.
    Running,
    /// 저장된 snapshot으로 복구 중입니다.
    RollingBack,
    /// 모든 단계와 read-back이 성공했습니다.
    Succeeded,
    /// 변경 전 실패하여 rollback이 필요하지 않습니다.
    Failed,
    /// 실패 후 자동 rollback이 성공했습니다.
    RolledBack,
    /// 자동 rollback도 실패해 수동 복구가 필요합니다.
    RollbackFailed,
}

/// 재개 가능한 transaction ledger입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationState {
    /// state schema 버전입니다.
    pub schema_version: u32,
    /// plan의 operation 식별자입니다.
    pub operation_id: String,
    /// 확인된 plan SHA-256입니다.
    pub plan_sha256: String,
    /// 현재 실행 상태입니다.
    pub status: OperationStatus,
    /// process 중단 시 다시 실행할 현재 단계입니다.
    pub current_phase: Option<OperationPhase>,
    /// 원자 저장이 끝난 완료 단계입니다.
    pub completed: Vec<PhaseReport>,
    /// 마지막 구조화 실패입니다.
    pub last_issue: Option<OperationIssue>,
    /// 자동 rollback 자체가 실패했을 때의 별도 원인입니다.
    pub rollback_issue: Option<OperationIssue>,
}

impl OperationState {
    /// 검증된 plan의 초기 ledger를 만듭니다.
    ///
    /// # Errors
    ///
    /// plan 검증 또는 hash 생성 실패를 반환합니다.
    pub fn new(plan: &OperationPlan) -> Result<Self, OperationContractError> {
        Ok(Self {
            schema_version: OPERATION_SCHEMA_VERSION,
            operation_id: plan.operation_id.clone(),
            plan_sha256: plan.sha256()?,
            status: OperationStatus::Running,
            current_phase: None,
            completed: Vec::new(),
            last_issue: None,
            rollback_issue: None,
        })
    }

    /// ledger가 plan의 prefix 순서와 일치하는지 검증합니다.
    ///
    /// # Errors
    ///
    /// schema, plan hash 또는 완료 단계 순서가 잘못되면 반환합니다.
    pub fn validate_for(&self, plan: &OperationPlan) -> Result<(), OperationEngineError> {
        if self.schema_version != OPERATION_SCHEMA_VERSION {
            return Err(OperationEngineError::StateConflict {
                problem: format!(
                    "지원하지 않는 operation state schema입니다: {}",
                    self.schema_version
                ),
            });
        }
        let expected_hash = plan.sha256()?;
        if self.operation_id != plan.operation_id || self.plan_sha256 != expected_hash {
            return Err(OperationEngineError::StateConflict {
                problem: "실행 중 state와 요청 plan이 다릅니다.".to_owned(),
            });
        }
        let phases = plan.operation.phases();
        for (index, report) in self
            .completed
            .iter()
            .filter(|report| report.phase != OperationPhase::Rollback)
            .enumerate()
        {
            if phases.get(index) != Some(&report.phase) {
                return Err(OperationEngineError::StateConflict {
                    problem: format!("완료 단계 순서가 잘못됐습니다: {:?}", report.phase),
                });
            }
        }
        if let Some(current_phase) = self.current_phase {
            let expected = if self.status == OperationStatus::RollingBack {
                Some(OperationPhase::Rollback)
            } else {
                phases.get(self.normal_phase_count()).copied()
            };
            if expected != Some(current_phase) {
                return Err(OperationEngineError::StateConflict {
                    problem: format!(
                        "현재 단계가 완료 prefix와 다릅니다: expected={expected:?}, actual={current_phase:?}"
                    ),
                });
            }
        }
        let normal_phase_count = self.normal_phase_count();
        let rollback_complete = self
            .completed
            .last()
            .is_some_and(|report| report.phase == OperationPhase::Rollback);
        let valid_status = match self.status {
            OperationStatus::Running => !rollback_complete,
            OperationStatus::RollingBack => {
                self.current_phase == Some(OperationPhase::Rollback) && !rollback_complete
            }
            OperationStatus::Succeeded => {
                self.current_phase.is_none()
                    && normal_phase_count == phases.len()
                    && !rollback_complete
                    && self.last_issue.is_none()
                    && self.rollback_issue.is_none()
            }
            OperationStatus::Failed => {
                self.current_phase.is_none() && !rollback_complete && self.last_issue.is_some()
            }
            OperationStatus::RolledBack => {
                self.current_phase.is_none()
                    && rollback_complete
                    && self.last_issue.is_some()
                    && self.rollback_issue.is_none()
            }
            OperationStatus::RollbackFailed => {
                self.current_phase.is_none()
                    && !rollback_complete
                    && self.last_issue.is_some()
                    && self.rollback_issue.is_some()
            }
        };
        if !valid_status {
            return Err(OperationEngineError::StateConflict {
                problem: format!("상태와 완료 단계가 일치하지 않습니다: {:?}", self.status),
            });
        }
        Ok(())
    }

    fn normal_phase_count(&self) -> usize {
        self.completed
            .iter()
            .filter(|report| report.phase != OperationPhase::Rollback)
            .count()
    }

    fn elapsed_ms(&self) -> u64 {
        self.completed
            .iter()
            .filter(|report| report.phase != OperationPhase::Rollback)
            .map(|report| report.elapsed_ms)
            .sum()
    }

    fn interruption_ms(&self) -> u64 {
        self.completed
            .iter()
            .filter(|report| report.phase != OperationPhase::Rollback)
            .map(|report| report.public_interruption_ms)
            .sum()
    }
}

/// OS 변경을 수행하는 project-owned adapter 계약입니다.
pub trait OperationDriver {
    /// 한 단계를 timeout 안에 실행하고 실제 duration을 반환합니다.
    ///
    /// # Errors
    ///
    /// 단계 실패를 구조화 [`OperationIssue`]로 반환합니다.
    fn run_phase(
        &mut self,
        plan: &OperationPlan,
        phase: OperationPhase,
        timeout: Duration,
    ) -> Result<PhaseReport, OperationIssue>;

    /// 저장된 snapshot을 timeout 안에 역순 복구합니다.
    ///
    /// # Errors
    ///
    /// 자동 복구 실패를 구조화 [`OperationIssue`]로 반환합니다.
    fn rollback(
        &mut self,
        plan: &OperationPlan,
        timeout: Duration,
    ) -> Result<PhaseReport, OperationIssue>;
}

/// 운영 plan 또는 snapshot 계약 오류입니다.
#[derive(Debug, Error)]
pub enum OperationContractError {
    /// 지원하지 않는 미래 schema입니다.
    #[error("지원하지 않는 operation schema입니다: {0}")]
    UnsupportedSchema(u32),
    /// 식별자가 비었거나 허용 문자를 벗어났습니다.
    #[error("잘못된 {field}입니다: {value}")]
    InvalidIdentifier {
        /// 필드 이름입니다.
        field: &'static str,
        /// 거부한 값입니다.
        value: String,
    },
    /// topology 변경 작업의 source와 target이 같습니다.
    #[error("source와 target ingress topology가 같습니다")]
    UnchangedTopology,
    /// 시간 예산이 hard limit을 넘었습니다.
    #[error("운영 시간 예산이 hard limit을 넘었습니다: {0}")]
    ExcessiveBudget(&'static str),
    /// snapshot resource가 없습니다.
    #[error("snapshot resource가 비어 있습니다")]
    EmptySnapshot,
    /// non-web listener read-back이 없습니다.
    #[error("listener inventory가 snapshot 범위에 없습니다")]
    MissingListenerInventory,
    /// 사이트 tree 또는 허용되지 않은 경로입니다.
    #[error("snapshot 허용 범위 밖 경로입니다: {0}")]
    ForeignSnapshotPath(String),
    /// 허용되지 않은 service입니다.
    #[error("snapshot 허용 범위 밖 service입니다: {0}")]
    ForeignService(String),
    /// 허용되지 않은 system account입니다.
    #[error("snapshot 허용 범위 밖 system account입니다: {0}")]
    ForeignSystemAccount(String),
    /// plan JSON encode 실패입니다.
    #[error("operation plan JSON 처리 실패: {0}")]
    Json(#[from] serde_json::Error),
}

/// lock, state 저장, 시간 예산 또는 rollback 실행 오류입니다.
#[derive(Debug, Error)]
pub enum OperationEngineError {
    /// plan 계약 오류입니다.
    #[error(transparent)]
    Contract(#[from] OperationContractError),
    /// 원자 state 저장 오류입니다.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// operation lock 파일 작업 오류입니다.
    #[error("operation lock 실패: operation={operation}, path={path}, cause={source}")]
    LockIo {
        /// 실패한 lock 작업입니다.
        operation: &'static str,
        /// lock 파일 경로입니다.
        path: String,
        /// 원본 I/O 오류입니다.
        source: std::io::Error,
    },
    /// 다른 process가 운영 작업을 실행 중입니다.
    #[error("다른 운영 transaction이 실행 중입니다: {active_operation_id}")]
    Busy {
        /// lock record의 operation 식별자입니다.
        active_operation_id: String,
    },
    /// 기존 state가 요청 plan과 충돌합니다.
    #[error("operation state 충돌: {problem}")]
    StateConflict {
        /// 충돌 설명입니다.
        problem: String,
    },
    /// 이전 terminal state는 새 operation ID 없이는 재실행할 수 없습니다.
    #[error("operation이 이미 종료됐습니다: status={status:?}")]
    TerminalState {
        /// 저장된 terminal 상태입니다.
        status: OperationStatus,
    },
    /// 단계 실패 후 rollback 결과입니다.
    #[error("operation 실패: id={operation_id}, rollback_succeeded={rollback_succeeded}")]
    OperationFailed {
        /// 실패한 operation 식별자입니다.
        operation_id: String,
        /// 자동 rollback 성공 여부입니다.
        rollback_succeeded: bool,
    },
}

#[derive(Debug, Deserialize, Serialize)]
struct LockRecord {
    schema_version: u32,
    operation_id: String,
    pid: u32,
    acquired_at: String,
}

/// process lifetime 동안 하나의 운영 작업만 허용하는 advisory OS lock입니다.
#[derive(Debug)]
pub struct OperationLock {
    file: File,
}

impl OperationLock {
    /// lock을 non-blocking으로 획득하고 활성 operation ID를 기록합니다.
    ///
    /// # Errors
    ///
    /// 다른 process가 lock을 소유하면 [`OperationEngineError::Busy`]를 반환합니다.
    pub fn acquire(
        path: impl Into<PathBuf>,
        operation_id: &str,
    ) -> Result<Self, OperationEngineError> {
        let path = path.into();
        let parent = path.parent().ok_or_else(|| OperationEngineError::LockIo {
            operation: "resolve_parent",
            path: path.display().to_string(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "lock parent가 없습니다"),
        })?;
        fs::create_dir_all(parent).map_err(|source| lock_io("create_parent", &path, source))?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .map_err(|source| lock_io("open", &path, source))?;
        if let Err(error) = flock(&file, FlockOperation::NonBlockingLockExclusive) {
            let active_operation_id =
                read_lock_operation(&path).unwrap_or_else(|| "initializing".to_owned());
            if error == rustix::io::Errno::WOULDBLOCK || error == rustix::io::Errno::AGAIN {
                return Err(OperationEngineError::Busy {
                    active_operation_id,
                });
            }
            return Err(lock_io("flock", &path, std::io::Error::from(error)));
        }
        file.set_len(0)
            .map_err(|source| lock_io("truncate", &path, source))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|source| lock_io("seek", &path, source))?;
        let record = LockRecord {
            schema_version: OPERATION_SCHEMA_VERSION,
            operation_id: operation_id.to_owned(),
            pid: std::process::id(),
            acquired_at: format_now(),
        };
        let bytes = serde_json::to_vec(&record).map_err(OperationContractError::Json)?;
        file.write_all(&bytes)
            .map_err(|source| lock_io("write", &path, source))?;
        file.sync_all()
            .map_err(|source| lock_io("sync", &path, source))?;
        Ok(Self { file })
    }
}

impl Drop for OperationLock {
    fn drop(&mut self) {
        let _ignored = flock(&self.file, FlockOperation::Unlock);
    }
}

/// plan을 단일 lock 아래 실행하고 단계 state를 원자 저장합니다.
///
/// 이미 같은 plan의 `Running` state가 있으면 마지막 완료 단계 다음부터 재개합니다.
/// 실패가 snapshot 이후 발생하면 driver rollback을 즉시 실행합니다.
///
/// # Errors
///
/// plan·state·lock 오류 또는 rollback 결과를 포함한 실행 실패를 반환합니다.
pub fn execute_operation<D>(
    plan: &OperationPlan,
    state_path: impl Into<PathBuf>,
    lock_path: impl Into<PathBuf>,
    driver: &mut D,
) -> Result<OperationState, OperationEngineError>
where
    D: OperationDriver,
{
    plan.validate()?;
    let _lock = OperationLock::acquire(lock_path, &plan.operation_id)?;
    let store = AtomicJsonStore::<OperationState>::new(state_path.into());
    let mut state = if store.path().exists() {
        store.read()?
    } else {
        OperationState::new(plan)?
    };
    state.validate_for(plan)?;
    match state.status {
        OperationStatus::Running => {}
        OperationStatus::RollingBack => {
            return complete_rollback(plan, state, &store, driver);
        }
        OperationStatus::Succeeded => return Ok(state),
        status => return Err(OperationEngineError::TerminalState { status }),
    }
    store.write(&state)?;

    let phases = plan.operation.phases();
    for phase in phases.into_iter().skip(state.normal_phase_count()) {
        state.current_phase = Some(phase);
        store.write(&state)?;
        let timeout = plan.budgets.timeout_for(phase);
        match driver.run_phase(plan, phase, timeout) {
            Ok(report) => {
                if let Err(issue) = validate_phase_report(plan, &state, phase, &report) {
                    return fail_operation(plan, state, &store, driver, issue);
                }
                state.completed.push(report);
                state.current_phase = None;
                store.write(&state)?;
            }
            Err(issue) => return fail_operation(plan, state, &store, driver, issue),
        }
    }
    state.status = OperationStatus::Succeeded;
    state.current_phase = None;
    store.write(&state)?;
    Ok(state)
}

fn fail_operation<D>(
    plan: &OperationPlan,
    mut state: OperationState,
    store: &AtomicJsonStore<OperationState>,
    driver: &mut D,
    issue: OperationIssue,
) -> Result<OperationState, OperationEngineError>
where
    D: OperationDriver,
{
    state.last_issue = Some(issue);
    state.current_phase = None;
    let snapshot_complete = state
        .completed
        .iter()
        .any(|report| report.phase == OperationPhase::Snapshot);
    if !snapshot_complete {
        state.status = OperationStatus::Failed;
        store.write(&state)?;
        return Err(OperationEngineError::OperationFailed {
            operation_id: plan.operation_id.clone(),
            rollback_succeeded: false,
        });
    }

    state.status = OperationStatus::RollingBack;
    state.current_phase = Some(OperationPhase::Rollback);
    store.write(&state)?;
    complete_rollback(plan, state, store, driver)
}

fn complete_rollback<D>(
    plan: &OperationPlan,
    mut state: OperationState,
    store: &AtomicJsonStore<OperationState>,
    driver: &mut D,
) -> Result<OperationState, OperationEngineError>
where
    D: OperationDriver,
{
    let rollback_result = driver.rollback(plan, plan.budgets.timeout_for(OperationPhase::Rollback));
    let rollback_succeeded = match rollback_result {
        Ok(report)
            if report.phase == OperationPhase::Rollback
                && report.elapsed_ms <= plan.budgets.rollback_ms
                && report.public_interruption_ms <= report.elapsed_ms =>
        {
            state.completed.push(report);
            state.rollback_issue = None;
            state.status = OperationStatus::RolledBack;
            true
        }
        Ok(report) => {
            state.rollback_issue = Some(budget_issue(
                "ROLLBACK_BUDGET_EXCEEDED",
                format!("rollback report가 계약을 위반했습니다: {report:?}"),
            ));
            state.status = OperationStatus::RollbackFailed;
            false
        }
        Err(rollback_issue) => {
            state.rollback_issue = Some(rollback_issue);
            state.status = OperationStatus::RollbackFailed;
            false
        }
    };
    state.current_phase = None;
    store.write(&state)?;
    Err(OperationEngineError::OperationFailed {
        operation_id: plan.operation_id.clone(),
        rollback_succeeded,
    })
}

fn validate_phase_report(
    plan: &OperationPlan,
    state: &OperationState,
    phase: OperationPhase,
    report: &PhaseReport,
) -> Result<(), OperationIssue> {
    if report.phase != phase {
        return Err(budget_issue(
            "PHASE_REPORT_MISMATCH",
            format!("expected={phase:?}, actual={:?}", report.phase),
        ));
    }
    let phase_limit: u64 = plan
        .budgets
        .timeout_for(phase)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);
    if report.elapsed_ms > phase_limit {
        return Err(budget_issue(
            "PHASE_TIMEOUT_EXCEEDED",
            format!(
                "phase={phase:?}, elapsed_ms={}, limit_ms={phase_limit}",
                report.elapsed_ms
            ),
        ));
    }
    if report.public_interruption_ms > report.elapsed_ms {
        return Err(budget_issue(
            "INVALID_INTERRUPTION_MEASUREMENT",
            format!(
                "interruption_ms={}, elapsed_ms={}",
                report.public_interruption_ms, report.elapsed_ms
            ),
        ));
    }
    if state.elapsed_ms().saturating_add(report.elapsed_ms) > plan.budgets.operation_ms {
        return Err(budget_issue(
            "OPERATION_BUDGET_EXCEEDED",
            format!("operation limit_ms={}", plan.budgets.operation_ms),
        ));
    }
    if state
        .interruption_ms()
        .saturating_add(report.public_interruption_ms)
        > plan.budgets.public_interruption_ms
    {
        return Err(budget_issue(
            "PUBLIC_INTERRUPTION_BUDGET_EXCEEDED",
            format!(
                "public ingress 순단 limit_ms={}",
                plan.budgets.public_interruption_ms
            ),
        ));
    }
    Ok(())
}

fn validate_budgets(
    kind: OperationKind,
    budgets: OperationBudgets,
) -> Result<(), OperationContractError> {
    if budgets.preflight_ms == 0 || budgets.preflight_ms > MAX_PREFLIGHT_MS {
        return Err(OperationContractError::ExcessiveBudget("preflight 60초"));
    }
    if budgets.phase_ms == 0 || budgets.phase_ms > MAX_APPLY_MS {
        return Err(OperationContractError::ExcessiveBudget("일반 단계 60초"));
    }
    if budgets.public_interruption_ms == 0
        || budgets.public_interruption_ms > MAX_PUBLIC_INTERRUPTION_MS
    {
        return Err(OperationContractError::ExcessiveBudget(
            "public ingress 순단 5초",
        ));
    }
    if budgets.rollback_ms == 0 || budgets.rollback_ms > MAX_ROLLBACK_MS {
        return Err(OperationContractError::ExcessiveBudget("rollback 10초"));
    }
    if budgets.operation_ms == 0 || budgets.operation_ms > kind.maximum_operation_ms() {
        return Err(OperationContractError::ExcessiveBudget(
            "apply/update 60초 또는 restore 30초",
        ));
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), OperationContractError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(OperationContractError::InvalidIdentifier {
            field,
            value: value.to_owned(),
        })
    }
}

fn validate_owned_path(path: &Path) -> Result<(), OperationContractError> {
    validate_absolute_file(path)?;
    let text = path.display().to_string();
    let allowed = [
        "/etc/vps-guard/",
        "/var/lib/vps-guard/",
        "/run/vps-guard/",
        "/usr/local/libexec/vps-guard/",
        "/etc/systemd/system/vps-guard-",
    ];
    let exact = [
        "/usr/local/bin/vps-guard",
        "/usr/local/bin/vps-guard-control",
        "/usr/local/bin/vps-guard-privileged",
        "/usr/local/bin/vps-guard-edge",
        "/usr/local/lib/vps-guard/current",
        "/usr/lib/tmpfiles.d/vps-guard.conf",
        "/etc/pam.d/vps-guard",
        "/etc/letsencrypt/renewal-hooks/deploy/vps-guard",
    ];
    if allowed.iter().any(|prefix| text.starts_with(prefix)) || exact.contains(&text.as_str()) {
        Ok(())
    } else {
        Err(OperationContractError::ForeignSnapshotPath(text))
    }
}

fn validate_owned_directory(path: &Path) -> Result<(), OperationContractError> {
    validate_absolute_file(path)?;
    let allowed = [
        "/usr/local/lib/vps-guard/releases",
        "/usr/local/lib/vps-guard",
        "/usr/local/libexec/vps-guard",
        "/etc/systemd/system/vps-guard-control.service.d",
        "/etc/systemd/system/vps-guard-edge.service.d",
        "/etc/vps-guard/secrets",
        "/etc/vps-guard/apache",
        "/etc/vps-guard",
        "/run/vps-guard",
        "/run/vps-guard-privileged",
        "/var/lib/vps-guard",
    ];
    if allowed.contains(&path.to_string_lossy().as_ref()) {
        Ok(())
    } else {
        Err(OperationContractError::ForeignSnapshotPath(
            path.display().to_string(),
        ))
    }
}

fn validate_protected_path(path: &Path) -> Result<(), OperationContractError> {
    validate_absolute_file(path)?;
    let allowed = [
        "/etc/ssh",
        "/etc/nginx",
        "/etc/letsencrypt",
        "/home/g7devops/public_html",
    ];
    if allowed.contains(&path.to_string_lossy().as_ref()) {
        Ok(())
    } else {
        Err(OperationContractError::ForeignSnapshotPath(
            path.display().to_string(),
        ))
    }
}

fn validate_ingress_path(path: &Path, symlink: bool) -> Result<(), OperationContractError> {
    validate_absolute_file(path)?;
    let allowed = if symlink {
        path.starts_with("/etc/nginx/sites-enabled/")
    } else {
        path.starts_with("/etc/nginx/sites-available/")
            || path.starts_with("/etc/nginx/sites-enabled/")
            || path.starts_with("/etc/nginx/conf.d/")
    };
    if allowed {
        Ok(())
    } else {
        Err(OperationContractError::ForeignSnapshotPath(
            path.display().to_string(),
        ))
    }
}

fn validate_apache_ingress_path(path: &Path, symlink: bool) -> Result<(), OperationContractError> {
    validate_absolute_file(path)?;
    let allowed = if symlink {
        path.starts_with("/etc/apache2/sites-enabled/")
            || path.starts_with("/etc/apache2/conf-enabled/")
            || path.starts_with("/etc/apache2/mods-enabled/")
    } else {
        path.starts_with("/etc/apache2/sites-available/")
            || path.starts_with("/etc/apache2/sites-enabled/")
            || path.starts_with("/etc/apache2/conf-available/")
            || path.starts_with("/etc/apache2/conf-enabled/")
    };
    if allowed {
        Ok(())
    } else {
        Err(OperationContractError::ForeignSnapshotPath(
            path.display().to_string(),
        ))
    }
}

fn validate_absolute_file(path: &Path) -> Result<(), OperationContractError> {
    let valid = path.is_absolute()
        && path.file_name().is_some()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        && !path
            .as_os_str()
            .to_string_lossy()
            .bytes()
            .any(|byte| matches!(byte, b'*' | b'?' | b'[' | b']' | b'\n' | b'\r'));
    if valid {
        Ok(())
    } else {
        Err(OperationContractError::ForeignSnapshotPath(
            path.display().to_string(),
        ))
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ignored = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn budget_issue(code: &str, cause: String) -> OperationIssue {
    OperationIssue {
        code: code.to_owned(),
        problem: "운영 작업이 안전 시간 예산을 벗어났습니다.".to_owned(),
        cause,
        impact: "새 상태를 완료 처리하지 않고 자동 복구를 시도합니다.".to_owned(),
        next_action: "transaction 단계 duration과 rollback 결과를 확인하십시오.".to_owned(),
    }
}

fn format_now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unavailable".to_owned())
}

fn read_lock_operation(path: &Path) -> Option<String> {
    let mut bytes = Vec::new();
    File::open(path).ok()?.read_to_end(&mut bytes).ok()?;
    serde_json::from_slice::<LockRecord>(&bytes)
        .ok()
        .map(|record| record.operation_id)
}

fn lock_io(operation: &'static str, path: &Path, source: std::io::Error) -> OperationEngineError {
    OperationEngineError::LockIo {
        operation,
        path: path.display().to_string(),
        source,
    }
}

#[cfg(test)]
#[path = "operation/tests.rs"]
mod tests;
