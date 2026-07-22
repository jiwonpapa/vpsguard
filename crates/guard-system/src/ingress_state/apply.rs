//! Staged direct TLS candidate를 OPS-010 apply transaction으로 실행합니다.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::{
    INGRESS_SNAPSHOT_SCHEMA_VERSION, IngressStateError, IngressStateStore, elapsed_ms, issue,
};
use crate::{
    AtomicJsonStore, OperationDriver, OperationIssue, OperationKind, OperationPhase, OperationPlan,
    PhaseReport,
};

/// staged candidate 적용과 process-restart rollback을 소유하는 driver입니다.
#[derive(Debug)]
pub struct IngressApplyDriver {
    store: IngressStateStore,
    candidate_snapshot: PathBuf,
    rollback_snapshot: Option<PathBuf>,
    checkpoint: AtomicJsonStore<ApplyRollbackCheckpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ApplyRollbackCheckpoint {
    schema_version: u32,
    candidate_snapshot: PathBuf,
    rollback_snapshot: PathBuf,
}

impl IngressApplyDriver {
    /// candidate snapshot과 재시작 checkpoint를 묶습니다.
    ///
    /// # Errors
    ///
    /// checkpoint가 다른 candidate 또는 schema를 가리키면 거부합니다.
    pub fn with_checkpoint(
        store: IngressStateStore,
        candidate_snapshot: impl Into<PathBuf>,
        checkpoint_path: impl Into<PathBuf>,
    ) -> Result<Self, IngressStateError> {
        let candidate_snapshot = candidate_snapshot.into();
        let checkpoint = AtomicJsonStore::new(checkpoint_path.into());
        let rollback_snapshot = if checkpoint.path().exists() {
            let record: ApplyRollbackCheckpoint = checkpoint.read()?;
            if record.schema_version != INGRESS_SNAPSHOT_SCHEMA_VERSION
                || record.candidate_snapshot != candidate_snapshot
            {
                return Err(IngressStateError::Contract(
                    "direct apply checkpoint가 다른 candidate 또는 schema입니다".to_owned(),
                ));
            }
            Some(record.rollback_snapshot)
        } else {
            None
        };
        Ok(Self {
            store,
            candidate_snapshot,
            rollback_snapshot,
            checkpoint,
        })
    }

    /// public 변경 전 생성된 rollback snapshot입니다.
    #[must_use]
    pub fn rollback_snapshot(&self) -> Option<&Path> {
        self.rollback_snapshot.as_deref()
    }

    fn execute_phase(&mut self, phase: OperationPhase) -> Result<u64, IngressStateError> {
        match phase {
            OperationPhase::Preflight => {
                self.store.verify_snapshot(&self.candidate_snapshot)?;
                Ok(0)
            }
            OperationPhase::Snapshot => {
                let rollback_snapshot = self.store.create_snapshot("rollback")?;
                self.checkpoint.write(&ApplyRollbackCheckpoint {
                    schema_version: INGRESS_SNAPSHOT_SCHEMA_VERSION,
                    candidate_snapshot: self.candidate_snapshot.clone(),
                    rollback_snapshot: rollback_snapshot.clone(),
                })?;
                self.rollback_snapshot = Some(rollback_snapshot);
                Ok(0)
            }
            OperationPhase::StageRelease => Ok(0),
            OperationPhase::ValidateCandidate => {
                self.store.validate_candidate(&self.candidate_snapshot)?;
                Ok(0)
            }
            OperationPhase::SwitchIngress => self.store.restore_snapshot(&self.candidate_snapshot),
            OperationPhase::VerifyTarget => {
                self.store
                    .verify_restored_snapshot(&self.candidate_snapshot)?;
                Ok(0)
            }
            OperationPhase::Commit => Ok(0),
            other => Err(IngressStateError::Contract(format!(
                "direct apply driver가 지원하지 않는 단계입니다: {other:?}"
            ))),
        }
    }
}

impl OperationDriver for IngressApplyDriver {
    fn run_phase(
        &mut self,
        plan: &OperationPlan,
        phase: OperationPhase,
        _timeout: Duration,
    ) -> Result<PhaseReport, OperationIssue> {
        if plan.operation != OperationKind::Apply {
            return Err(issue("INGRESS_APPLY_KIND_INVALID", "apply plan이 아닙니다"));
        }
        let started = Instant::now();
        let interruption = self
            .execute_phase(phase)
            .map_err(|error| issue("INGRESS_APPLY_PHASE_FAILED", &error.to_string()))?;
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
                "INGRESS_APPLY_ROLLBACK_MISSING",
                "pre-cutover rollback snapshot이 없습니다",
            )
        })?;
        let interruption = self
            .store
            .restore_snapshot(&snapshot)
            .map_err(|error| issue("INGRESS_APPLY_ROLLBACK_FAILED", &error.to_string()))?;
        self.store
            .verify_restored_snapshot(&snapshot)
            .map_err(|error| issue("INGRESS_APPLY_ROLLBACK_VERIFY_FAILED", &error.to_string()))?;
        Ok(PhaseReport::new(
            OperationPhase::Rollback,
            elapsed_ms(started.elapsed()),
            interruption,
        ))
    }
}
