//! OPS-010 운영 transaction의 시간 예산, 재개, lock과 rollback 회귀 테스트입니다.

use std::collections::VecDeque;
use std::path::Path;
use std::time::Duration;

use tempfile::tempdir;

use super::{
    IngressTopology, OperationDriver, OperationEngineError, OperationIssue, OperationKind,
    OperationPhase, OperationPlan, OperationState, OperationStatus, PhaseReport, SnapshotResource,
    execute_operation,
};

#[derive(Debug)]
struct FakeDriver {
    reports: VecDeque<Result<PhaseReport, OperationIssue>>,
    phases: Vec<OperationPhase>,
    rollback: Result<PhaseReport, OperationIssue>,
    rollback_calls: usize,
}

impl FakeDriver {
    fn successful() -> Self {
        Self {
            reports: VecDeque::new(),
            phases: Vec::new(),
            rollback: Ok(PhaseReport::new(OperationPhase::Rollback, 20, 0)),
            rollback_calls: 0,
        }
    }

    fn with_failure(phase: OperationPhase) -> Self {
        let mut driver = Self::successful();
        for candidate in OperationKind::Apply.phases() {
            if candidate == phase {
                driver.reports.push_back(Err(issue("FAULT_INJECTED")));
                break;
            }
            driver
                .reports
                .push_back(Ok(PhaseReport::new(candidate, 10, 0)));
        }
        driver
    }
}

impl OperationDriver for FakeDriver {
    fn run_phase(
        &mut self,
        _plan: &OperationPlan,
        phase: OperationPhase,
        _timeout: Duration,
    ) -> Result<PhaseReport, OperationIssue> {
        self.phases.push(phase);
        self.reports
            .pop_front()
            .unwrap_or_else(|| Ok(PhaseReport::new(phase, 10, 0)))
    }

    fn rollback(
        &mut self,
        _plan: &OperationPlan,
        _timeout: Duration,
    ) -> Result<PhaseReport, OperationIssue> {
        self.rollback_calls += 1;
        self.rollback.clone()
    }
}

fn issue(code: &str) -> OperationIssue {
    OperationIssue {
        code: code.to_owned(),
        problem: "운영 단계가 실패했습니다.".to_owned(),
        cause: "fault fixture".to_owned(),
        impact: "새 topology를 완료하지 않았습니다.".to_owned(),
        next_action: "저장된 rollback 상태를 확인하십시오.".to_owned(),
    }
}

fn plan(operation_id: &str, kind: OperationKind) -> OperationPlan {
    OperationPlan::new(
        operation_id,
        kind,
        "release-0123456789abcdef",
        IngressTopology::NginxPublic,
        IngressTopology::VpsGuardPublic,
        vec![
            SnapshotResource::OwnedPath {
                path: "/etc/vps-guard/config.toml".into(),
            },
            SnapshotResource::IngressFile {
                path: "/etc/nginx/sites-available/site.conf".into(),
            },
            SnapshotResource::Service {
                unit: "nginx.service".to_owned(),
            },
            SnapshotResource::CertificateFingerprint {
                path: "/etc/letsencrypt/live/example.com/fullchain.pem".into(),
            },
            SnapshotResource::ListenerInventory,
        ],
    )
}

fn state_path(root: &Path) -> std::path::PathBuf {
    root.join("transactions/active/state.json")
}

fn lock_path(root: &Path) -> std::path::PathBuf {
    root.join("operation.lock")
}

#[test]
fn plan_rejects_site_tree_and_excessive_budgets() {
    let mut unsafe_plan = plan("op-site", OperationKind::Apply);
    unsafe_plan.resources.push(SnapshotResource::OwnedPath {
        path: "/home/example/public_html".into(),
    });
    let error = unsafe_plan
        .validate()
        .map_or_else(|error| error.to_string(), |()| String::new());
    assert!(error.contains("snapshot 허용 범위 밖"));

    let mut slow_plan = plan("op-slow", OperationKind::Apply);
    slow_plan.budgets.public_interruption_ms = 5_001;
    let error = slow_plan
        .validate()
        .map_or_else(|error| error.to_string(), |()| String::new());
    assert!(error.contains("public ingress 순단"));
}

#[test]
fn restore_plan_may_preserve_the_current_ingress_topology() {
    let mut restore = plan("op-restore", OperationKind::Restore);
    restore.target_topology = restore.source_topology;

    assert!(restore.validate().is_ok());
}

#[test]
fn successful_apply_records_ordered_progress_and_releases_lock()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let plan = plan("op-success", OperationKind::Apply);
    let mut driver = FakeDriver::successful();
    let state = execute_operation(
        &plan,
        state_path(temp.path()),
        lock_path(temp.path()),
        &mut driver,
    )?;

    assert_eq!(state.status, OperationStatus::Succeeded);
    assert_eq!(driver.phases, OperationKind::Apply.phases());
    assert_eq!(state.completed.len(), driver.phases.len());
    let reacquired = super::OperationLock::acquire(lock_path(temp.path()), "op-next")?;
    drop(reacquired);
    Ok(())
}

#[test]
fn cutover_failure_automatically_rolls_back_and_persists_cause()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let plan = plan("op-rollback", OperationKind::Apply);
    let mut driver = FakeDriver::with_failure(OperationPhase::SwitchIngress);
    let result = execute_operation(
        &plan,
        state_path(temp.path()),
        lock_path(temp.path()),
        &mut driver,
    );

    assert!(matches!(
        result,
        Err(OperationEngineError::OperationFailed { .. })
    ));
    assert_eq!(driver.rollback_calls, 1);
    let state: OperationState = serde_json::from_slice(&std::fs::read(state_path(temp.path()))?)?;
    assert_eq!(state.status, OperationStatus::RolledBack);
    assert_eq!(
        state.last_issue.as_ref().map(|entry| entry.code.as_str()),
        Some("FAULT_INJECTED")
    );
    Ok(())
}

#[test]
fn rollback_failure_preserves_both_the_apply_and_rollback_causes()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let plan = plan("op-rollback-failed", OperationKind::Apply);
    let mut driver = FakeDriver::with_failure(OperationPhase::SwitchIngress);
    driver.rollback = Err(issue("ROLLBACK_FAULT_INJECTED"));

    let result = execute_operation(
        &plan,
        state_path(temp.path()),
        lock_path(temp.path()),
        &mut driver,
    );
    assert!(matches!(
        result,
        Err(OperationEngineError::OperationFailed {
            rollback_succeeded: false,
            ..
        })
    ));
    let state: OperationState = serde_json::from_slice(&std::fs::read(state_path(temp.path()))?)?;
    assert_eq!(state.status, OperationStatus::RollbackFailed);
    assert_eq!(
        state.last_issue.as_ref().map(|entry| entry.code.as_str()),
        Some("FAULT_INJECTED")
    );
    assert_eq!(
        state
            .rollback_issue
            .as_ref()
            .map(|entry| entry.code.as_str()),
        Some("ROLLBACK_FAULT_INJECTED")
    );
    Ok(())
}

#[test]
fn interruption_budget_violation_is_a_failure_and_rollback_trigger()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let plan = plan("op-budget", OperationKind::Apply);
    let mut driver = FakeDriver::successful();
    for phase in OperationKind::Apply.phases() {
        let interruption = usize::from(phase == OperationPhase::SwitchIngress) as u64 * 5_001;
        driver.reports.push_back(Ok(PhaseReport::new(
            phase,
            interruption.max(10),
            interruption,
        )));
    }

    let result = execute_operation(
        &plan,
        state_path(temp.path()),
        lock_path(temp.path()),
        &mut driver,
    );
    assert!(matches!(
        result,
        Err(OperationEngineError::OperationFailed { .. })
    ));
    assert_eq!(driver.rollback_calls, 1);
    Ok(())
}

#[test]
fn running_transaction_resumes_after_the_last_completed_phase()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let plan = plan("op-resume", OperationKind::Apply);
    let mut state = OperationState::new(&plan)?;
    state
        .completed
        .push(PhaseReport::new(OperationPhase::Preflight, 10, 0));
    state
        .completed
        .push(PhaseReport::new(OperationPhase::Snapshot, 10, 0));
    let store = super::AtomicJsonStore::new(state_path(temp.path()));
    store.write(&state)?;

    let mut driver = FakeDriver::successful();
    let result = execute_operation(
        &plan,
        state_path(temp.path()),
        lock_path(temp.path()),
        &mut driver,
    )?;
    assert_eq!(result.status, OperationStatus::Succeeded);
    assert_eq!(driver.phases.first(), Some(&OperationPhase::StageRelease));
    Ok(())
}

#[test]
fn interrupted_rollback_is_resumed_instead_of_starting_apply_again()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let plan = plan("op-resume-rollback", OperationKind::Apply);
    let mut state = OperationState::new(&plan)?;
    state.status = OperationStatus::RollingBack;
    state.current_phase = Some(OperationPhase::Rollback);
    state
        .completed
        .push(PhaseReport::new(OperationPhase::Preflight, 10, 0));
    state
        .completed
        .push(PhaseReport::new(OperationPhase::Snapshot, 10, 0));
    let store = super::AtomicJsonStore::new(state_path(temp.path()));
    store.write(&state)?;

    let mut driver = FakeDriver::successful();
    let result = execute_operation(
        &plan,
        state_path(temp.path()),
        lock_path(temp.path()),
        &mut driver,
    );
    assert!(matches!(
        result,
        Err(OperationEngineError::OperationFailed {
            rollback_succeeded: true,
            ..
        })
    ));
    assert!(driver.phases.is_empty());
    assert_eq!(driver.rollback_calls, 1);
    let restored: OperationState =
        serde_json::from_slice(&std::fs::read(state_path(temp.path()))?)?;
    assert_eq!(restored.status, OperationStatus::RolledBack);
    Ok(())
}

#[test]
fn incomplete_succeeded_ledger_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let plan = plan("op-incomplete-success", OperationKind::Apply);
    let mut state = OperationState::new(&plan)?;
    state.status = OperationStatus::Succeeded;
    state
        .completed
        .push(PhaseReport::new(OperationPhase::Preflight, 10, 0));
    let store = super::AtomicJsonStore::new(state_path(temp.path()));
    store.write(&state)?;

    let mut driver = FakeDriver::successful();
    let result = execute_operation(
        &plan,
        state_path(temp.path()),
        lock_path(temp.path()),
        &mut driver,
    );
    assert!(matches!(
        result,
        Err(OperationEngineError::StateConflict { .. })
    ));
    assert!(driver.phases.is_empty());
    Ok(())
}

#[test]
fn concurrent_operation_reports_the_active_transaction() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let first = super::OperationLock::acquire(lock_path(temp.path()), "op-first")?;
    let error = super::OperationLock::acquire(lock_path(temp.path()), "op-second");
    assert!(matches!(
        error,
        Err(OperationEngineError::Busy {
            active_operation_id,
        }) if active_operation_id == "op-first"
    ));
    drop(first);
    let reacquired = super::OperationLock::acquire(lock_path(temp.path()), "op-second")?;
    drop(reacquired);
    Ok(())
}
