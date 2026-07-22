//! Standalone UFW 소유권과 bounded 승인 plan 저장소를 제공합니다.

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};

use guard_core::config::FirewallMode;
use guard_system::{
    CommandAudit, SystemUfwExecutor, UfwController, UfwError, UfwExecutor, UfwMutation, UfwPlan,
    UfwSnapshot,
};
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

use crate::privileged::PrivilegedUfwExecutor;

const MAX_PENDING_PLANS: usize = 32;

/// 관리 API에 노출하는 host firewall 상태입니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FirewallStatus {
    pub(crate) mode: FirewallMode,
    pub(crate) backend: &'static str,
    pub(crate) mutable: bool,
    pub(crate) snapshot: Option<UfwSnapshot>,
}

/// 승인 전 저장한 UFW plan입니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PendingFirewallPlan {
    pub(crate) operation_id: String,
    pub(crate) plan: UfwPlan,
}

/// UFW apply 결과입니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FirewallApplyResult {
    pub(crate) operation_id: String,
    pub(crate) audits: Vec<CommandAudit>,
}

/// control firewall orchestration 실패입니다.
#[derive(Debug, Error)]
pub(crate) enum FirewallError {
    #[error(transparent)]
    Ufw(#[from] UfwError),
    #[error("승인 대기 중인 firewall plan이 없습니다")]
    PlanNotFound,
}

/// API가 사용할 firewall orchestration 경계입니다.
pub(crate) trait FirewallOperations: Send + Sync {
    fn status(&self) -> Result<FirewallStatus, FirewallError>;
    fn plan(&self, mutation: UfwMutation) -> Result<PendingFirewallPlan, FirewallError>;
    fn apply(&self, operation_id: &str) -> Result<FirewallApplyResult, FirewallError>;
}

/// UFW controller와 bounded pending plan을 소유합니다.
pub(crate) struct FirewallManager<E = SystemUfwExecutor> {
    mode: FirewallMode,
    ssh_port: u16,
    controller: UfwController<E>,
    pending: Mutex<VecDeque<PendingFirewallPlan>>,
}

impl FirewallManager<PrivilegedUfwExecutor> {
    pub(crate) fn system(mode: FirewallMode, ssh_port: u16, socket: std::path::PathBuf) -> Self {
        Self::new(mode, ssh_port, PrivilegedUfwExecutor::new(socket))
    }
}

impl<E: UfwExecutor> FirewallManager<E> {
    pub(crate) const fn new(mode: FirewallMode, ssh_port: u16, executor: E) -> Self {
        Self {
            mode,
            ssh_port,
            controller: UfwController::new(executor),
            pending: Mutex::new(VecDeque::new()),
        }
    }

    fn lock_pending(&self) -> MutexGuard<'_, VecDeque<PendingFirewallPlan>> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn assert_mutable(&self) -> Result<(), FirewallError> {
        if self.mode == FirewallMode::StandaloneUfw {
            Ok(())
        } else {
            Err(FirewallError::Ufw(UfwError::OwnershipDenied))
        }
    }
}

impl<E: UfwExecutor> FirewallOperations for FirewallManager<E> {
    fn status(&self) -> Result<FirewallStatus, FirewallError> {
        if self.mode != FirewallMode::StandaloneUfw {
            return Ok(FirewallStatus {
                mode: self.mode,
                backend: if self.mode == FirewallMode::JwAgentDelegated {
                    "jw-agent"
                } else {
                    "disabled"
                },
                mutable: false,
                snapshot: None,
            });
        }
        let (snapshot, _) = self.controller.snapshot()?;
        Ok(FirewallStatus {
            mode: self.mode,
            backend: "ufw",
            mutable: true,
            snapshot: Some(snapshot),
        })
    }

    fn plan(&self, mutation: UfwMutation) -> Result<PendingFirewallPlan, FirewallError> {
        self.assert_mutable()?;
        let (snapshot, _) = self.controller.snapshot()?;
        let plan = UfwController::<E>::plan(self.mode, &snapshot, mutation, self.ssh_port)?;
        let pending = PendingFirewallPlan {
            operation_id: Uuid::new_v4().to_string(),
            plan,
        };
        let mut plans = self.lock_pending();
        while plans.len() >= MAX_PENDING_PLANS {
            plans.pop_front();
        }
        plans.push_back(pending.clone());
        Ok(pending)
    }

    fn apply(&self, operation_id: &str) -> Result<FirewallApplyResult, FirewallError> {
        self.assert_mutable()?;
        let plan = {
            let mut plans = self.lock_pending();
            let position = plans
                .iter()
                .position(|pending| pending.operation_id == operation_id)
                .ok_or(FirewallError::PlanNotFound)?;
            plans.remove(position).ok_or(FirewallError::PlanNotFound)?
        };
        let audits = self.controller.apply(&plan.plan)?;
        Ok(FirewallApplyResult {
            operation_id: plan.operation_id,
            audits,
        })
    }
}

#[cfg(test)]
mod tests {
    use guard_system::{CommandError, CommandOutput, UfwAction, UfwProtocol, UfwRule};

    use super::*;

    struct PanicExecutor;

    impl UfwExecutor for PanicExecutor {
        fn run(&self, _arguments: &[String]) -> Result<CommandOutput, CommandError> {
            Err(CommandError::Io(std::io::Error::other(
                "delegated mode executed UFW",
            )))
        }
    }

    #[test]
    fn delegated_mode_reports_owner_and_executes_no_ufw() -> Result<(), FirewallError> {
        let manager = FirewallManager::new(FirewallMode::JwAgentDelegated, 22, PanicExecutor);
        let status = manager.status()?;
        assert_eq!(status.backend, "jw-agent");
        assert!(!status.mutable);
        assert!(matches!(
            manager.plan(UfwMutation::Add {
                rule: UfwRule {
                    id: "web".to_owned(),
                    action: UfwAction::Allow,
                    source: None,
                    destination_port: Some(443),
                    protocol: UfwProtocol::Tcp,
                },
            }),
            Err(FirewallError::Ufw(UfwError::OwnershipDenied))
        ));
        Ok(())
    }
}
