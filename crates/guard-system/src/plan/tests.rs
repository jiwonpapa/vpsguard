//! 변경 plan 보존 불변조건 테스트입니다.

use std::path::PathBuf;

use super::{MutationPlan, PlanError, PlannedChange};

fn base(changes: Vec<PlannedChange>) -> MutationPlan {
    MutationPlan {
        schema_version: 1,
        operation_id: "test-1".to_owned(),
        changes,
        preserve: vec![
            "ssh".to_owned(),
            "certificates".to_owned(),
            "site-data".to_owned(),
        ],
    }
}

#[test]
fn accepts_owned_paths() {
    let plan = base(vec![PlannedChange::WriteOwnedFile {
        path: PathBuf::from("/etc/vps-guard/config.toml"),
    }]);
    assert_eq!(plan.validate(), Ok(()));
}

#[test]
fn rejects_ssh_mutation() {
    let plan = base(vec![PlannedChange::WriteOwnedFile {
        path: PathBuf::from("/etc/ssh/sshd_config"),
    }]);
    assert_eq!(
        plan.validate(),
        Err(PlanError::ForeignPath("/etc/ssh/sshd_config".to_owned()))
    );
}
