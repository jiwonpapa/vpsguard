//! nftables, systemd, TLS 파일, Nginx와 원자 파일 작업 adapter를 소유합니다.
//!
//! 외부 명령은 검증된 argv와 공통 command runner를 통해서만 실행합니다.

pub mod atomic_store;
pub mod command;
pub mod deployment_state;
pub mod ingress_state;
pub mod nftables;
pub mod operation;
pub mod plan;
pub mod secret;
pub mod tls;

pub use atomic_store::{AtomicJsonStore, StoreError};
pub use command::{CommandAudit, CommandError, CommandOutput, OwnedProgram, SystemCommandRunner};
pub use deployment_state::{
    DEPLOYMENT_SNAPSHOT_SCHEMA_VERSION, DeploymentRestoreDriver, DeploymentStateConfig,
    DeploymentStateError, DeploymentStateStore, deployment_restore_plan,
};
pub use ingress_state::{
    ApacheIngressConfig, ApacheIngressDirection, ApacheIngressDriver,
    INGRESS_SNAPSHOT_SCHEMA_VERSION, IngressApplyDriver, IngressRestoreDriver, IngressStateConfig,
    IngressStateError, IngressStateStore, IngressSwitchConfig, IngressSwitchDirection,
    IngressSwitchDriver, apache_ingress_plan, ingress_apply_plan, ingress_restore_plan,
    ingress_switch_plan,
};
pub use nftables::{NftablesError, OriginFirewallPlan, VpsGuardNftables};
pub use operation::{
    IngressTopology, OperationBudgets, OperationContractError, OperationDriver,
    OperationEngineError, OperationIssue, OperationKind, OperationPhase, OperationPlan,
    OperationState, OperationStatus, PhaseReport, SnapshotResource, execute_operation,
};
pub use plan::{MutationPlan, PlanError, PlannedChange};
pub use secret::{SecretFileError, SecretFilePolicy, load_secret_file, resolve_credential_path};
pub use tls::{
    CertbotAssistedPlan, CertbotPlanError, CertbotPlanStep, CertificateInspection, TlsHealth,
    TlsManagementSnapshot, TlsOwnership, TlsRenewalState, build_certbot_assisted_plan,
    inspect_tls_management, resolve_tls_credential_path, validate_certificate,
};
