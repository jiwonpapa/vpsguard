//! nftables, systemd, TLS 파일, Nginx와 원자 파일 작업 adapter를 소유합니다.
//!
//! 외부 명령은 검증된 argv와 공통 command runner를 통해서만 실행합니다.

pub mod atomic_store;
pub mod command;
pub mod deployment_state;
pub mod ingress_state;
mod listener;
pub mod nftables;
pub mod operation;
pub mod plan;
pub mod secret;
pub mod site_setup;
pub mod tls;
pub mod ufw;

pub use atomic_store::{AtomicJsonStore, StoreError};
pub use command::{CommandAudit, CommandError, CommandOutput, OwnedProgram, SystemCommandRunner};
pub use deployment_state::{
    DEPLOYMENT_SNAPSHOT_SCHEMA_VERSION, DeploymentRestoreDriver, DeploymentStateConfig,
    DeploymentStateError, DeploymentStateStore, UninstallReleaseSnapshot, UninstallReleaseStore,
    deployment_restore_plan,
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
pub use site_setup::{
    ApacheSiteCandidates, NginxSiteCandidates, PhpRuntime, SITE_SETUP_SCHEMA_VERSION,
    SetupCompatibility, SetupIssue, SetupIssueCode, SetupPlanStep, SiteSetupError,
    SiteSetupManifest, SiteSetupReport, WebServerKind, build_apache_site_candidates,
    build_nginx_site_candidates, inspect_site_setup, remove_apache_candidate_stage,
    remove_nginx_candidate_stage, write_apache_candidate_stage, write_nginx_candidate_stage,
};
pub use tls::{
    CertbotAssistedPlan, CertbotPlanError, CertbotPlanStep, CertificateInspection,
    ServedCertificateProbeError, ServedCertificateReport, ServedCertificateState, TlsHealth,
    TlsManagementSnapshot, TlsOwnership, TlsReloadBundle, TlsReloadStageError, TlsRenewalState,
    VPS_GUARD_TLS_RELOAD_CERTIFICATE, VPS_GUARD_TLS_RELOAD_DIRECTORY, VPS_GUARD_TLS_RELOAD_KEY,
    build_certbot_assisted_plan, inspect_served_certificate, inspect_tls_management,
    resolve_tls_credential_path, stage_tls_reload_bundle, validate_certificate,
};
pub use ufw::{
    SystemUfwExecutor, UfwAction, UfwController, UfwError, UfwExecutor, UfwMutation,
    UfwObservedRule, UfwPlan, UfwProtocol, UfwRule, UfwSnapshot, validate_ufw_add_arguments,
};
