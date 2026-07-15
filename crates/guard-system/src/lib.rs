//! nftables, systemd, TLS 파일, Nginx와 원자 파일 작업 adapter를 소유합니다.
//!
//! 외부 명령은 검증된 argv와 공통 command runner를 통해서만 실행합니다.

pub mod atomic_store;
pub mod command;
pub mod nftables;
pub mod plan;
pub mod tls;

pub use atomic_store::{AtomicJsonStore, StoreError};
pub use command::{CommandAudit, CommandError, CommandOutput, OwnedProgram, SystemCommandRunner};
pub use nftables::{NftablesError, OriginFirewallPlan, VpsGuardNftables};
pub use plan::{MutationPlan, PlanError, PlannedChange};
pub use tls::{
    CertbotAssistedPlan, CertbotPlanError, CertbotPlanStep, CertificateInspection, TlsHealth,
    TlsManagementSnapshot, TlsOwnership, TlsRenewalState, build_certbot_assisted_plan,
    inspect_tls_management, resolve_tls_credential_path, validate_certificate,
};
