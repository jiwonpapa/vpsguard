//! nftables, systemd, TLS 파일, Nginx와 원자 파일 작업 adapter를 소유합니다.
//!
//! 외부 명령은 검증된 argv와 공통 command runner를 통해서만 실행합니다.

pub mod atomic_store;
pub mod plan;

pub use atomic_store::{AtomicJsonStore, StoreError};
pub use plan::{MutationPlan, PlanError, PlannedChange};
