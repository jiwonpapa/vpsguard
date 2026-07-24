//! Pingora 데이터 플레인과 요청 hot path 정책을 소유합니다.
//!
//! 요청 처리 중 동기 IPC, 데이터베이스, 디스크 쓰기와 외부 API 호출을 금지합니다.

mod challenge;
mod context;
pub mod policy;
mod policy_runtime;
mod proxy;
pub mod rate_limit;
mod response;
mod runtime;
mod security;
mod startup;
pub mod supervisor;
pub mod telemetry;
pub mod tls;

pub use startup::{EdgeStartupError, EdgeWorkerOptions, run_from_path, run_worker_from_path};
pub use supervisor::{EdgeSupervisorError, run_supervisor};

/// 현재 연결된 core 계약 버전을 반환합니다.
#[must_use]
pub const fn contract_version() -> u32 {
    guard_core::CONTRACT_VERSION
}
