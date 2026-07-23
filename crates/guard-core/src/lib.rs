//! VPSGuard의 상태, 정책, 설정과 오류 계약을 소유합니다.
//!
//! 이 크레이트에는 네트워크, 파일 시스템, 데이터베이스 또는 외부 명령 부작용을
//! 넣지 않습니다.

pub mod admin;
pub mod config;
pub mod correlation;
pub mod crawler;
pub mod detection;
pub mod event;
pub mod policy;
pub mod state;

pub use config::{ConfigError, GuardConfig};
pub use crawler::{
    BotClass, BotReason, CrawlerNetwork, CrawlerProvider, CrawlerVerification,
    CrawlerVerificationInput, DeclaredBotDisposition, UserAgentFamily, VerificationMethod,
    VerificationReason, declared_bot_disposition, user_agent_family, verify_crawler,
};
pub use detection::{Assessment, Decision, DetectionInput, Detector, HostPressure, ReasonCode};
pub use event::{GuardEvent, Severity};
pub use policy::{PolicyError, PolicySnapshot};
pub use state::{GuardMode, GuardState, StateError, TransitionInput};

/// 현재 workspace 계약 버전입니다.
pub const CONTRACT_VERSION: u32 = 1;
pub use admin::{
    ADMIN_PROTOCOL_VERSION, AdminCommand, AdminErrorCode, AdminRequest, AdminResponse,
};
