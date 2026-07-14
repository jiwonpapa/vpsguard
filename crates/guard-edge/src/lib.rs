//! Pingora 데이터 플레인과 요청 hot path 정책을 소유합니다.
//!
//! 요청 처리 중 동기 IPC, 데이터베이스, 디스크 쓰기와 외부 API 호출을 금지합니다.

/// 현재 연결된 core 계약 버전을 반환합니다.
#[must_use]
pub const fn contract_version() -> u32 {
    guard_core::CONTRACT_VERSION
}
