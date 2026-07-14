//! 정책 생성, 상태 저장, API, SSE와 수집 orchestration을 소유합니다.

/// 초기 control 프로세스가 agent library를 포함하는지 반환합니다.
#[must_use]
pub const fn embeds_agent() -> bool {
    guard_agent::EMBEDDED_IN_CONTROL
}
