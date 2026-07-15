//! OS, Nginx, PHP-FPM, MySQL과 Redis의 읽기 전용 collector 계약을 소유합니다.
//!
//! MVP에서는 별도 daemon이 아니라 `guard-control` 프로세스에 library로 포함됩니다.

/// MVP agent가 control 프로세스에 포함되는 계약입니다.
pub const EMBEDDED_IN_CONTROL: bool = true;

pub mod cgroup;
pub mod os;
pub mod services;

use serde::{Deserialize, Serialize};

/// collector의 최신성·가용 상태입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorState {
    /// 최신 값입니다.
    Live,
    /// 예상 수집 주기를 넘겼습니다.
    Delayed,
    /// 판단에 사용할 수 없습니다.
    Stale,
    /// 대상 서비스가 설정되지 않았습니다.
    Unavailable,
    /// 수집에 실패했습니다.
    Error,
}

/// 개별 서비스 collector의 최소 health입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorHealth {
    /// collector 이름입니다.
    pub name: String,
    /// 현재 상태입니다.
    pub state: CollectorState,
    /// 마지막 정상 수집 시각입니다.
    pub last_success_at: Option<String>,
    /// 비밀값을 포함하지 않는 오류 코드입니다.
    pub error_code: Option<String>,
    /// allowlist된 systemd unit입니다. legacy probe면 없습니다.
    #[serde(default)]
    pub unit: Option<String>,
    /// 마지막 수집 시각입니다.
    #[serde(default)]
    pub collected_at_unix_ms: Option<u64>,
    /// cgroup v2 resource 상태입니다.
    #[serde(default)]
    pub resource_state: Option<CollectorState>,
    /// semantic metric 상태입니다.
    #[serde(default)]
    pub semantic_state: Option<CollectorState>,
    /// cgroup 오류 코드입니다.
    #[serde(default)]
    pub resource_error_code: Option<String>,
    /// semantic probe 오류 코드입니다.
    #[serde(default)]
    pub semantic_error_code: Option<String>,
    /// allowlist된 unit의 cgroup v2 snapshot입니다.
    #[serde(default)]
    pub resources: Option<cgroup::CgroupSnapshot>,
    /// service 종류별 병목 snapshot입니다.
    #[serde(default)]
    pub semantic: Option<services::ServiceSemanticSnapshot>,
}
