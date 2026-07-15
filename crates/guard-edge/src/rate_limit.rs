//! Bounded client·route fixed-window rate limiter입니다.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// limiter가 분리해 추적하는 route class입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteClass {
    /// 일반 공개 요청입니다.
    General,
    /// 검색·로그인 같은 고비용 요청입니다.
    Strict,
    /// 업로드 요청입니다.
    Upload,
    /// app profile이 식별한 인증 시도입니다.
    Authentication,
    /// 애플리케이션 traffic과 counter를 공유하지 않는 관리 로그인입니다.
    ManagementAuth,
}

impl RouteClass {
    /// 정책과 telemetry에 사용하는 안정적인 문자열입니다.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::General => "general",
            Self::Strict => "strict",
            Self::Upload => "upload",
            Self::Authentication => "authentication",
            Self::ManagementAuth => "management_auth",
        }
    }
}

/// 한 요청에 대한 limiter 판정입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitDecision {
    /// 한도 안이므로 허용합니다.
    Allow,
    /// 현재 window 한도를 초과했습니다.
    Deny,
    /// cardinality 상한에 도달해 새 client를 추적하지 못했습니다.
    CapacityReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct LimitKey {
    client_ip: IpAddr,
    route_class: RouteClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LimitWindow {
    minute_bucket: u64,
    request_count: u32,
}

#[derive(Debug, Default)]
struct LimitState {
    last_cleanup_bucket: Option<u64>,
    windows: HashMap<LimitKey, LimitWindow>,
}

/// 명시적 cardinality 상한을 갖는 fixed-window limiter입니다.
#[derive(Debug)]
pub struct BoundedRateLimiter {
    max_entries: usize,
    state: Mutex<LimitState>,
}

impl BoundedRateLimiter {
    /// 최대 추적 key 수를 고정해 limiter를 생성합니다.
    ///
    /// `max_entries`가 0이면 모든 새 key에 `CapacityReached`를 반환합니다.
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries,
            state: Mutex::new(LimitState::default()),
        }
    }

    /// 현재 minute window의 client·route 요청을 판정합니다.
    #[must_use]
    pub fn check(
        &self,
        client_ip: IpAddr,
        route_class: RouteClass,
        limit: u32,
        now: SystemTime,
    ) -> LimitDecision {
        let current_bucket = minute_bucket(now);
        let mut state = self.lock_state();
        if state.last_cleanup_bucket != Some(current_bucket) {
            state
                .windows
                .retain(|_, window| window.minute_bucket == current_bucket);
            state.last_cleanup_bucket = Some(current_bucket);
        }

        let key = LimitKey {
            client_ip,
            route_class,
        };
        if !state.windows.contains_key(&key) && state.windows.len() >= self.max_entries {
            return LimitDecision::CapacityReached;
        }

        let window = state.windows.entry(key).or_insert(LimitWindow {
            minute_bucket: current_bucket,
            request_count: 0,
        });
        if window.request_count >= limit {
            return LimitDecision::Deny;
        }
        window.request_count = window.request_count.saturating_add(1);
        LimitDecision::Allow
    }

    fn lock_state(&self) -> MutexGuard<'_, LimitState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(test)]
    fn tracked_entries(&self) -> usize {
        self.lock_state().windows.len()
    }
}

fn minute_bucket(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() / 60
}

#[cfg(test)]
#[path = "rate_limit/tests.rs"]
mod tests;
