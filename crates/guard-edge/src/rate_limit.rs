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
    /// client cardinality 대신 상위 aggregate fallback으로 허용했습니다.
    AllowFallback,
    /// 현재 window의 계층별 한도를 초과했습니다.
    Deny(LimitScope),
}

/// 요청을 거부한 limiter 계층입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitScope {
    /// client IP별 예산입니다.
    Client,
    /// IPv4 /24 또는 IPv6 /64 prefix별 예산입니다.
    Prefix,
    /// route class aggregate 예산입니다.
    Route,
    /// 전체 listener aggregate 예산입니다.
    Global,
}

/// 한 요청에 적용할 계층별 분당 예산입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitPolicy {
    /// client IP별 예산입니다.
    pub client_rpm: u32,
    /// network prefix별 예산입니다.
    pub prefix_rpm: u32,
    /// route class aggregate 예산입니다.
    pub route_rpm: u32,
    /// 전체 listener aggregate 예산입니다.
    pub global_rpm: u32,
}

impl RateLimitPolicy {
    /// client 예산과 설정 multiplier로 saturating aggregate 예산을 만듭니다.
    #[must_use]
    pub const fn from_multipliers(
        client_rpm: u32,
        prefix_multiplier: u32,
        route_multiplier: u32,
        global_multiplier: u32,
    ) -> Self {
        Self {
            client_rpm,
            prefix_rpm: client_rpm.saturating_mul(prefix_multiplier),
            route_rpm: client_rpm.saturating_mul(route_multiplier),
            global_rpm: client_rpm.saturating_mul(global_multiplier),
        }
    }
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

impl LimitWindow {
    fn consume(&mut self, minute_bucket: u64, limit: u32) -> bool {
        if self.minute_bucket != minute_bucket {
            self.minute_bucket = minute_bucket;
            self.request_count = 0;
        }
        if self.request_count >= limit {
            return false;
        }
        self.request_count = self.request_count.saturating_add(1);
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PrefixKey {
    V4(u32),
    V6(u64),
}

impl From<IpAddr> for PrefixKey {
    fn from(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(value) => Self::V4(u32::from(value) & 0xffff_ff00),
            IpAddr::V6(value) => Self::V6((u128::from(value) >> 64) as u64),
        }
    }
}

#[derive(Debug, Default)]
struct LimitState {
    last_cleanup_bucket: Option<u64>,
    windows: HashMap<LimitKey, LimitWindow>,
    prefixes: HashMap<PrefixKey, LimitWindow>,
    routes: HashMap<RouteClass, LimitWindow>,
    global: Option<LimitWindow>,
}

/// 명시적 cardinality 상한을 갖는 fixed-window limiter입니다.
#[derive(Debug)]
pub struct BoundedRateLimiter {
    max_entries: usize,
    max_prefixes: usize,
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
            max_prefixes: max_entries.div_ceil(4).max(1),
            state: Mutex::new(LimitState::default()),
        }
    }

    /// 현재 minute window의 client·route 요청을 판정합니다.
    #[must_use]
    pub fn check(
        &self,
        client_ip: IpAddr,
        route_class: RouteClass,
        policy: RateLimitPolicy,
        now: SystemTime,
    ) -> LimitDecision {
        let current_bucket = minute_bucket(now);
        let mut state = self.lock_state();
        if state.last_cleanup_bucket != Some(current_bucket) {
            state
                .windows
                .retain(|_, window| window.minute_bucket == current_bucket);
            state
                .prefixes
                .retain(|_, window| window.minute_bucket == current_bucket);
            state
                .routes
                .retain(|_, window| window.minute_bucket == current_bucket);
            if state
                .global
                .is_some_and(|window| window.minute_bucket != current_bucket)
            {
                state.global = None;
            }
            state.last_cleanup_bucket = Some(current_bucket);
        }

        let global = state.global.get_or_insert(LimitWindow {
            minute_bucket: current_bucket,
            request_count: 0,
        });
        if !global.consume(current_bucket, policy.global_rpm) {
            return LimitDecision::Deny(LimitScope::Global);
        }

        let route = state.routes.entry(route_class).or_insert(LimitWindow {
            minute_bucket: current_bucket,
            request_count: 0,
        });
        if !route.consume(current_bucket, policy.route_rpm) {
            return LimitDecision::Deny(LimitScope::Route);
        }

        let prefix_key = PrefixKey::from(client_ip);
        let prefix_tracked = state.prefixes.contains_key(&prefix_key);
        if prefix_tracked || state.prefixes.len() < self.max_prefixes {
            let prefix = state.prefixes.entry(prefix_key).or_insert(LimitWindow {
                minute_bucket: current_bucket,
                request_count: 0,
            });
            if !prefix.consume(current_bucket, policy.prefix_rpm) {
                return LimitDecision::Deny(LimitScope::Prefix);
            }
        }

        let key = LimitKey {
            client_ip,
            route_class,
        };
        if !state.windows.contains_key(&key) && state.windows.len() >= self.max_entries {
            return LimitDecision::AllowFallback;
        }

        let window = state.windows.entry(key).or_insert(LimitWindow {
            minute_bucket: current_bucket,
            request_count: 0,
        });
        if !window.consume(current_bucket, policy.client_rpm) {
            return LimitDecision::Deny(LimitScope::Client);
        }
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
