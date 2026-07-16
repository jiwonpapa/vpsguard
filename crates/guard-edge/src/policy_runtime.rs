//! 검증된 마지막 정상 정책을 lock-free 읽기로 edge hot path에 제공합니다.

use std::fs;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use guard_core::correlation::LOG_SCHEMA_VERSION;
use guard_core::{Decision, PolicyError, PolicySnapshot};
use thiserror::Error;
use time::OffsetDateTime;
use tracing::{info, warn};

/// 정책 파일 reload 실패입니다. 실패해도 마지막 정상 정책은 유지됩니다.
#[derive(Debug, Error)]
pub enum PolicyReloadError {
    /// 정책 파일 읽기 실패입니다.
    #[error("정책 파일 읽기 실패: {0}")]
    Read(#[from] std::io::Error),
    /// JSON 계약 실패입니다.
    #[error("정책 JSON 해석 실패: {0}")]
    Json(#[from] serde_json::Error),
    /// schema, hash, TTL 검증 실패입니다.
    #[error(transparent)]
    Policy(#[from] PolicyError),
}

/// 요청에 적용할 동적 정책 결과입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeDecision {
    /// client TTL 규칙 판정입니다.
    pub action: Option<Decision>,
    /// route별 분당 한도입니다.
    pub requests_per_minute: Option<u32>,
    /// 적용 정책 버전입니다.
    pub policy_version: u64,
}

/// 원자 교체되는 정책 snapshot 소유자입니다.
#[derive(Debug)]
pub struct PolicyRuntime {
    path: PathBuf,
    current: ArcSwapOption<PolicySnapshot>,
    version: AtomicU64,
}

impl PolicyRuntime {
    /// 비어 있는 runtime을 생성합니다.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            current: ArcSwapOption::empty(),
            version: AtomicU64::new(0),
        }
    }

    /// 현재 적용된 정책 버전입니다.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// 파일을 검증한 뒤 기존보다 새 버전일 때만 원자 교체합니다.
    ///
    /// # Errors
    ///
    /// 파일, JSON, schema, hash 또는 TTL 검증 실패를 반환합니다.
    pub fn reload_at(&self, now: OffsetDateTime) -> Result<bool, PolicyReloadError> {
        let source = match fs::read_to_string(&self.path) {
            Ok(source) => source,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        let policy: PolicySnapshot = serde_json::from_str(&source)?;
        policy.validate_at(now)?;
        let current_version = self.version();
        if policy.policy_version <= current_version {
            return Ok(false);
        }
        let new_version = policy.policy_version;
        self.current.store(Some(Arc::new(policy)));
        self.version.store(new_version, Ordering::Release);
        Ok(true)
    }

    /// 현재 정책에서 client·route 판정을 계산합니다.
    #[must_use]
    pub fn decision_at(
        &self,
        client_ip: Option<IpAddr>,
        route_class: &str,
        now: OffsetDateTime,
    ) -> RuntimeDecision {
        let Some(policy) = self.current.load_full() else {
            return inactive_decision(0);
        };
        let snapshot_expires = OffsetDateTime::parse(
            &policy.expires_at,
            &time::format_description::well_known::Rfc3339,
        );
        if snapshot_expires.is_err() || snapshot_expires.is_ok_and(|expires| expires <= now) {
            return inactive_decision(policy.policy_version);
        }
        let action = client_ip.and_then(|ip| {
            policy.client_rules.iter().find_map(|rule| {
                if rule.client_ip != ip {
                    return None;
                }
                let expires = OffsetDateTime::parse(
                    &rule.expires_at,
                    &time::format_description::well_known::Rfc3339,
                )
                .ok()?;
                (expires > now).then_some(rule.action)
            })
        });
        let requests_per_minute = policy
            .route_rules
            .iter()
            .find(|rule| rule.route_class == route_class)
            .map(|rule| rule.requests_per_minute)
            .filter(|limit| *limit > 0);
        RuntimeDecision {
            action,
            requests_per_minute,
            policy_version: policy.policy_version,
        }
    }

    /// 백그라운드 reload thread를 시작합니다.
    pub fn spawn(self: &Arc<Self>, interval: Duration) {
        let runtime = Arc::clone(self);
        let spawn_result = std::thread::Builder::new()
            .name("vps-guard-policy-reload".to_owned())
            .spawn(move || {
                loop {
                    match runtime.reload_at(OffsetDateTime::now_utc()) {
                        Ok(true) => info!(
                            log_schema_version = LOG_SCHEMA_VERSION,
                            component = "guard-edge",
                            event_code = "EDGE_POLICY_RELOADED",
                            policy_version = runtime.version(),
                            "policy reloaded"
                        ),
                        Ok(false) => {}
                        Err(error) => {
                            warn!(
                                log_schema_version = LOG_SCHEMA_VERSION,
                                component = "guard-edge",
                                error_code = "EDGE_POLICY_RELOAD_REJECTED",
                                error = %error,
                                "policy reload rejected; keeping last-known-good"
                            )
                        }
                    }
                    std::thread::sleep(interval);
                }
            });
        if let Err(error) = spawn_result {
            warn!(
                log_schema_version = LOG_SCHEMA_VERSION,
                component = "guard-edge",
                error_code = "EDGE_POLICY_RELOAD_THREAD_UNAVAILABLE",
                error = %error,
                "policy reload thread unavailable"
            );
        }
    }

    /// 정책 파일 경로입니다.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn inactive_decision(policy_version: u64) -> RuntimeDecision {
    RuntimeDecision {
        action: None,
        requests_per_minute: None,
        policy_version,
    }
}

#[cfg(test)]
#[path = "policy_runtime/tests.rs"]
mod tests;
