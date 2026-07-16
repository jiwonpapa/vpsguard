//! 요청 hot path에서 손실을 허용하는 non-blocking Unix datagram telemetry입니다.

use std::io::ErrorKind;
use std::net::IpAddr;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use guard_core::correlation::LOG_SCHEMA_VERSION;
use serde::{Deserialize, Serialize};

use crate::rate_limit::RouteClass;

const MAX_DATAGRAM_BYTES: usize = 4_096;

/// edge 요청 처리 판정입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    /// upstream 전달 요청입니다.
    Allow,
    /// 속도 제한 응답입니다.
    Throttle,
    /// 검증 응답입니다.
    Challenge,
    /// 거부 응답입니다.
    Deny,
}

/// query·header·body를 포함하지 않는 bounded 요청 aggregate 입력입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestTelemetry {
    /// telemetry schema 버전입니다.
    pub schema_version: u32,
    /// edge가 생성한 request ID입니다.
    pub request_id: String,
    /// HTTP method입니다.
    pub method: String,
    /// bounded route class입니다.
    pub route_class: RouteClass,
    /// profile이 cardinality를 제한한 route key입니다.
    pub normalized_route: String,
    /// profile의 상대 route 비용입니다.
    pub route_cost: u8,
    /// 최종 status입니다.
    pub status: u16,
    /// edge 전체 지연 microseconds입니다.
    pub latency_micros: u64,
    /// 검증된 client IP입니다.
    pub client_ip: Option<IpAddr>,
    /// edge에서 확인한 request body bytes입니다.
    pub request_body_bytes: u64,
    /// downstream으로 전달한 response body bytes입니다.
    pub response_body_bytes: u64,
    /// upstream connection 재사용 여부입니다.
    pub upstream_connection_reused: Option<bool>,
    /// 요청 처리 판정입니다.
    pub decision: DecisionKind,
    /// edge에 적용된 정책 버전입니다.
    pub policy_version: u64,
    /// 관측 발생 Unix epoch milliseconds입니다.
    pub occurred_at_unix_ms: u64,
}

/// 연결 실패·backpressure가 요청 실패로 전파되지 않는 telemetry sink입니다.
#[derive(Debug, Clone)]
pub struct TelemetrySink {
    inner: Arc<TelemetryInner>,
}

#[derive(Debug)]
struct TelemetryInner {
    path: PathBuf,
    socket: Mutex<Option<UnixDatagram>>,
    dropped: AtomicU64,
    emitted: AtomicU64,
    reconnected: AtomicU64,
    reconnect_interval: Duration,
}

impl TelemetrySink {
    /// receiver path에 non-blocking datagram을 연결합니다.
    ///
    /// socket 부재나 권한 오류는 disabled sink로 전환합니다.
    #[must_use]
    pub fn connect(path: &Path) -> Self {
        Self::connect_with_interval(path, Duration::from_secs(1))
    }

    fn connect_with_interval(path: &Path, reconnect_interval: Duration) -> Self {
        let inner = Arc::new(TelemetryInner {
            path: path.to_path_buf(),
            socket: Mutex::new(connect_socket(path)),
            dropped: AtomicU64::new(0),
            emitted: AtomicU64::new(0),
            reconnected: AtomicU64::new(0),
            reconnect_interval,
        });
        spawn_reconnector(&inner);
        Self { inner }
    }

    /// 요청을 blocking 없이 전송하며 실패는 drop counter로만 기록합니다.
    pub fn emit(&self, telemetry: &RequestTelemetry) {
        let Ok(payload) = serde_json::to_vec(telemetry) else {
            self.inner.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if payload.len() > MAX_DATAGRAM_BYTES {
            self.inner.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let Ok(mut socket_guard) = self.inner.socket.try_lock() else {
            self.inner.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let Some(socket) = socket_guard.as_ref() else {
            self.inner.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        match socket.send(&payload) {
            Ok(_) => {
                self.inner.emitted.fetch_add(1, Ordering::Relaxed);
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                self.inner.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(error) => {
                self.inner.dropped.fetch_add(1, Ordering::Relaxed);
                if matches!(
                    error.kind(),
                    ErrorKind::NotFound
                        | ErrorKind::ConnectionRefused
                        | ErrorKind::ConnectionReset
                        | ErrorKind::BrokenPipe
                ) {
                    *socket_guard = None;
                }
            }
        }
    }

    /// 손실 datagram 수입니다.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.inner.dropped.load(Ordering::Relaxed)
    }

    /// 성공 전송 datagram 수입니다.
    #[must_use]
    pub fn emitted(&self) -> u64 {
        self.inner.emitted.load(Ordering::Relaxed)
    }

    /// receiver 재생성 뒤 연결을 복구한 횟수입니다.
    #[must_use]
    pub fn reconnected(&self) -> u64 {
        self.inner.reconnected.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn from_socket(socket: UnixDatagram) -> Self {
        let _nonblocking_result = socket.set_nonblocking(true);
        Self {
            inner: Arc::new(TelemetryInner {
                path: PathBuf::new(),
                socket: Mutex::new(Some(socket)),
                dropped: AtomicU64::new(0),
                emitted: AtomicU64::new(0),
                reconnected: AtomicU64::new(0),
                reconnect_interval: Duration::from_secs(1),
            }),
        }
    }
}

fn connect_socket(path: &Path) -> Option<UnixDatagram> {
    UnixDatagram::unbound().ok().and_then(|socket| {
        if socket.set_nonblocking(true).is_err() || socket.connect(path).is_err() {
            None
        } else {
            Some(socket)
        }
    })
}

fn spawn_reconnector(inner: &Arc<TelemetryInner>) {
    let weak = Arc::downgrade(inner);
    let spawn_result = std::thread::Builder::new()
        .name("vps-guard-telemetry-reconnect".to_owned())
        .spawn(move || {
            loop {
                let Some(inner) = weak.upgrade() else {
                    return;
                };
                std::thread::sleep(inner.reconnect_interval);
                let Ok(mut socket_guard) = inner.socket.try_lock() else {
                    continue;
                };
                if socket_guard.is_none()
                    && let Some(socket) = connect_socket(&inner.path)
                {
                    *socket_guard = Some(socket);
                    inner.reconnected.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    if let Err(error) = spawn_result {
        tracing::warn!(
            log_schema_version = LOG_SCHEMA_VERSION,
            component = "guard-edge",
            error_code = "EDGE_TELEMETRY_RECONNECT_THREAD_UNAVAILABLE",
            error = %error,
            "telemetry reconnect thread unavailable"
        );
    }
}

#[cfg(test)]
#[path = "telemetry/tests.rs"]
mod tests;
