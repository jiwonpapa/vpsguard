//! Nginx, PHP-FPM, MySQL과 Redis의 timeout 적용 read-only health probe입니다.

use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::{CollectorHealth, CollectorState};

/// service probe 대상입니다.
#[derive(Debug, Clone, Default)]
pub struct ServiceTargets {
    /// Nginx `stub_status` HTTP URL입니다.
    pub nginx_status_url: Option<String>,
    /// PHP-FPM status HTTP URL입니다.
    pub php_fpm_status_url: Option<String>,
    /// MySQL handshake 주소입니다.
    pub mysql_address: Option<SocketAddr>,
    /// Redis PING 주소입니다.
    pub redis_address: Option<SocketAddr>,
}

/// 개별 service probe 실패입니다.
#[derive(Debug, Error)]
enum ProbeError {
    #[error("지원하지 않는 HTTP status URL")]
    InvalidUrl,
    #[error("service timeout")]
    Timeout,
    #[error("service 연결 또는 응답 실패")]
    Io,
    #[error("service health 응답이 정상이 아님")]
    Unhealthy,
}

/// 구성된 모든 service를 독립 timeout으로 확인합니다.
pub async fn collect_services(
    targets: &ServiceTargets,
    timeout_duration: Duration,
) -> Vec<CollectorHealth> {
    let mut health = Vec::with_capacity(4);
    health.push(
        collect_optional_http(
            "nginx",
            targets.nginx_status_url.as_deref(),
            timeout_duration,
        )
        .await,
    );
    health.push(
        collect_optional_http(
            "php_fpm",
            targets.php_fpm_status_url.as_deref(),
            timeout_duration,
        )
        .await,
    );
    health
        .push(collect_optional_tcp("mysql", targets.mysql_address, timeout_duration, false).await);
    health.push(collect_optional_tcp("redis", targets.redis_address, timeout_duration, true).await);
    health
}

async fn collect_optional_http(
    name: &str,
    url: Option<&str>,
    timeout_duration: Duration,
) -> CollectorHealth {
    let Some(url) = url else {
        return unavailable(name);
    };
    match probe_http(url, timeout_duration).await {
        Ok(()) => live(name),
        Err(error) => failed(name, error),
    }
}

async fn collect_optional_tcp(
    name: &str,
    address: Option<SocketAddr>,
    timeout_duration: Duration,
    redis_ping: bool,
) -> CollectorHealth {
    let Some(address) = address else {
        return unavailable(name);
    };
    let result = if redis_ping {
        probe_redis(address, timeout_duration).await
    } else {
        probe_tcp(address, timeout_duration).await
    };
    match result {
        Ok(()) => live(name),
        Err(error) => failed(name, error),
    }
}

async fn probe_http(url: &str, timeout_duration: Duration) -> Result<(), ProbeError> {
    let (host, port, path) = parse_http_url(url)?;
    let future = async {
        let mut stream = TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|_| ProbeError::Io)?;
        let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|_| ProbeError::Io)?;
        let mut response = [0_u8; 256];
        let length = stream
            .read(&mut response)
            .await
            .map_err(|_| ProbeError::Io)?;
        let status = std::str::from_utf8(&response[..length]).map_err(|_| ProbeError::Io)?;
        if status.starts_with("HTTP/1.1 200") || status.starts_with("HTTP/1.0 200") {
            Ok(())
        } else {
            Err(ProbeError::Unhealthy)
        }
    };
    timeout(timeout_duration, future)
        .await
        .map_err(|_| ProbeError::Timeout)?
}

async fn probe_tcp(address: SocketAddr, timeout_duration: Duration) -> Result<(), ProbeError> {
    timeout(timeout_duration, TcpStream::connect(address))
        .await
        .map_err(|_| ProbeError::Timeout)?
        .map(|_| ())
        .map_err(|_| ProbeError::Io)
}

async fn probe_redis(address: SocketAddr, timeout_duration: Duration) -> Result<(), ProbeError> {
    let future = async {
        let mut stream = TcpStream::connect(address)
            .await
            .map_err(|_| ProbeError::Io)?;
        stream
            .write_all(b"*1\r\n$4\r\nPING\r\n")
            .await
            .map_err(|_| ProbeError::Io)?;
        let mut response = [0_u8; 16];
        let length = stream
            .read(&mut response)
            .await
            .map_err(|_| ProbeError::Io)?;
        if response[..length].starts_with(b"+PONG") {
            Ok(())
        } else {
            Err(ProbeError::Unhealthy)
        }
    };
    timeout(timeout_duration, future)
        .await
        .map_err(|_| ProbeError::Timeout)?
}

fn parse_http_url(url: &str) -> Result<(String, u16, String), ProbeError> {
    let without_scheme = url.strip_prefix("http://").ok_or(ProbeError::InvalidUrl)?;
    let (authority, path) = without_scheme
        .split_once('/')
        .map_or((without_scheme, "/"), |(authority, path)| (authority, path));
    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, 80), |(host, port)| {
            (host, port.parse::<u16>().unwrap_or_default())
        });
    if host.is_empty() || port == 0 {
        return Err(ProbeError::InvalidUrl);
    }
    Ok((host.to_owned(), port, format!("/{path}")))
}

fn live(name: &str) -> CollectorHealth {
    CollectorHealth {
        name: name.to_owned(),
        state: CollectorState::Live,
        last_success_at: OffsetDateTime::now_utc().format(&Rfc3339).ok(),
        error_code: None,
    }
}

fn unavailable(name: &str) -> CollectorHealth {
    CollectorHealth {
        name: name.to_owned(),
        state: CollectorState::Unavailable,
        last_success_at: None,
        error_code: None,
    }
}

fn failed(name: &str, error: ProbeError) -> CollectorHealth {
    CollectorHealth {
        name: name.to_owned(),
        state: CollectorState::Error,
        last_success_at: None,
        error_code: Some(
            match error {
                ProbeError::InvalidUrl => "INVALID_URL",
                ProbeError::Timeout => "TIMEOUT",
                ProbeError::Io => "CONNECT_FAILED",
                ProbeError::Unhealthy => "UNHEALTHY_RESPONSE",
            }
            .to_owned(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_http_url;

    #[test]
    fn parses_bounded_http_status_url() -> Result<(), Box<dyn std::error::Error>> {
        let parsed = parse_http_url("http://127.0.0.1:8080/status")?;
        assert_eq!(parsed, ("127.0.0.1".to_owned(), 8080, "/status".to_owned()));
        assert!(parse_http_url("https://example.com/status").is_err());
        Ok(())
    }
}
