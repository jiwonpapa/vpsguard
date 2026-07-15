//! allowlist된 Nginx·Apache·PHP-FPM·MySQL·Redis의 bounded semantic probe입니다.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use guard_system::{SecretFilePolicy, load_secret_file};
use mysql_async::prelude::Queryable;
use reqwest::{Client, StatusCode, redirect::Policy};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::cgroup::{self, CgroupError};
use crate::{CollectorHealth, CollectorState};

const MAX_SEMANTIC_BODY_BYTES: usize = 64 * 1_024;
const SECRET_CONNECTION_URL_POLICY: SecretFilePolicy = SecretFilePolicy {
    min_bytes: 8,
    max_bytes: 2_048,
};

/// 한 allowlist service의 semantic probe 종류입니다.
#[derive(Debug, Clone)]
pub enum ServiceProbe {
    /// Nginx `stub_status` URL입니다.
    Nginx {
        /// 인증 정보가 없는 loopback status URL입니다.
        status_url: String,
    },
    /// Apache `mod_status?auto` URL입니다.
    Apache {
        /// 인증 정보가 없는 loopback status URL입니다.
        status_url: String,
    },
    /// PHP-FPM status text URL입니다.
    PhpFpm {
        /// 인증 정보가 없는 loopback status URL입니다.
        status_url: String,
    },
    /// MySQL connection URL credential 파일입니다.
    Mysql {
        /// MySQL URL을 담은 root-only credential 파일입니다.
        credential_file: PathBuf,
    },
    /// 인증 없는 loopback Redis 주소입니다.
    RedisAddress {
        /// 인증 없는 loopback Redis 주소입니다.
        address: SocketAddr,
    },
    /// Redis connection URL credential 파일입니다.
    RedisCredential {
        /// Redis URL을 담은 root-only credential 파일입니다.
        credential_file: PathBuf,
    },
    /// 구버전 설정의 TCP 생존 확인입니다. 새 MySQL 설정에는 사용하지 않습니다.
    TcpHealth {
        /// loopback service 주소입니다.
        address: SocketAddr,
    },
}

/// 관리자 allowlist에서 변환한 단일 service 대상입니다.
#[derive(Debug, Clone)]
pub struct ServiceTarget {
    /// API와 UI의 안정 식별자입니다.
    pub name: String,
    /// allowlist된 systemd unit입니다. legacy probe에는 없습니다.
    pub unit: Option<String>,
    /// cgroup root 아래 상대 경로입니다. legacy probe에는 없습니다.
    pub cgroup_path: Option<PathBuf>,
    /// service별 semantic probe입니다.
    pub probe: ServiceProbe,
}

/// 독립 timeout과 공유 HTTP client를 포함한 service collector 대상입니다.
#[derive(Debug, Clone)]
pub struct ServiceTargets {
    cgroup_root: PathBuf,
    services: Vec<ServiceTarget>,
    timeout: Duration,
    http_client: Client,
}

/// collector client 생성 실패입니다.
#[derive(Debug, Error)]
pub enum ServiceTargetsError {
    /// redirect와 proxy를 끈 bounded HTTP client 생성 실패입니다.
    #[error("service collector HTTP client 생성 실패")]
    HttpClient,
    /// service target 개수가 제품 상한을 넘었습니다.
    #[error("service collector target 상한 초과")]
    TooManyTargets,
}

impl ServiceTargets {
    /// 최대 16개 target과 공유 bounded HTTP client를 만듭니다.
    ///
    /// # Errors
    ///
    /// target 상한 또는 HTTP client 생성 실패를 반환합니다.
    pub fn new(
        cgroup_root: PathBuf,
        services: Vec<ServiceTarget>,
        timeout: Duration,
    ) -> Result<Self, ServiceTargetsError> {
        if services.len() > 16 {
            return Err(ServiceTargetsError::TooManyTargets);
        }
        let http_client = Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            .redirect(Policy::none())
            .no_proxy()
            .user_agent("VPSGuard/0.1 service-collector")
            .build()
            .map_err(|_| ServiceTargetsError::HttpClient)?;
        Ok(Self {
            cgroup_root,
            services,
            timeout,
            http_client,
        })
    }
}

/// service별 병목 semantic snapshot입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServiceSemanticSnapshot {
    /// 구버전 TCP 생존 probe가 연결에 성공했습니다.
    TcpHealth,
    /// Nginx `stub_status` 값입니다.
    Nginx {
        /// 현재 open client connection 수입니다.
        active_connections: u64,
        /// 누적 accepted connection 수입니다.
        accepts: u64,
        /// 누적 handled connection 수입니다.
        handled: u64,
        /// 누적 HTTP request 수입니다.
        requests: u64,
        /// request header를 읽는 connection 수입니다.
        reading: u64,
        /// 응답을 쓰는 connection 수입니다.
        writing: u64,
        /// keep-alive 대기 connection 수입니다.
        waiting: u64,
    },
    /// Apache `mod_status?auto` 값입니다.
    Apache {
        /// 누적 access 수입니다.
        total_accesses: u64,
        /// 누적 전송 KiB입니다.
        total_kbytes: u64,
        /// 요청을 처리 중인 worker 수입니다.
        busy_workers: u64,
        /// 대기 worker 수입니다.
        idle_workers: u64,
    },
    /// PHP-FPM pool·queue·child 값입니다.
    PhpFpm {
        /// 누적 accepted connection 수입니다.
        accepted_connections: u64,
        /// 현재 listen queue 길이입니다.
        listen_queue: u64,
        /// 관측된 최대 listen queue 길이입니다.
        max_listen_queue: u64,
        /// socket listen queue 용량입니다.
        listen_queue_length: u64,
        /// idle child process 수입니다.
        idle_processes: u64,
        /// active child process 수입니다.
        active_processes: u64,
        /// 전체 child process 수입니다.
        total_processes: u64,
        /// 관측된 최대 active process 수입니다.
        max_active_processes: u64,
        /// `pm.max_children` 도달 누계입니다.
        max_children_reached: u64,
        /// slow request 누계입니다.
        slow_requests: u64,
    },
    /// MySQL/MariaDB global status 값입니다.
    Mysql {
        /// 설정된 최대 connection 수입니다.
        max_connections: u64,
        /// 현재 연결 client 수입니다.
        threads_connected: u64,
        /// 현재 실행 중 thread 수입니다.
        threads_running: u64,
        /// slow query 누계입니다.
        slow_queries: u64,
        /// 현재 InnoDB row lock wait 수입니다.
        innodb_row_lock_current_waits: u64,
        /// 누적 connection 수입니다.
        total_connections: u64,
        /// 인증·연결 실패 누계입니다.
        aborted_connects: u64,
    },
    /// Redis INFO 값입니다.
    Redis {
        /// Redis allocator가 보고한 현재 memory bytes입니다.
        used_memory_bytes: u64,
        /// 현재 연결 client 수입니다.
        connected_clients: u64,
        /// blocking command 대기 client 수입니다.
        blocked_clients: u64,
        /// keyspace hit 누계입니다.
        keyspace_hits: u64,
        /// keyspace miss 누계입니다.
        keyspace_misses: u64,
        /// eviction 누계입니다.
        evicted_keys: u64,
    },
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
enum ProbeError {
    #[error("target URL invalid")]
    InvalidUrl,
    #[error("service timeout")]
    Timeout,
    #[error("service connect failed")]
    Connect,
    #[error("service authentication failed")]
    Authentication,
    #[error("service permission denied")]
    Permission,
    #[error("service response unhealthy")]
    Unhealthy,
    #[error("service response invalid")]
    InvalidResponse,
    #[error("credential file invalid")]
    Credential,
}

impl ProbeError {
    const fn code(self) -> &'static str {
        match self {
            Self::InvalidUrl => "TARGET_URL_INVALID",
            Self::Timeout => "TIMEOUT",
            Self::Connect => "CONNECT_FAILED",
            Self::Authentication => "AUTHENTICATION_FAILED",
            Self::Permission => "PERMISSION_DENIED",
            Self::Unhealthy => "UNHEALTHY_RESPONSE",
            Self::InvalidResponse => "INVALID_RESPONSE",
            Self::Credential => "CREDENTIAL_INVALID",
        }
    }
}

/// 구성된 service를 동시에 수집하되 각 probe의 timeout을 독립 적용합니다.
pub async fn collect_services(targets: &ServiceTargets) -> Vec<CollectorHealth> {
    let mut tasks = JoinSet::new();
    for target in targets.services.iter().cloned() {
        let root = targets.cgroup_root.clone();
        let client = targets.http_client.clone();
        let timeout_duration = targets.timeout;
        tasks.spawn(async move { collect_service(root, target, client, timeout_duration).await });
    }
    let mut health = Vec::with_capacity(targets.services.len());
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(snapshot) => health.push(snapshot),
            Err(_join_error) => health.push(failed_task()),
        }
    }
    health.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    health
}

/// 직전 성공값을 stale로 명시해 유지하고 CPU delta를 계산합니다.
pub fn merge_service_history(
    previous: &[CollectorHealth],
    current: &mut [CollectorHealth],
    now_unix_ms: u64,
    stale_after: Duration,
) {
    let previous = previous
        .iter()
        .map(|snapshot| (snapshot.name.as_str(), snapshot))
        .collect::<HashMap<_, _>>();
    for snapshot in current {
        let Some(old) = previous.get(snapshot.name.as_str()).copied() else {
            continue;
        };
        if let (Some(old_resource), Some(resource)) = (&old.resources, &mut snapshot.resources) {
            let elapsed_ms = resource
                .collected_at_unix_ms
                .saturating_sub(old_resource.collected_at_unix_ms);
            if elapsed_ms > 0 {
                let delta_usec = resource
                    .cpu_usage_usec
                    .saturating_sub(old_resource.cpu_usage_usec);
                resource.cpu_usage_milli_percent =
                    Some(delta_usec.saturating_mul(100).saturating_div(elapsed_ms));
            }
        }
        if snapshot.state == CollectorState::Live {
            continue;
        }
        if snapshot.resources.is_none() {
            snapshot.resources.clone_from(&old.resources);
        }
        if snapshot.semantic.is_none() {
            snapshot.semantic.clone_from(&old.semantic);
        }
        snapshot.last_success_at.clone_from(&old.last_success_at);
        let age_ms = old
            .collected_at_unix_ms
            .map_or(u64::MAX, |collected| now_unix_ms.saturating_sub(collected));
        snapshot.state = if age_ms >= duration_millis(stale_after) {
            CollectorState::Stale
        } else {
            CollectorState::Delayed
        };
        snapshot.collected_at_unix_ms = old.collected_at_unix_ms;
    }
}

async fn collect_service(
    cgroup_root: PathBuf,
    target: ServiceTarget,
    client: Client,
    timeout_duration: Duration,
) -> CollectorHealth {
    let collected_at_unix_ms = unix_millis();
    let cgroup_path = target.cgroup_path.clone();
    let resource_task = tokio::task::spawn_blocking(move || {
        cgroup_path.map_or(Ok(None), |path| {
            cgroup::collect(&cgroup_root, &path, collected_at_unix_ms).map(Some)
        })
    });
    let semantic_result = timeout(timeout_duration, collect_semantic(&client, &target.probe))
        .await
        .map_err(|_| ProbeError::Timeout)
        .and_then(std::convert::identity);
    let resource_result = match resource_task.await {
        Ok(result) => result,
        Err(_join_error) => Err(CgroupError::Unavailable),
    };
    let configured_resource = target.cgroup_path.is_some();
    let resource_state = if !configured_resource {
        None
    } else if resource_result.is_ok() {
        Some(CollectorState::Live)
    } else {
        Some(CollectorState::Error)
    };
    let semantic_state = Some(if semantic_result.is_ok() {
        CollectorState::Live
    } else {
        CollectorState::Error
    });
    let resources = resource_result.as_ref().ok().and_then(Clone::clone);
    let semantic = semantic_result.as_ref().ok().cloned();
    let resource_error_code = resource_result.err().map(|error| error.code().to_owned());
    let semantic_error_code = semantic_result.err().map(|error| error.code().to_owned());
    let state = if resource_state.is_none() && semantic_state == Some(CollectorState::Live)
        || resource_state == Some(CollectorState::Live)
            && semantic_state == Some(CollectorState::Live)
    {
        CollectorState::Live
    } else {
        CollectorState::Error
    };
    let error_code = resource_error_code
        .as_deref()
        .or(semantic_error_code.as_deref())
        .map(ToOwned::to_owned);
    CollectorHealth {
        name: target.name,
        state,
        last_success_at: (state == CollectorState::Live).then(current_timestamp),
        error_code,
        unit: target.unit,
        collected_at_unix_ms: Some(collected_at_unix_ms),
        resource_state,
        semantic_state,
        resource_error_code,
        semantic_error_code,
        resources,
        semantic,
    }
}

async fn collect_semantic(
    client: &Client,
    probe: &ServiceProbe,
) -> Result<ServiceSemanticSnapshot, ProbeError> {
    match probe {
        ServiceProbe::Nginx { status_url } => {
            parse_nginx_status(&fetch_http(client, status_url).await?)
        }
        ServiceProbe::Apache { status_url } => {
            parse_apache_status(&fetch_http(client, status_url).await?)
        }
        ServiceProbe::PhpFpm { status_url } => {
            parse_php_fpm_status(&fetch_http(client, status_url).await?)
        }
        ServiceProbe::Mysql { credential_file } => probe_mysql(credential_file).await,
        ServiceProbe::RedisAddress { address } => probe_redis(&format!("redis://{address}/")).await,
        ServiceProbe::RedisCredential { credential_file } => {
            let connection_url = load_secret_file(credential_file, SECRET_CONNECTION_URL_POLICY)
                .map_err(|_| ProbeError::Credential)?;
            probe_redis(connection_url.expose_secret()).await
        }
        ServiceProbe::TcpHealth { address } => {
            TcpStream::connect(address)
                .await
                .map_err(|_| ProbeError::Connect)?;
            Ok(ServiceSemanticSnapshot::TcpHealth)
        }
    }
}

async fn fetch_http(client: &Client, value: &str) -> Result<String, ProbeError> {
    validate_loopback_url(value, "http")?;
    let mut response = client
        .get(value)
        .send()
        .await
        .map_err(|_| ProbeError::Connect)?;
    match response.status() {
        StatusCode::OK => {}
        StatusCode::UNAUTHORIZED => return Err(ProbeError::Authentication),
        StatusCode::FORBIDDEN => return Err(ProbeError::Permission),
        _ => return Err(ProbeError::Unhealthy),
    }
    let mut bytes = Vec::with_capacity(1_024);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| ProbeError::InvalidResponse)?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_SEMANTIC_BODY_BYTES {
            return Err(ProbeError::InvalidResponse);
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).map_err(|_| ProbeError::InvalidResponse)
}

async fn probe_mysql(credential_file: &Path) -> Result<ServiceSemanticSnapshot, ProbeError> {
    let connection_url = load_secret_file(credential_file, SECRET_CONNECTION_URL_POLICY)
        .map_err(|_| ProbeError::Credential)?;
    validate_loopback_url(connection_url.expose_secret(), "mysql")?;
    let options = mysql_async::Opts::from_url(connection_url.expose_secret())
        .map_err(|_| ProbeError::InvalidUrl)?;
    let mut connection = mysql_async::Conn::new(options)
        .await
        .map_err(classify_mysql_error)?;
    let rows = connection
        .query::<(String, String), _>(
            "SHOW GLOBAL STATUS WHERE Variable_name IN (
                'Threads_connected', 'Threads_running', 'Slow_queries',
                'Innodb_row_lock_current_waits', 'Connections', 'Aborted_connects'
             )",
        )
        .await
        .map_err(classify_mysql_error)?;
    let max_connections = connection
        .query_first::<(String, String), _>("SHOW GLOBAL VARIABLES LIKE 'max_connections'")
        .await
        .map_err(classify_mysql_error)?
        .and_then(|(_name, value)| value.parse::<u64>().ok())
        .ok_or(ProbeError::InvalidResponse)?;
    connection
        .disconnect()
        .await
        .map_err(classify_mysql_error)?;
    parse_mysql_status(max_connections, rows)
}

fn classify_mysql_error(error: mysql_async::Error) -> ProbeError {
    match error {
        mysql_async::Error::Server(ref server) if server.code == 1045 => ProbeError::Authentication,
        mysql_async::Error::Server(ref server) if matches!(server.code, 1044 | 1142 | 1227) => {
            ProbeError::Permission
        }
        _ => ProbeError::Connect,
    }
}

async fn probe_redis(value: &str) -> Result<ServiceSemanticSnapshot, ProbeError> {
    validate_loopback_url(value, "redis")?;
    let client = redis::Client::open(value).map_err(|_| ProbeError::InvalidUrl)?;
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .map_err(classify_redis_error)?;
    let pong = redis::cmd("PING")
        .query_async::<String>(&mut connection)
        .await
        .map_err(classify_redis_error)?;
    if pong != "PONG" {
        return Err(ProbeError::Unhealthy);
    }
    let info = redis::cmd("INFO")
        .query_async::<String>(&mut connection)
        .await
        .map_err(classify_redis_error)?;
    if info.len() > MAX_SEMANTIC_BODY_BYTES {
        return Err(ProbeError::InvalidResponse);
    }
    parse_redis_info(&info)
}

fn classify_redis_error(error: redis::RedisError) -> ProbeError {
    if error.kind() == redis::ErrorKind::AuthenticationFailed {
        ProbeError::Authentication
    } else if error.code() == Some("NOPERM") {
        ProbeError::Permission
    } else {
        ProbeError::Connect
    }
}

fn validate_loopback_url(value: &str, scheme: &str) -> Result<(), ProbeError> {
    let parsed = url::Url::parse(value).map_err(|_| ProbeError::InvalidUrl)?;
    let host_loopback = match parsed.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    };
    let http_credentials =
        scheme == "http" && (!parsed.username().is_empty() || parsed.password().is_some());
    if parsed.scheme() != scheme
        || !host_loopback
        || parsed.fragment().is_some()
        || http_credentials
    {
        return Err(ProbeError::InvalidUrl);
    }
    Ok(())
}

fn parse_nginx_status(value: &str) -> Result<ServiceSemanticSnapshot, ProbeError> {
    let lines = value.lines().collect::<Vec<_>>();
    if lines.len() < 4 {
        return Err(ProbeError::InvalidResponse);
    }
    let active_connections = lines[0]
        .strip_prefix("Active connections:")
        .and_then(parse_trimmed_u64)
        .ok_or(ProbeError::InvalidResponse)?;
    let totals = lines[2]
        .split_whitespace()
        .filter_map(|raw| raw.parse::<u64>().ok())
        .collect::<Vec<_>>();
    if totals.len() != 3 {
        return Err(ProbeError::InvalidResponse);
    }
    let states = named_space_values(lines[3]);
    Ok(ServiceSemanticSnapshot::Nginx {
        active_connections,
        accepts: totals[0],
        handled: totals[1],
        requests: totals[2],
        reading: required_map_value(&states, "Reading")?,
        writing: required_map_value(&states, "Writing")?,
        waiting: required_map_value(&states, "Waiting")?,
    })
}

fn parse_apache_status(value: &str) -> Result<ServiceSemanticSnapshot, ProbeError> {
    let values = colon_values(value);
    Ok(ServiceSemanticSnapshot::Apache {
        total_accesses: required_map_value(&values, "Total Accesses")?,
        total_kbytes: required_map_value(&values, "Total kBytes")?,
        busy_workers: required_map_value(&values, "BusyWorkers")?,
        idle_workers: required_map_value(&values, "IdleWorkers")?,
    })
}

fn parse_php_fpm_status(value: &str) -> Result<ServiceSemanticSnapshot, ProbeError> {
    let values = colon_values(value);
    Ok(ServiceSemanticSnapshot::PhpFpm {
        accepted_connections: required_map_value(&values, "accepted conn")?,
        listen_queue: required_map_value(&values, "listen queue")?,
        max_listen_queue: required_map_value(&values, "max listen queue")?,
        listen_queue_length: required_map_value(&values, "listen queue len")?,
        idle_processes: required_map_value(&values, "idle processes")?,
        active_processes: required_map_value(&values, "active processes")?,
        total_processes: required_map_value(&values, "total processes")?,
        max_active_processes: required_map_value(&values, "max active processes")?,
        max_children_reached: required_map_value(&values, "max children reached")?,
        slow_requests: required_map_value(&values, "slow requests")?,
    })
}

fn parse_mysql_status(
    max_connections: u64,
    rows: Vec<(String, String)>,
) -> Result<ServiceSemanticSnapshot, ProbeError> {
    let values = rows
        .into_iter()
        .filter_map(|(key, value)| value.parse::<u64>().ok().map(|value| (key, value)))
        .collect::<HashMap<_, _>>();
    Ok(ServiceSemanticSnapshot::Mysql {
        max_connections,
        threads_connected: required_map_value(&values, "Threads_connected")?,
        threads_running: required_map_value(&values, "Threads_running")?,
        slow_queries: required_map_value(&values, "Slow_queries")?,
        innodb_row_lock_current_waits: required_map_value(
            &values,
            "Innodb_row_lock_current_waits",
        )?,
        total_connections: required_map_value(&values, "Connections")?,
        aborted_connects: required_map_value(&values, "Aborted_connects")?,
    })
}

fn parse_redis_info(value: &str) -> Result<ServiceSemanticSnapshot, ProbeError> {
    let values = colon_values(value);
    Ok(ServiceSemanticSnapshot::Redis {
        used_memory_bytes: required_map_value(&values, "used_memory")?,
        connected_clients: required_map_value(&values, "connected_clients")?,
        blocked_clients: required_map_value(&values, "blocked_clients")?,
        keyspace_hits: required_map_value(&values, "keyspace_hits")?,
        keyspace_misses: required_map_value(&values, "keyspace_misses")?,
        evicted_keys: required_map_value(&values, "evicted_keys")?,
    })
}

fn colon_values(value: &str) -> HashMap<String, u64> {
    value
        .lines()
        .filter_map(|line| {
            let (key, raw) = line.split_once(':')?;
            raw.trim()
                .parse::<u64>()
                .ok()
                .map(|value| (key.trim().to_owned(), value))
        })
        .collect()
}

fn named_space_values(value: &str) -> HashMap<String, u64> {
    let fields = value.split_whitespace().collect::<Vec<_>>();
    fields
        .chunks_exact(2)
        .filter_map(|pair| {
            pair[1]
                .parse::<u64>()
                .ok()
                .map(|value| (pair[0].trim_end_matches(':').to_owned(), value))
        })
        .collect()
}

fn required_map_value<K>(values: &HashMap<K, u64>, key: &str) -> Result<u64, ProbeError>
where
    K: std::borrow::Borrow<str> + Eq + std::hash::Hash,
{
    values.get(key).copied().ok_or(ProbeError::InvalidResponse)
}

fn parse_trimmed_u64(value: &str) -> Option<u64> {
    value.trim().parse::<u64>().ok()
}

fn failed_task() -> CollectorHealth {
    CollectorHealth {
        name: "collector_task".to_owned(),
        state: CollectorState::Error,
        last_success_at: None,
        error_code: Some("COLLECTOR_TASK_FAILED".to_owned()),
        unit: None,
        collected_at_unix_ms: Some(unix_millis()),
        resource_state: None,
        semantic_state: Some(CollectorState::Error),
        resource_error_code: None,
        semantic_error_code: Some("COLLECTOR_TASK_FAILED".to_owned()),
        resources: None,
        semantic: None,
    }
}

fn current_timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        ServiceSemanticSnapshot, merge_service_history, parse_apache_status, parse_mysql_status,
        parse_nginx_status, parse_php_fpm_status, parse_redis_info,
    };
    use crate::cgroup::CgroupSnapshot;
    use crate::{CollectorHealth, CollectorState};

    #[test]
    fn parses_web_php_database_and_redis_semantics() -> Result<(), Box<dyn std::error::Error>> {
        let nginx = parse_nginx_status(
            "Active connections: 3\nserver accepts handled requests\n 10 10 21\nReading: 1 Writing: 1 Waiting: 1\n",
        )?;
        assert!(matches!(
            nginx,
            ServiceSemanticSnapshot::Nginx {
                requests: 21,
                waiting: 1,
                ..
            }
        ));
        let apache = parse_apache_status(
            "Total Accesses: 50\nTotal kBytes: 12\nBusyWorkers: 2\nIdleWorkers: 6\n",
        )?;
        assert!(matches!(
            apache,
            ServiceSemanticSnapshot::Apache {
                busy_workers: 2,
                ..
            }
        ));
        let php = parse_php_fpm_status(
            "accepted conn: 100\nlisten queue: 2\nmax listen queue: 4\nlisten queue len: 128\nidle processes: 3\nactive processes: 2\ntotal processes: 5\nmax active processes: 4\nmax children reached: 1\nslow requests: 2\n",
        )?;
        assert!(matches!(
            php,
            ServiceSemanticSnapshot::PhpFpm {
                listen_queue: 2,
                max_children_reached: 1,
                ..
            }
        ));
        let mysql = parse_mysql_status(
            151,
            vec![
                ("Threads_connected".to_owned(), "5".to_owned()),
                ("Threads_running".to_owned(), "2".to_owned()),
                ("Slow_queries".to_owned(), "7".to_owned()),
                ("Innodb_row_lock_current_waits".to_owned(), "1".to_owned()),
                ("Connections".to_owned(), "100".to_owned()),
                ("Aborted_connects".to_owned(), "3".to_owned()),
            ],
        )?;
        assert!(matches!(
            mysql,
            ServiceSemanticSnapshot::Mysql {
                max_connections: 151,
                threads_connected: 5,
                ..
            }
        ));
        let redis = parse_redis_info(
            "used_memory:4096\nconnected_clients:3\nblocked_clients:1\nkeyspace_hits:20\nkeyspace_misses:4\nevicted_keys:2\n",
        )?;
        assert!(matches!(
            redis,
            ServiceSemanticSnapshot::Redis {
                used_memory_bytes: 4096,
                keyspace_hits: 20,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn computes_cpu_delta_and_marks_failed_values_stale() {
        let old = health(1_000, 10_000, CollectorState::Live);
        let mut current = vec![health(2_000, 510_000, CollectorState::Live)];
        merge_service_history(
            std::slice::from_ref(&old),
            &mut current,
            2_000,
            Duration::from_secs(30),
        );
        assert_eq!(
            current[0]
                .resources
                .as_ref()
                .and_then(|resource| resource.cpu_usage_milli_percent),
            Some(50_000)
        );

        let mut failed = vec![CollectorHealth {
            state: CollectorState::Error,
            resources: None,
            semantic: None,
            collected_at_unix_ms: Some(3_000),
            ..health(3_000, 0, CollectorState::Error)
        }];
        merge_service_history(&[old], &mut failed, 40_000, Duration::from_secs(30));
        assert_eq!(failed[0].state, CollectorState::Stale);
        assert!(failed[0].resources.is_some());
    }

    fn health(
        collected_at_unix_ms: u64,
        cpu_usage_usec: u64,
        state: CollectorState,
    ) -> CollectorHealth {
        CollectorHealth {
            name: "php".to_owned(),
            state,
            last_success_at: Some("1970-01-01T00:00:01Z".to_owned()),
            error_code: None,
            unit: Some("php.service".to_owned()),
            collected_at_unix_ms: Some(collected_at_unix_ms),
            resource_state: Some(state),
            semantic_state: Some(state),
            resource_error_code: None,
            semantic_error_code: None,
            resources: Some(CgroupSnapshot {
                collected_at_unix_ms,
                cpu_usage_usec,
                cpu_user_usec: 0,
                cpu_system_usec: 0,
                cpu_nr_throttled: 0,
                cpu_throttled_usec: 0,
                cpu_usage_milli_percent: None,
                memory_current_bytes: 0,
                memory_peak_bytes: None,
                memory_high_events: 0,
                memory_max_events: 0,
                oom_events: 0,
                oom_kill_events: 0,
                io_read_bytes: 0,
                io_write_bytes: 0,
                process_count: 1,
                task_count: 1,
            }),
            semantic: Some(ServiceSemanticSnapshot::PhpFpm {
                accepted_connections: 1,
                listen_queue: 0,
                max_listen_queue: 0,
                listen_queue_length: 128,
                idle_processes: 1,
                active_processes: 1,
                total_processes: 2,
                max_active_processes: 1,
                max_children_reached: 0,
                slow_requests: 0,
            }),
        }
    }
}
