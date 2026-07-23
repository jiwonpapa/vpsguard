//! 주요 방어 사건을 비차단 bounded HTTPS webhook으로 전달합니다.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use guard_core::config::NotificationConfig;
use guard_core::correlation::LOG_SCHEMA_VERSION;
use guard_core::{GuardEvent, Severity};
use guard_system::{SecretFileError, SecretFilePolicy, load_secret_file};
use reqwest::StatusCode;
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use thiserror::Error;
use tokio::sync::mpsc;

use crate::storage::{NotificationDeliverySummary, SqliteStore};

const USER_AGENT: &str = "VPSGuard/0.1";
const PENDING_REPLAY_LIMIT: usize = 4_096;

/// notification worker 초기화 실패입니다.
#[derive(Debug, Error)]
pub(crate) enum NotificationInitError {
    /// 활성 설정에 webhook URL이 없습니다.
    #[error("notification webhook URL이 없습니다")]
    MissingUrl,
    /// bearer credential을 안전하게 읽지 못했습니다.
    #[error("notification credential을 읽지 못했습니다")]
    Secret(#[from] SecretFileError),
    /// HTTPS client를 구성하지 못했습니다.
    #[error("notification HTTPS client를 구성하지 못했습니다")]
    Client,
    /// 재시작 복구 대상 사건을 읽지 못했습니다.
    #[error("notification 재개 상태를 읽지 못했습니다")]
    Storage,
}

impl NotificationInitError {
    const fn code(&self) -> &'static str {
        match self {
            Self::MissingUrl => "NOTIFICATION_URL_MISSING",
            Self::Secret(_) => "NOTIFICATION_CREDENTIAL_UNAVAILABLE",
            Self::Client => "NOTIFICATION_CLIENT_UNAVAILABLE",
            Self::Storage => "NOTIFICATION_STORAGE_UNAVAILABLE",
        }
    }
}

/// 관리자 API와 UI에 제공하는 notification 상태입니다.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct NotificationStatus {
    pub(crate) enabled: bool,
    pub(crate) configured: bool,
    pub(crate) queue_depth: u64,
    pub(crate) queue_capacity: u64,
    pub(crate) queue_dropped: u64,
    pub(crate) delivered: u64,
    pub(crate) failed: u64,
    pub(crate) pending: u64,
    pub(crate) last_success_at: Option<String>,
    pub(crate) last_failure_at: Option<String>,
    pub(crate) last_error_code: Option<String>,
    pub(crate) storage_available: bool,
}

#[derive(Debug, Default)]
struct RuntimeMetrics {
    queue_depth: AtomicU64,
    queue_dropped: AtomicU64,
}

/// 사건 생산자와 background worker 사이의 non-blocking notification handle입니다.
#[derive(Clone)]
pub(crate) struct NotificationHandle {
    enabled: bool,
    configured: bool,
    queue_capacity: u64,
    max_attempts: u8,
    sender: Option<mpsc::Sender<GuardEvent>>,
    storage: Arc<SqliteStore>,
    metrics: Arc<RuntimeMetrics>,
    startup_error_code: Option<&'static str>,
}

impl NotificationHandle {
    /// 비활성 notification 상태를 생성합니다.
    #[must_use]
    pub(crate) fn disabled(storage: Arc<SqliteStore>) -> Self {
        Self {
            enabled: false,
            configured: false,
            queue_capacity: 0,
            max_attempts: 0,
            sender: None,
            storage,
            metrics: Arc::new(RuntimeMetrics::default()),
            startup_error_code: None,
        }
    }

    /// notification 초기화 실패를 방어 동작과 분리한 degraded 상태를 생성합니다.
    #[must_use]
    pub(crate) fn unavailable(
        config: &NotificationConfig,
        storage: Arc<SqliteStore>,
        error: &NotificationInitError,
    ) -> Self {
        Self {
            enabled: config.enabled,
            configured: config.webhook_url.is_some(),
            queue_capacity: config.queue_capacity as u64,
            max_attempts: config.max_attempts,
            sender: None,
            storage,
            metrics: Arc::new(RuntimeMetrics::default()),
            startup_error_code: Some(error.code()),
        }
    }

    /// 중요 사건을 영속 등록한 뒤 bounded queue에 즉시 넣습니다.
    ///
    /// queue·storage 실패는 호출자의 방어 또는 provider 조치를 막지 않습니다.
    pub(crate) fn enqueue(&self, event: &GuardEvent) {
        if !self.enabled || !should_notify(event) {
            return;
        }
        match self
            .storage
            .register_notification(&event.event_id, self.max_attempts)
        {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                self.metrics.queue_dropped.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    log_schema_version = LOG_SCHEMA_VERSION,
                    component = "guard-control",
                    error_code = "NOTIFICATION_REGISTER_FAILED",
                    event_id = %event.event_id,
                    error = %error,
                    "notification registration failed without blocking protection"
                );
                return;
            }
        }
        let Some(sender) = &self.sender else {
            self.metrics.queue_dropped.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                log_schema_version = LOG_SCHEMA_VERSION,
                component = "guard-control",
                error_code = self
                    .startup_error_code
                    .unwrap_or("NOTIFICATION_WORKER_UNAVAILABLE"),
                event_id = %event.event_id,
                "notification worker unavailable without blocking protection"
            );
            return;
        };
        self.metrics.queue_depth.fetch_add(1, Ordering::Relaxed);
        if sender.try_send(event.clone()).is_err() {
            decrement(&self.metrics.queue_depth);
            self.metrics.queue_dropped.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                log_schema_version = LOG_SCHEMA_VERSION,
                component = "guard-control",
                error_code = "NOTIFICATION_QUEUE_FULL",
                event_id = %event.event_id,
                "notification queue rejected an event without blocking protection"
            );
        }
    }

    /// 현재 queue와 영속 전송 결과를 결합해 반환합니다.
    #[must_use]
    pub(crate) fn status(&self) -> NotificationStatus {
        match self.storage.notification_summary() {
            Ok(summary) => self.status_from_summary(summary, true),
            Err(error) => {
                tracing::warn!(
                    log_schema_version = LOG_SCHEMA_VERSION,
                    component = "guard-control",
                    error_code = "NOTIFICATION_STATUS_READ_FAILED",
                    error = %error,
                    "notification status read-back failed"
                );
                self.status_from_summary(NotificationDeliverySummary::default(), false)
            }
        }
    }

    fn status_from_summary(
        &self,
        summary: NotificationDeliverySummary,
        storage_available: bool,
    ) -> NotificationStatus {
        NotificationStatus {
            enabled: self.enabled,
            configured: self.configured,
            queue_depth: self.metrics.queue_depth.load(Ordering::Relaxed),
            queue_capacity: self.queue_capacity,
            queue_dropped: self.metrics.queue_dropped.load(Ordering::Relaxed),
            delivered: summary.delivered,
            failed: summary.failed,
            pending: summary.pending,
            last_success_at: summary.last_success_at,
            last_failure_at: summary.last_failure_at,
            last_error_code: summary
                .last_error_code
                .or_else(|| self.startup_error_code.map(ToOwned::to_owned)),
            storage_available,
        }
    }
}

/// 설정을 검증된 HTTPS backend와 bounded worker로 조립합니다.
pub(crate) fn start(
    config: &NotificationConfig,
    storage: Arc<SqliteStore>,
) -> Result<NotificationHandle, NotificationInitError> {
    if !config.enabled {
        return Ok(NotificationHandle::disabled(storage));
    }
    let backend = Arc::new(WebhookBackend::from_config(config)?);
    let (sender, receiver) = mpsc::channel(config.queue_capacity);
    let handle = NotificationHandle {
        enabled: true,
        configured: true,
        queue_capacity: config.queue_capacity as u64,
        max_attempts: config.max_attempts,
        sender: Some(sender),
        storage: Arc::clone(&storage),
        metrics: Arc::new(RuntimeMetrics::default()),
        startup_error_code: None,
    };
    let replay_sender = handle.sender.as_ref().cloned();
    let replay_metrics = Arc::clone(&handle.metrics);
    let pending = storage
        .pending_notifications(config.max_attempts, PENDING_REPLAY_LIMIT)
        .map_err(|_error| NotificationInitError::Storage)?;
    let worker = NotificationWorker {
        receiver,
        backend,
        storage,
        metrics: Arc::clone(&handle.metrics),
        max_attempts: config.max_attempts,
        initial_backoff: Duration::from_millis(config.initial_backoff_ms),
    };
    tokio::spawn(worker.run());
    if let Some(sender) = replay_sender {
        tokio::spawn(replay_pending(sender, replay_metrics, pending));
    }
    Ok(handle)
}

trait NotificationBackend: Send + Sync {
    fn send(&self, event: &GuardEvent) -> Result<(), DeliveryError>;
}

struct WebhookBackend {
    client: Client,
    url: String,
    token: Option<SecretString>,
}

impl WebhookBackend {
    fn from_config(config: &NotificationConfig) -> Result<Self, NotificationInitError> {
        let url = config
            .webhook_url
            .clone()
            .ok_or(NotificationInitError::MissingUrl)?;
        let token = config
            .token_file
            .as_deref()
            .map(|path| {
                load_secret_file(
                    path,
                    SecretFilePolicy {
                        min_bytes: 16,
                        max_bytes: 4_096,
                    },
                )
            })
            .transpose()?;
        let client = Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .redirect(Policy::none())
            .user_agent(USER_AGENT)
            .build()
            .map_err(|_error| NotificationInitError::Client)?;
        Ok(Self { client, url, token })
    }
}

impl NotificationBackend for WebhookBackend {
    fn send(&self, event: &GuardEvent) -> Result<(), DeliveryError> {
        let payload = WebhookPayload::from_event(event);
        let mut request = self
            .client
            .post(&self.url)
            .header("Idempotency-Key", &event.event_id)
            .json(&payload);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token.expose_secret());
        }
        let response = request.send().map_err(|error| {
            if error.is_timeout() {
                DeliveryError::Timeout
            } else {
                DeliveryError::Transport
            }
        })?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(DeliveryError::Http(response.status()))
        }
    }
}

#[derive(Debug, Serialize)]
struct WebhookPayload<'a> {
    schema_version: u32,
    event_id: &'a str,
    occurred_at: &'a str,
    severity: Severity,
    kind: &'a str,
    summary: &'a str,
    reason_codes: &'a [guard_core::ReasonCode],
    action: Option<&'a str>,
    mode: Option<&'a str>,
}

impl<'a> WebhookPayload<'a> {
    fn from_event(event: &'a GuardEvent) -> Self {
        Self {
            schema_version: 1,
            event_id: &event.event_id,
            occurred_at: &event.occurred_at,
            severity: event.severity,
            kind: &event.kind,
            summary: &event.summary,
            reason_codes: &event.reason_codes,
            action: event.action.get("name").map(String::as_str),
            mode: event
                .action
                .get("mode")
                .or_else(|| event.result.get("mode"))
                .map(String::as_str),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeliveryError {
    Timeout,
    Transport,
    Http(StatusCode),
}

impl DeliveryError {
    const fn code(self) -> &'static str {
        match self {
            Self::Timeout => "WEBHOOK_TIMEOUT",
            Self::Transport => "WEBHOOK_TRANSPORT_FAILED",
            Self::Http(_) => "WEBHOOK_HTTP_REJECTED",
        }
    }

    fn retryable(self) -> bool {
        match self {
            Self::Timeout | Self::Transport => true,
            Self::Http(status) => {
                status == StatusCode::REQUEST_TIMEOUT
                    || status == StatusCode::TOO_MANY_REQUESTS
                    || status.is_server_error()
            }
        }
    }
}

struct NotificationWorker {
    receiver: mpsc::Receiver<GuardEvent>,
    backend: Arc<dyn NotificationBackend>,
    storage: Arc<SqliteStore>,
    metrics: Arc<RuntimeMetrics>,
    max_attempts: u8,
    initial_backoff: Duration,
}

impl NotificationWorker {
    async fn run(mut self) {
        while let Some(event) = self.receiver.recv().await {
            decrement(&self.metrics.queue_depth);
            self.deliver(&event).await;
        }
    }

    async fn deliver(&self, event: &GuardEvent) {
        let eligible = match self
            .storage
            .register_notification(&event.event_id, self.max_attempts)
        {
            Ok(value) => value,
            Err(error) => {
                self.log_storage_failure(event, &error);
                return;
            }
        };
        if !eligible {
            return;
        }
        loop {
            let attempted_at = current_timestamp();
            let attempt = match self
                .storage
                .begin_notification_attempt(&event.event_id, &attempted_at)
            {
                Ok(attempt) => attempt,
                Err(error) => {
                    self.log_storage_failure(event, &error);
                    return;
                }
            };
            let backend = Arc::clone(&self.backend);
            let event_for_task = event.clone();
            let result = tokio::task::spawn_blocking(move || backend.send(&event_for_task)).await;
            match result {
                Ok(Ok(())) => {
                    if let Err(error) = self
                        .storage
                        .complete_notification(&event.event_id, &current_timestamp())
                    {
                        self.log_storage_failure(event, &error);
                    }
                    return;
                }
                Ok(Err(error)) => {
                    let exhausted = attempt >= self.max_attempts || !error.retryable();
                    if let Err(storage_error) = self.storage.fail_notification(
                        &event.event_id,
                        &current_timestamp(),
                        error.code(),
                        exhausted,
                    ) {
                        self.log_storage_failure(event, &storage_error);
                        return;
                    }
                    if exhausted {
                        tracing::warn!(
                            log_schema_version = LOG_SCHEMA_VERSION,
                            component = "guard-control",
                            error_code = error.code(),
                            event_id = %event.event_id,
                            attempts = attempt,
                            "notification failed without blocking protection"
                        );
                        return;
                    }
                    let multiplier = 1_u32 << u32::from(attempt.saturating_sub(1).min(10));
                    tokio::time::sleep(self.initial_backoff.saturating_mul(multiplier)).await;
                }
                Err(error) => {
                    let exhausted = attempt >= self.max_attempts;
                    if let Err(storage_error) = self.storage.fail_notification(
                        &event.event_id,
                        &current_timestamp(),
                        "WEBHOOK_TASK_FAILED",
                        exhausted,
                    ) {
                        self.log_storage_failure(event, &storage_error);
                        return;
                    }
                    if exhausted {
                        tracing::warn!(
                            log_schema_version = LOG_SCHEMA_VERSION,
                            component = "guard-control",
                            error_code = "WEBHOOK_TASK_FAILED",
                            event_id = %event.event_id,
                            error = %error,
                            "notification task failed without blocking protection"
                        );
                        return;
                    }
                }
            }
        }
    }

    fn log_storage_failure(&self, event: &GuardEvent, error: &crate::storage::StorageError) {
        tracing::warn!(
            log_schema_version = LOG_SCHEMA_VERSION,
            component = "guard-control",
            error_code = "NOTIFICATION_STORAGE_FAILED",
            event_id = %event.event_id,
            error = %error,
            "notification storage failed without blocking protection"
        );
    }
}

fn should_notify(event: &GuardEvent) -> bool {
    match event.kind.as_str() {
        "guard.mode_transition" => event.action.get("mode").is_some_and(|mode| {
            matches!(
                mode.as_str(),
                "LocalGuard" | "EmergencyProxy" | "RecoveryReady"
            )
        }),
        kind => kind.starts_with("provider."),
    }
}

fn decrement(value: &AtomicU64) {
    let _result = value.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_sub(1))
    });
}

async fn replay_pending(
    sender: mpsc::Sender<GuardEvent>,
    metrics: Arc<RuntimeMetrics>,
    pending: Vec<GuardEvent>,
) {
    for event in pending {
        let permit = match sender.reserve().await {
            Ok(permit) => permit,
            Err(_error) => {
                metrics.queue_dropped.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    log_schema_version = LOG_SCHEMA_VERSION,
                    component = "guard-control",
                    error_code = "NOTIFICATION_REPLAY_QUEUE_CLOSED",
                    event_id = %event.event_id,
                    "notification replay remains pending after worker shutdown"
                );
                break;
            }
        };
        metrics.queue_depth.fetch_add(1, Ordering::Relaxed);
        permit.send(event);
    }
}

fn current_timestamp() -> String {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_error| "1970-01-01T00:00:00Z".to_owned())
}

#[cfg(test)]
#[path = "notification/tests.rs"]
mod tests;
