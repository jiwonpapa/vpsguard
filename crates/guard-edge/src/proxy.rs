//! Pingora `ProxyHttp` adapter와 request lifecycle 정책을 구현합니다.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use guard_core::Decision;
use guard_profiles::classify;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{
    Error, ErrorSource,
    ErrorType::{ConnectionClosed, HTTPStatus, ReadError, WriteError},
};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{FailToProxy, ProxyHttp, Session};
use time::OffsetDateTime;
use tracing::{info, warn};

use crate::challenge::ClearanceSigner;
use crate::context::RequestContext;
use crate::policy::{effective_client_ip, host_allowed, normalize_host};
use crate::policy_runtime::PolicyRuntime;
use crate::rate_limit::{BoundedRateLimiter, LimitDecision, RouteClass};
use crate::response::{
    add_common_headers, respond_redirect, respond_text, respond_text_with_headers,
};
use crate::runtime::EdgeRuntimeConfig;
use crate::telemetry::{DecisionKind, RequestTelemetry, TelemetrySink};

const LIVE_PATH: &str = "/health/live";
const READY_PATH: &str = "/health/ready";

/// 단일 origin으로 요청을 전달하는 VPSGuard Pingora edge입니다.
#[derive(Debug)]
pub(crate) struct GuardEdge {
    config: EdgeRuntimeConfig,
    request_sequence: AtomicU64,
    rate_limiter: Arc<BoundedRateLimiter>,
    origin_ready: AtomicBool,
    telemetry: TelemetrySink,
    policy: Arc<PolicyRuntime>,
    clearance: Option<ClearanceSigner>,
}

impl GuardEdge {
    pub(crate) fn new(config: EdgeRuntimeConfig) -> Self {
        let max_entries = config.max_tracked_clients;
        let telemetry = TelemetrySink::connect(&config.telemetry_socket);
        let policy = Arc::new(PolicyRuntime::new(config.policy_path.clone()));
        if let Err(error) = policy.reload_at(OffsetDateTime::now_utc()) {
            warn!(error = %error, path = %policy.path().display(), "initial policy rejected");
        }
        policy.spawn(config.policy_reload_interval);
        let clearance = config.challenge_secret_file.as_deref().and_then(|path| {
            ClearanceSigner::from_file(path, config.clearance_ttl_seconds)
                .map_err(
                    |error| warn!(error = %error, path = %path.display(), "clearance disabled"),
                )
                .ok()
        });
        Self {
            config,
            request_sequence: AtomicU64::new(1),
            rate_limiter: Arc::new(BoundedRateLimiter::new(max_entries)),
            origin_ready: AtomicBool::new(true),
            telemetry,
            policy,
            clearance,
        }
    }

    fn next_request_id(&self) -> String {
        let next = self.request_sequence.fetch_add(1, Ordering::Relaxed);
        format!("guard-{next:016x}")
    }

    async fn filter_request(
        &self,
        session: &mut Session,
        context: &mut RequestContext,
    ) -> pingora_core::Result<bool> {
        let (method, path, target, host, forwarded_for, content_length, cookie) = {
            let request = session.req_header();
            (
                request.method.as_str().to_owned(),
                request.uri.path().to_owned(),
                request.uri.path_and_query().map_or_else(
                    || request.uri.path().to_owned(),
                    |value| value.as_str().to_owned(),
                ),
                header_value(request, "host"),
                header_value(request, "x-forwarded-for"),
                header_value(request, "content-length").and_then(|value| value.parse::<u64>().ok()),
                header_value(request, "cookie"),
            )
        };
        context.started_at = Instant::now();
        context.request_id = self.next_request_id();
        context.method = method;
        context.path = path.clone();
        context.host = host.clone();
        context.direct_peer = direct_client_ip(session);
        context.forwarded_headers_trusted = context
            .direct_peer
            .is_some_and(|peer| self.config.trusts_peer(peer));
        context.client_ip = context.direct_peer.map(|direct| {
            effective_client_ip(
                direct,
                forwarded_for.as_deref(),
                &self.config.trusted_proxy_cidrs,
            )
        });
        context.route_class = self.config.route_class(&path);
        let route_profile = classify(self.config.application_profile, &target);
        context.normalized_route = route_profile.normalized_route;
        context.route_cost = route_profile.base_cost;
        context.request_body_bytes_seen = 0;

        if !host_allowed(host.as_deref(), &self.config.allowed_hosts) {
            warn!(
                request_id = %context.request_id,
                path = %context.path,
                client_ip = ?context.client_ip,
                "invalid host rejected"
            );
            respond_text(session, 400, b"invalid host\n", &context.request_id, None).await?;
            self.emit_telemetry(context, 400, DecisionKind::Deny);
            return Ok(true);
        }
        if path == LIVE_PATH {
            respond_text(session, 200, b"live\n", &context.request_id, None).await?;
            self.emit_telemetry(context, 200, DecisionKind::Allow);
            return Ok(true);
        }
        if path == READY_PATH {
            let ready = self.origin_ready.load(Ordering::Acquire);
            let (status, body): (u16, &'static [u8]) = if ready {
                (200, b"ready\n")
            } else {
                (503, b"origin unavailable\n")
            };
            respond_text(session, status, body, &context.request_id, None).await?;
            self.emit_telemetry(context, status, DecisionKind::Allow);
            return Ok(true);
        }
        if let (Some(canonical), Some(current)) =
            (self.config.canonical_host.as_deref(), host.as_deref())
            && normalize_host(current) != normalize_host(canonical)
        {
            let scheme = current_proto(session, context.forwarded_headers_trusted);
            let location = format!("{scheme}://{canonical}{target}");
            info!(
                request_id = %context.request_id,
                path = %context.path,
                canonical_host = canonical,
                "canonical host redirect"
            );
            respond_redirect(session, &location, &context.request_id).await?;
            self.emit_telemetry(context, 308, DecisionKind::Allow);
            return Ok(true);
        }
        let runtime_decision = self.policy.decision_at(
            context.client_ip,
            context.route_class.as_str(),
            OffsetDateTime::now_utc(),
        );
        context.policy_version = runtime_decision.policy_version;
        if let Some(client_ip) = context.client_ip {
            match runtime_decision.action {
                Some(Decision::Deny) => {
                    respond_text(session, 403, b"request denied\n", &context.request_id, None)
                        .await?;
                    self.emit_telemetry(context, 403, DecisionKind::Deny);
                    return Ok(true);
                }
                Some(Decision::Challenge) => {
                    let now_unix = unix_seconds();
                    let cleared = self.clearance.as_ref().is_some_and(|signer| {
                        signer.verify_cookie(cookie.as_deref(), client_ip, now_unix)
                    });
                    if !cleared {
                        let headers = self.clearance.as_ref().map_or_else(Vec::new, |signer| {
                            vec![(
                                "set-cookie",
                                signer.issue_cookie(
                                    client_ip,
                                    now_unix,
                                    current_proto(session, context.forwarded_headers_trusted)
                                        == "https",
                                ),
                            )]
                        });
                        respond_text_with_headers(
                            session,
                            401,
                            b"browser verification required; retry request\n",
                            &context.request_id,
                            &headers,
                        )
                        .await?;
                        self.emit_telemetry(context, 401, DecisionKind::Challenge);
                        return Ok(true);
                    }
                }
                Some(Decision::Throttle) => {
                    respond_text(
                        session,
                        429,
                        b"temporarily throttled\n",
                        &context.request_id,
                        Some(60),
                    )
                    .await?;
                    self.emit_telemetry(context, 429, DecisionKind::Throttle);
                    return Ok(true);
                }
                Some(Decision::Allow | Decision::Observe) | None => {}
            }
        }
        let rate_limit = runtime_decision
            .requests_per_minute
            .or_else(|| self.config.rate_limit(context.route_class));
        if let (Some(client_ip), Some(limit)) = (context.client_ip, rate_limit) {
            match self
                .rate_limiter
                .check(client_ip, context.route_class, limit, SystemTime::now())
            {
                LimitDecision::Allow => {}
                LimitDecision::Deny => {
                    warn!(
                        request_id = %context.request_id,
                        path = %context.path,
                        client_ip = %client_ip,
                        "request rate limited"
                    );
                    respond_text(
                        session,
                        429,
                        b"too many requests\n",
                        &context.request_id,
                        Some(60),
                    )
                    .await?;
                    self.emit_telemetry(context, 429, DecisionKind::Throttle);
                    return Ok(true);
                }
                LimitDecision::CapacityReached => {
                    warn!("rate limiter capacity reached; request allowed");
                }
            }
        }
        let body_limit = self.config.body_limit(context.route_class);
        if content_length.is_some_and(|body_size| body_size > body_limit) {
            respond_text(
                session,
                413,
                b"payload too large\n",
                &context.request_id,
                None,
            )
            .await?;
            self.emit_telemetry(context, 413, DecisionKind::Deny);
            return Ok(true);
        }
        Ok(false)
    }

    async fn filter_body(
        &self,
        body: &Option<Bytes>,
        context: &mut RequestContext,
    ) -> pingora_core::Result<()> {
        let chunk_len = body.as_ref().map_or(0, |chunk| chunk.len() as u64);
        context.request_body_bytes_seen = context.request_body_bytes_seen.saturating_add(chunk_len);
        if context.request_body_bytes_seen > self.config.body_limit(context.route_class) {
            return Err(Error::new(HTTPStatus(413)));
        }
        Ok(())
    }

    fn filter_upstream_request(
        &self,
        session: &Session,
        upstream_request: &mut RequestHeader,
        context: &RequestContext,
    ) -> pingora_core::Result<()> {
        if let Some(client_ip) = context.client_ip {
            let value = client_ip.to_string();
            upstream_request.insert_header("x-forwarded-for", &value)?;
            upstream_request.insert_header("x-real-ip", &value)?;
        }
        let proto = current_proto(session, context.forwarded_headers_trusted);
        upstream_request.insert_header("x-forwarded-proto", &proto)?;
        if let Some(host) = context.host.as_deref() {
            upstream_request.insert_header("x-forwarded-host", host)?;
        }
        upstream_request.insert_header("x-request-id", &context.request_id)?;
        Ok(())
    }
}

#[async_trait]
impl ProxyHttp for GuardEdge {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext::new()
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        context: &mut Self::CTX,
    ) -> pingora_core::Result<Box<HttpPeer>> {
        let mut peer = HttpPeer::new(
            (&*self.config.origin_host, self.config.origin_port),
            self.config.origin_tls,
            self.config.origin_sni.clone(),
        );
        peer.options.connection_timeout = Some(self.config.upstream_connect_timeout);
        peer.options.read_timeout = Some(if context.route_class == RouteClass::Upload {
            self.config.upload_upstream_read_timeout
        } else {
            self.config.upstream_read_timeout
        });
        Ok(Box::new(peer))
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        context: &mut Self::CTX,
    ) -> pingora_core::Result<bool> {
        self.filter_request(session, context).await
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        context: &mut Self::CTX,
    ) -> pingora_core::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        self.filter_body(body, context).await
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        context: &mut Self::CTX,
    ) -> pingora_core::Result<()> {
        self.filter_upstream_request(session, upstream_request, context)
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        context: &mut Self::CTX,
    ) -> pingora_core::Result<()> {
        self.origin_ready.store(true, Ordering::Release);
        add_common_headers(upstream_response, &context.request_id)?;
        info!(
            request_id = %context.request_id,
            method = %context.method,
            path = %context.path,
            status = upstream_response.status.as_u16(),
            client_ip = ?context.client_ip,
            latency_ms = context.started_at.elapsed().as_millis(),
            "request completed"
        );
        self.emit_telemetry(
            context,
            upstream_response.status.as_u16(),
            DecisionKind::Allow,
        );
        Ok(())
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        error: &pingora_core::Error,
        context: &mut Self::CTX,
    ) -> FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        self.origin_ready.store(false, Ordering::Release);
        let error_code = match error.etype() {
            HTTPStatus(code) => *code,
            _ => match error.esource() {
                ErrorSource::Upstream => 502,
                ErrorSource::Downstream => match error.etype() {
                    WriteError | ReadError | ConnectionClosed => 0,
                    _ => 400,
                },
                ErrorSource::Internal | ErrorSource::Unset => 500,
            },
        };
        if error_code > 0
            && let Err(send_error) = session.respond_error(error_code).await
        {
            warn!(error = %send_error, "failed to send proxy error response");
        }
        if error_code > 0 {
            let decision = if error_code == 429 {
                DecisionKind::Throttle
            } else if (400..500).contains(&error_code) {
                DecisionKind::Deny
            } else {
                DecisionKind::Allow
            };
            self.emit_telemetry(context, error_code, decision);
        }
        FailToProxy {
            error_code,
            can_reuse_downstream: false,
        }
    }

    fn request_summary(&self, _session: &Session, context: &Self::CTX) -> String {
        format!(
            "id={} {} {} -> {}:{} tls={}",
            context.request_id,
            context.method,
            context.path,
            self.config.origin_host,
            self.config.origin_port,
            self.config.origin_tls
        )
    }
}

impl GuardEdge {
    fn emit_telemetry(&self, context: &RequestContext, status: u16, decision: DecisionKind) {
        self.telemetry.emit(&RequestTelemetry {
            schema_version: 1,
            request_id: context.request_id.clone(),
            method: context.method.clone(),
            route_class: context.route_class,
            normalized_route: context.normalized_route.clone(),
            route_cost: context.route_cost,
            status,
            latency_micros: context
                .started_at
                .elapsed()
                .as_micros()
                .try_into()
                .unwrap_or(u64::MAX),
            client_ip: context.client_ip,
            request_body_bytes: context.request_body_bytes_seen,
            decision,
            policy_version: context.policy_version,
            occurred_at_unix_ms: unix_millis(),
        });
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn header_value(request: &RequestHeader, name: &str) -> Option<String> {
    request
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn direct_client_ip(session: &Session) -> Option<IpAddr> {
    session
        .as_downstream()
        .client_addr()
        .and_then(|address| address.as_inet().map(|inet| inet.ip()))
}

fn current_proto(session: &Session, forwarded_headers_trusted: bool) -> String {
    if forwarded_headers_trusted
        && let Some(proto) = header_value(session.req_header(), "x-forwarded-proto")
        && matches!(proto.to_ascii_lowercase().as_str(), "http" | "https")
    {
        return proto.to_ascii_lowercase();
    }
    if session
        .as_downstream()
        .digest()
        .and_then(|digest| digest.ssl_digest.as_ref())
        .is_some()
    {
        "https".to_owned()
    } else {
        "http".to_owned()
    }
}
