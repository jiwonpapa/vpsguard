//! Pingora `ProxyHttp` adapter와 request lifecycle 정책을 구현합니다.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Instant, SystemTime};

use async_trait::async_trait;
use bytes::Bytes;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{
    Error, ErrorSource,
    ErrorType::{ConnectionClosed, HTTPStatus, ReadError, WriteError},
};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{FailToProxy, ProxyHttp, Session};
use tracing::{info, warn};

use crate::context::RequestContext;
use crate::policy::{effective_client_ip, host_allowed, normalize_host};
use crate::rate_limit::{BoundedRateLimiter, LimitDecision, RouteClass};
use crate::response::{add_common_headers, respond_redirect, respond_text};
use crate::runtime::EdgeRuntimeConfig;

const LIVE_PATH: &str = "/health/live";
const READY_PATH: &str = "/health/ready";

/// 단일 origin으로 요청을 전달하는 VPSGuard Pingora edge입니다.
#[derive(Debug)]
pub(crate) struct GuardEdge {
    config: EdgeRuntimeConfig,
    request_sequence: AtomicU64,
    rate_limiter: Arc<BoundedRateLimiter>,
    origin_ready: AtomicBool,
}

impl GuardEdge {
    pub(crate) fn new(config: EdgeRuntimeConfig) -> Self {
        let max_entries = config.max_tracked_clients;
        Self {
            config,
            request_sequence: AtomicU64::new(1),
            rate_limiter: Arc::new(BoundedRateLimiter::new(max_entries)),
            origin_ready: AtomicBool::new(true),
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
        let (method, path, target, host, forwarded_for, content_length) = {
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
        context.request_body_bytes_seen = 0;

        if !host_allowed(host.as_deref(), &self.config.allowed_hosts) {
            warn!(
                request_id = %context.request_id,
                path = %context.path,
                client_ip = ?context.client_ip,
                "invalid host rejected"
            );
            respond_text(session, 400, b"invalid host\n", &context.request_id, None).await?;
            return Ok(true);
        }
        if path == LIVE_PATH {
            respond_text(session, 200, b"live\n", &context.request_id, None).await?;
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
            return Ok(true);
        }
        if let (Some(client_ip), Some(limit)) = (
            context.client_ip,
            self.config.rate_limit(context.route_class),
        ) {
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
        Ok(())
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        error: &pingora_core::Error,
        _context: &mut Self::CTX,
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
