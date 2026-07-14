use std::time::{Instant, SystemTime};

use bytes::Bytes;
use log::{error, info, warn};
use pingora_error::{
    Error, ErrorSource,
    ErrorType::{ConnectionClosed, HTTPStatus, ReadError, WriteError},
};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{FailToProxy, Session};

use crate::context::RequestCtx;
use crate::request_policy::{
    canonical_redirect_location, content_length, current_proto, direct_client_ip,
    effective_client_ip_from_headers, first_forwarded_for, request_header_value, request_target,
    select_rate_limit,
};
use crate::response::{add_common_response_headers, respond_plain_text, respond_redirect};
use crate::runtime_config::normalize_host;
use crate::{EDGE_HEALTH_PATH, EdgeProxyApp};

impl EdgeProxyApp {
    pub(crate) async fn handle_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> pingora_core::Result<bool> {
        let (method, path, target, host, request_id, content_length_value, forwarded_for) = {
            let req = session.req_header();
            (
                req.method.as_str().to_string(),
                req.uri.path().to_string(),
                request_target(req),
                request_header_value(req, "host"),
                request_header_value(req, self.config.request_id_header.as_str())
                    .unwrap_or_else(|| self.next_request_id()),
                content_length(req),
                request_header_value(req, "x-forwarded-for"),
            )
        };

        ctx.started_at = Instant::now();
        ctx.method = method;
        ctx.path = path.clone();
        ctx.target = target.clone();
        ctx.host = host.clone();
        ctx.request_id = request_id;
        ctx.direct_client_ip = direct_client_ip(session);
        ctx.forwarded_headers_trusted = self.forwarded_headers_trusted(ctx.direct_client_ip);
        ctx.effective_client_ip = effective_client_ip_from_headers(
            forwarded_for.as_deref(),
            ctx.direct_client_ip,
            ctx.forwarded_headers_trusted,
        );
        ctx.request_body_bytes_seen = 0;

        let downstream_read_timeout = if self.is_upload_path(path.as_str()) {
            self.config
                .upload_downstream_read_timeout
                .or(self.config.downstream_read_timeout)
        } else {
            self.config.downstream_read_timeout
        };
        session
            .as_downstream_mut()
            .set_read_timeout(downstream_read_timeout);
        session
            .as_downstream_mut()
            .set_write_timeout(self.config.downstream_write_timeout);
        session
            .as_downstream_mut()
            .set_total_drain_timeout(self.config.downstream_total_drain_timeout);

        if path == EDGE_HEALTH_PATH {
            info!(
                "edge_proxy health request id={} client_ip={:?}",
                ctx.request_id, ctx.effective_client_ip
            );
            respond_plain_text(
                session,
                200,
                b"ok\n",
                self.config.request_id_header.as_str(),
                ctx.request_id.as_str(),
            )
            .await?;
            return Ok(true);
        }

        if !self.host_allowed(host.as_deref()) {
            warn!(
                "edge_proxy rejected invalid host id={} host={:?} path={} client_ip={:?}",
                ctx.request_id, ctx.host, ctx.path, ctx.effective_client_ip
            );
            respond_plain_text(
                session,
                400,
                b"invalid host\n",
                self.config.request_id_header.as_str(),
                ctx.request_id.as_str(),
            )
            .await?;
            return Ok(true);
        }

        if !self.host_passthrough(host.as_deref())
            && let (Some(canonical_host), Some(current_host)) =
                (self.config.canonical_host.as_deref(), host.as_deref())
            && normalize_host(current_host) != canonical_host
        {
            let location = canonical_redirect_location(
                &current_proto(session, ctx.forwarded_headers_trusted),
                canonical_host,
                &target,
            );
            info!(
                "edge_proxy redirect id={} from_host={:?} to={} path={}",
                ctx.request_id, ctx.host, canonical_host, ctx.target
            );
            respond_redirect(
                session,
                &location,
                self.config.request_id_header.as_str(),
                ctx.request_id.as_str(),
            )
            .await?;
            return Ok(true);
        }

        if self.is_gone_path(path.as_str()) {
            warn!(
                "edge_proxy blocked gone path id={} path={} client_ip={:?}",
                ctx.request_id, ctx.path, ctx.effective_client_ip
            );
            respond_plain_text(
                session,
                410,
                b"gone\n",
                self.config.request_id_header.as_str(),
                ctx.request_id.as_str(),
            )
            .await?;
            return Ok(true);
        }

        if self.blocked_ip_denied(ctx.effective_client_ip) {
            warn!(
                "edge_proxy denied blocked client id={} path={} client_ip={:?}",
                ctx.request_id, ctx.path, ctx.effective_client_ip
            );
            respond_plain_text(
                session,
                403,
                b"forbidden\n",
                self.config.request_id_header.as_str(),
                ctx.request_id.as_str(),
            )
            .await?;
            return Ok(true);
        }

        if self.is_admin_path(path.as_str()) && !self.admin_ip_allowed(ctx.effective_client_ip) {
            warn!(
                "edge_proxy denied admin path id={} path={} client_ip={:?}",
                ctx.request_id, ctx.path, ctx.effective_client_ip
            );
            respond_plain_text(
                session,
                403,
                b"forbidden\n",
                self.config.request_id_header.as_str(),
                ctx.request_id.as_str(),
            )
            .await?;
            return Ok(true);
        }

        let rate_limit = select_rate_limit(path.as_str(), &self.config);

        if let (Some(limit), Some(client_ip)) = (rate_limit, ctx.effective_client_ip)
            && !self.rate_limiter.allow(client_ip, limit, SystemTime::now())
        {
            warn!(
                "edge_proxy rate limited id={} path={} client_ip={}",
                ctx.request_id, ctx.path, client_ip
            );
            respond_plain_text(
                session,
                429,
                b"too many requests\n",
                self.config.request_id_header.as_str(),
                ctx.request_id.as_str(),
            )
            .await?;
            return Ok(true);
        }

        let body_limit = if self.is_upload_path(path.as_str()) {
            self.config
                .upload_max_body_bytes
                .or(self.config.max_body_bytes)
        } else {
            self.config.max_body_bytes
        };

        if let (Some(limit), Some(body_size)) = (body_limit, content_length_value)
            && body_size > limit
        {
            warn!(
                "edge_proxy rejected oversized request id={} path={} content_length={} limit={}",
                ctx.request_id, ctx.path, body_size, limit
            );
            respond_plain_text(
                session,
                413,
                b"payload too large\n",
                self.config.request_id_header.as_str(),
                ctx.request_id.as_str(),
            )
            .await?;
            return Ok(true);
        }

        Ok(false)
    }

    pub(crate) async fn handle_request_body_filter(
        &self,
        body: &mut Option<Bytes>,
        ctx: &mut RequestCtx,
    ) -> pingora_core::Result<()> {
        let limit = if self.is_upload_path(ctx.path.as_str()) {
            self.config
                .upload_max_body_bytes
                .or(self.config.max_body_bytes)
        } else {
            self.config.max_body_bytes
        };

        let Some(limit) = limit else {
            return Ok(());
        };

        let chunk_len = body.as_ref().map_or(0, |chunk| chunk.len() as u64);
        ctx.request_body_bytes_seen = ctx.request_body_bytes_seen.saturating_add(chunk_len);

        if ctx.request_body_bytes_seen > limit {
            warn!(
                "edge_proxy rejected chunked oversized request id={} path={} seen_bytes={} limit={}",
                ctx.request_id, ctx.path, ctx.request_body_bytes_seen, limit
            );
            return Err(Error::new(HTTPStatus(413)));
        }

        Ok(())
    }

    pub(crate) async fn handle_upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut RequestCtx,
    ) -> pingora_core::Result<()> {
        let existing_forwarded_for = request_header_value(session.req_header(), "x-forwarded-for");
        let forwarded_for = if ctx.forwarded_headers_trusted {
            existing_forwarded_for.unwrap_or_else(|| {
                ctx.effective_client_ip
                    .or(ctx.direct_client_ip)
                    .map(|ip| ip.to_string())
                    .unwrap_or_default()
            })
        } else {
            ctx.direct_client_ip
                .or(ctx.effective_client_ip)
                .map(|ip| ip.to_string())
                .unwrap_or_default()
        };
        if !forwarded_for.is_empty() {
            upstream_request.insert_header("x-forwarded-for", forwarded_for.as_str())?;
        }

        if let Some(real_ip) = first_forwarded_for(&forwarded_for)
            .or_else(|| ctx.effective_client_ip.map(|ip| ip.to_string()))
        {
            upstream_request.insert_header("x-real-ip", real_ip.as_str())?;
        }

        let proto = current_proto(session, ctx.forwarded_headers_trusted);
        upstream_request.insert_header("x-forwarded-proto", proto.as_str())?;

        if let Some(host) = ctx.host.as_deref() {
            upstream_request.insert_header("x-forwarded-host", host)?;
        }

        upstream_request.insert_header(
            self.config.request_id_header.clone(),
            ctx.request_id.as_str(),
        )?;

        Ok(())
    }

    pub(crate) async fn handle_response_filter(
        &self,
        upstream_response: &mut ResponseHeader,
        ctx: &mut RequestCtx,
    ) -> pingora_core::Result<()> {
        add_common_response_headers(
            upstream_response,
            self.config.request_id_header.as_str(),
            ctx.request_id.as_str(),
        )?;

        info!(
            "edge_proxy request id={} method={} path={} status={} client_ip={:?} latency_ms={}",
            ctx.request_id,
            ctx.method,
            ctx.path,
            upstream_response.status.as_u16(),
            ctx.effective_client_ip,
            ctx.started_at.elapsed().as_millis()
        );

        Ok(())
    }

    pub(crate) async fn handle_fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora_core::Error,
        ctx: &mut RequestCtx,
    ) -> FailToProxy {
        if matches!(e.etype(), HTTPStatus(413)) {
            let _ = respond_plain_text(
                session,
                413,
                b"payload too large\n",
                self.config.request_id_header.as_str(),
                ctx.request_id.as_str(),
            )
            .await;

            return FailToProxy {
                error_code: 413,
                can_reuse_downstream: false,
            };
        }

        let code = match e.etype() {
            HTTPStatus(code) => *code,
            _ => match e.esource() {
                ErrorSource::Upstream => 502,
                ErrorSource::Downstream => match e.etype() {
                    WriteError | ReadError | ConnectionClosed => 0,
                    _ => 400,
                },
                ErrorSource::Internal | ErrorSource::Unset => 500,
            },
        };

        if code > 0 {
            session
                .respond_error(code)
                .await
                .unwrap_or_else(|send_err| {
                    error!("failed to send error response to downstream: {send_err}");
                });
        }

        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }

    pub(crate) fn build_request_summary(&self, ctx: &RequestCtx) -> String {
        format!(
            "id={} {} {} -> {}:{} tls={}",
            if ctx.request_id.is_empty() {
                "-"
            } else {
                ctx.request_id.as_str()
            },
            if ctx.method.is_empty() {
                "-"
            } else {
                ctx.method.as_str()
            },
            if ctx.path.is_empty() {
                "-"
            } else {
                ctx.path.as_str()
            },
            self.config.upstream_host,
            self.config.upstream_port,
            self.config.upstream_tls
        )
    }
}
