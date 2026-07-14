use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{FailToProxy, ProxyHttp, Session};

mod app_policy;
mod context;
mod proxy_flow;
mod rate_limit;
mod request_policy;
mod response;
mod runtime_config;
mod startup;

use context::RequestCtx;
use rate_limit::FixedWindowRateLimiter;
use runtime_config::EdgeRuntimeConfig;
use startup::{install_rustls_crypto_provider, load_runtime_config, run_server};

const EDGE_HEALTH_PATH: &str = "/edge/health";

#[derive(Debug, Clone)]
pub(crate) struct EdgeProxyApp {
    config: EdgeRuntimeConfig,
    request_sequence: Arc<AtomicU64>,
    rate_limiter: Arc<FixedWindowRateLimiter>,
}

impl EdgeProxyApp {
    pub(crate) fn new(config: EdgeRuntimeConfig) -> Self {
        Self {
            config,
            request_sequence: Arc::new(AtomicU64::new(1)),
            rate_limiter: Arc::new(FixedWindowRateLimiter::default()),
        }
    }

    fn next_request_id(&self) -> String {
        let next = self.request_sequence.fetch_add(1, Ordering::Relaxed);
        format!("edge-{next:016x}")
    }
}

#[async_trait]
impl ProxyHttp for EdgeProxyApp {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx::new()
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Box<HttpPeer>> {
        let mut peer = HttpPeer::new(
            (&*self.config.upstream_host, self.config.upstream_port),
            self.config.upstream_tls,
            self.config.upstream_sni.clone(),
        );
        let is_upload_path = self.is_upload_path(ctx.path.as_str());
        peer.options.connection_timeout = self.config.upstream_connect_timeout;
        peer.options.read_timeout = if is_upload_path {
            self.config
                .upload_upstream_read_timeout
                .or(self.config.upstream_read_timeout)
        } else {
            self.config.upstream_read_timeout
        };
        peer.options.write_timeout = self.config.upstream_write_timeout;
        peer.options.idle_timeout = self.config.upstream_idle_timeout;
        Ok(Box::new(peer))
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<bool> {
        self.handle_request_filter(session, ctx).await
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        self.handle_request_body_filter(body, ctx).await
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()> {
        self.handle_upstream_request_filter(session, upstream_request, ctx)
            .await
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()> {
        self.handle_response_filter(upstream_response, ctx).await
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora_core::Error,
        ctx: &mut Self::CTX,
    ) -> FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        self.handle_fail_to_proxy(session, e, ctx).await
    }

    fn request_summary(&self, _session: &Session, ctx: &Self::CTX) -> String {
        self.build_request_summary(ctx)
    }
}

fn main() {
    env_logger::init();

    install_rustls_crypto_provider().unwrap_or_else(|err| {
        eprintln!("rustls crypto provider 초기화 실패: {err}");
        process::exit(1);
    });

    let runtime_config = load_runtime_config().unwrap_or_else(|err| {
        eprintln!("{err:?}");
        process::exit(1);
    });
    run_server(EdgeProxyApp::new(runtime_config.clone()), runtime_config);
}

#[cfg(test)]
#[path = "main/tests.rs"]
mod tests;
