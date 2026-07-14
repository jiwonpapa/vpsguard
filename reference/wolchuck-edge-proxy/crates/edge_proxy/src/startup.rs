use anyhow::{Context, Result};
use common::config;
use log::info;
use pingora_core::server::Server;
use pingora_core::server::configuration::Opt;
use pingora_proxy::http_proxy_service;

use crate::{EdgeProxyApp, EdgeRuntimeConfig};

pub(crate) fn install_rustls_crypto_provider() -> Result<()> {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return Ok(());
    }

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("rustls crypto provider 설치에 실패했습니다"))?;

    Ok(())
}

pub(crate) fn load_runtime_config() -> Result<EdgeRuntimeConfig> {
    let config_dir = config::find_config_dir().context("edge_proxy 설정 디렉토리 탐색 실패")?;
    let local_dir = config_dir
        .parent()
        .map(|p| p.join("configs.local"))
        .filter(|p| p.exists());

    let cfg = config::load(
        "edge_proxy",
        config_dir
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid config path"))?,
        local_dir
            .as_ref()
            .map(|p| p.to_str().context("Invalid local path"))
            .transpose()?,
    )
    .context("edge_proxy 설정 로딩 실패")?;

    if !cfg.edge_proxy.enabled {
        anyhow::bail!("edge_proxy.enabled=false 상태에서는 edge_proxy를 기동할 수 없습니다");
    }

    EdgeRuntimeConfig::try_from(cfg.edge_proxy).context("edge_proxy 런타임 설정 변환 실패")
}

pub(crate) fn run_server(app: EdgeProxyApp, runtime_config: EdgeRuntimeConfig) {
    let opt = Opt::parse_args();
    let mut server = Server::new(Some(opt)).unwrap_or_else(|err| {
        eprintln!("edge_proxy 서버 초기화 실패: {err:?}");
        std::process::exit(1);
    });
    server.bootstrap();

    let mut proxy = http_proxy_service(&server.configuration, app);
    proxy.add_tcp(&runtime_config.listen_addr);
    if let (Some(tls_addr), Some(cert_file), Some(key_file)) = (
        runtime_config.tls_listen_addr.as_deref(),
        runtime_config.tls_cert_file.as_deref(),
        runtime_config.tls_key_file.as_deref(),
    ) {
        proxy
            .add_tls(tls_addr, cert_file, key_file)
            .unwrap_or_else(|err| {
                eprintln!("edge_proxy TLS 리스너 추가 실패: {err:?}");
                std::process::exit(1);
            });
    }

    info!(
        "Starting edge_proxy http_listener={} tls_listener={:?} -> {}:{} (upstream_tls={} allowed_hosts={} passthrough_hosts={} canonical_host={:?} trusted_proxies={} admin_rules={} blocked_rules={} admin_paths={} upload_paths={} thumb_paths={} strict_rate_limit_paths={} gone_paths={} max_body_bytes={:?} upload_max_body_bytes={:?} downstream_read_timeout={:?} upload_downstream_read_timeout={:?} upstream_connect_timeout={:?} upstream_read_timeout={:?} upload_upstream_read_timeout={:?} rate_limit_rpm={:?} upload_rate_limit_rpm={:?} thumb_rate_limit_rpm={:?} strict_rate_limit_rpm={:?})",
        runtime_config.listen_addr,
        runtime_config.tls_listen_addr,
        runtime_config.upstream_host,
        runtime_config.upstream_port,
        runtime_config.upstream_tls,
        runtime_config.allowed_hosts.len(),
        runtime_config.passthrough_hosts.len(),
        runtime_config.canonical_host,
        runtime_config.trusted_proxy_rules.len(),
        runtime_config.admin_allowed_rules.len(),
        runtime_config.blocked_rules.len(),
        runtime_config.admin_path_prefixes.len(),
        runtime_config.upload_path_prefixes.len(),
        runtime_config.thumb_path_prefixes.len(),
        runtime_config.strict_rate_limit_path_prefixes.len(),
        runtime_config.gone_paths.len(),
        runtime_config.max_body_bytes,
        runtime_config.upload_max_body_bytes,
        runtime_config.downstream_read_timeout,
        runtime_config.upload_downstream_read_timeout,
        runtime_config.upstream_connect_timeout,
        runtime_config.upstream_read_timeout,
        runtime_config.upload_upstream_read_timeout,
        runtime_config.rate_limit_requests_per_minute,
        runtime_config.upload_rate_limit_requests_per_minute,
        runtime_config.thumb_rate_limit_requests_per_minute,
        runtime_config.strict_rate_limit_requests_per_minute
    );

    server.add_service(proxy);
    server.run_forever();
}
