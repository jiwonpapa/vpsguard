//! Edge runtime 설정 불변조건 회귀 테스트입니다.

use guard_core::GuardConfig;
use guard_core::config::InspectionMode;

use super::{EdgeRuntimeConfig, RouteClassSource, UpstreamKind};
use crate::rate_limit::RouteClass;

#[test]
fn observe_mode_never_enables_common_rate_limits() -> Result<(), Box<dyn std::error::Error>> {
    let config = GuardConfig::from_toml(include_str!("../../../../configs/vps-guard.smoke.toml"))?;
    let runtime = EdgeRuntimeConfig::try_from_guard(&config)?;

    assert!(!runtime.enforces_common_protection());
    assert_eq!(runtime.rate_limit(RouteClass::General), None);
    assert_eq!(runtime.rate_limit(RouteClass::Strict), None);
    assert_eq!(runtime.rate_limit(RouteClass::Upload), None);
    assert_eq!(runtime.authentication_rate_limit(), None);
    assert_eq!(runtime.worker_threads, None);
    assert_eq!(runtime.max_in_flight_requests, 1_024);
    assert_eq!(runtime.downstream_io_timeout.as_millis(), 30_000);
    assert_eq!(runtime.downstream_min_send_rate_bps, 1_024);
    assert_eq!(runtime.keepalive_request_limit, 1_000);
    Ok(())
}

#[test]
fn protocol_only_skips_application_profile_but_enforces_common_protection()
-> Result<(), Box<dyn std::error::Error>> {
    let source = include_str!("../../../../configs/vps-guard.smoke.toml")
        .replace(
            "inspection = \"profiled\"",
            "inspection = \"protocol_only\"",
        )
        .replace("mode = \"observe\"", "mode = \"enforce\"");
    let config = GuardConfig::from_toml(&source)?;
    let runtime = EdgeRuntimeConfig::try_from_guard(&config)?;
    let auth = runtime.effective_route_profile(
        UpstreamKind::Application,
        "/api/auth/login",
        "/api/auth/login?next=%2Fadmin",
    );

    assert_eq!(runtime.inspection_mode, InspectionMode::ProtocolOnly);
    assert!(runtime.enforces_common_protection());
    assert_eq!(runtime.rate_limit(RouteClass::General), Some(2));
    assert_eq!(runtime.rate_limit(RouteClass::Strict), Some(1));
    assert_eq!(runtime.rate_limit(RouteClass::Upload), Some(1));
    assert_eq!(runtime.authentication_rate_limit(), None);
    assert_eq!(auth.route_class, RouteClass::General);
    assert_eq!(auth.normalized_route, "/api/auth/login");
    assert_eq!(auth.base_cost, 1);
    assert_eq!(auth.source, RouteClassSource::CoreDefault);
    assert!(!auth.authentication_route);
    Ok(())
}

#[test]
fn gnuboard7_profile_strengthens_auth_and_upload_routes() -> Result<(), Box<dyn std::error::Error>>
{
    let config = GuardConfig::from_toml(include_str!("../../../../configs/vps-guard.smoke.toml"))?;
    let runtime = EdgeRuntimeConfig::try_from_guard(&config)?;

    let auth = runtime.effective_route_profile(
        UpstreamKind::Application,
        "/api/auth/login",
        "/api/auth/login",
    );
    assert_eq!(auth.route_class, RouteClass::Strict);
    assert_eq!(auth.source, RouteClassSource::ApplicationProfile);
    assert!(auth.authentication_route);

    let upload = runtime.effective_route_profile(
        UpstreamKind::Application,
        "/api/me/avatar",
        "/api/me/avatar",
    );
    assert_eq!(upload.route_class, RouteClass::Upload);
    assert_eq!(upload.source, RouteClassSource::ApplicationProfile);
    Ok(())
}

#[test]
fn enforce_mode_applies_auth_limit_only_to_profiled_authentication()
-> Result<(), Box<dyn std::error::Error>> {
    let source = include_str!("../../../../configs/vps-guard.smoke.toml")
        .replace("mode = \"observe\"", "mode = \"enforce\"");
    let config = GuardConfig::from_toml(&source)?;
    let runtime = EdgeRuntimeConfig::try_from_guard(&config)?;
    let auth = runtime.effective_route_profile(
        UpstreamKind::Application,
        "/api/auth/login",
        "/api/auth/login",
    );
    let search = runtime.effective_route_profile(
        UpstreamKind::Application,
        "/api/search",
        "/api/search?q=secret",
    );

    assert_eq!(runtime.authentication_rate_limit(), Some(2));
    assert!(auth.authentication_route);
    assert!(!search.authentication_route);
    Ok(())
}

#[test]
fn explicit_site_prefix_overrides_application_default() -> Result<(), Box<dyn std::error::Error>> {
    let config = GuardConfig::from_toml(include_str!("../../../../configs/vps-guard.smoke.toml"))?;
    let runtime = EdgeRuntimeConfig::try_from_guard(&config)?;
    let route = runtime.effective_route_profile(
        UpstreamKind::Application,
        "/search/custom",
        "/search/custom",
    );
    assert_eq!(route.route_class, RouteClass::Strict);
    assert_eq!(route.source, RouteClassSource::SiteStrictOverride);
    Ok(())
}

#[test]
fn wordpress_xmlrpc_uses_strict_application_layer() -> Result<(), Box<dyn std::error::Error>> {
    let source = include_str!("../../../../configs/vps-guard.smoke.toml")
        .replace("profile = \"gnuboard7\"", "profile = \"wordpress\"");
    let config = GuardConfig::from_toml(&source)?;
    let runtime = EdgeRuntimeConfig::try_from_guard(&config)?;
    let route =
        runtime.effective_route_profile(UpstreamKind::Application, "/xmlrpc.php", "/xmlrpc.php");
    assert_eq!(route.route_class, RouteClass::Strict);
    assert_eq!(route.source, RouteClassSource::ApplicationProfile);
    Ok(())
}

#[test]
fn management_host_selects_control_without_canonical_redirect_semantics()
-> Result<(), Box<dyn std::error::Error>> {
    let source = include_str!("../../../../configs/vps-guard.smoke.toml")
        .replace(
            "http_bind = \"127.0.0.1:18080\"",
            "http_bind = \"127.0.0.1:18080\"\nhttps_bind = \"127.0.0.1:18443\"",
        )
        .replace(
            "[tls]\ncertificates = []",
            "[tls]\n[[tls.certificates]]\ndomains = [\"guard.example.test\"]\ncert_file = \"/tmp/cert.pem\"\nkey_file = \"/tmp/key.pem\"",
        )
        .replace(
            "bind = \"127.0.0.1:17727\"",
            "bind = \"127.0.0.1:17727\"\npublic_host = \"guard.example.test\"",
        );
    let config = GuardConfig::from_toml(&source)?;
    let runtime = EdgeRuntimeConfig::try_from_guard(&config)?;

    assert_eq!(
        runtime.upstream_kind(Some("guard.example.test:443")),
        UpstreamKind::Management
    );
    assert_eq!(
        runtime.upstream_kind(Some("example.test")),
        UpstreamKind::Application
    );
    let login = runtime.effective_route_profile(
        UpstreamKind::Management,
        "/api/v1/session",
        "/api/v1/session",
    );
    assert_eq!(login.source, RouteClassSource::ManagementAuth);
    assert_eq!(login.route_class, RouteClass::ManagementAuth);
    assert_eq!(
        runtime.management_login_rate_limit("POST", "/api/v1/session"),
        Some(10)
    );
    assert_eq!(
        runtime.management_login_rate_limit("GET", "/api/v1/session"),
        None
    );
    Ok(())
}
