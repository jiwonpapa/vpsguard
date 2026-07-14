//! Edge runtime 설정 불변조건 회귀 테스트입니다.

use guard_core::GuardConfig;

use super::{EdgeRuntimeConfig, RouteClassSource, UpstreamKind};
use crate::rate_limit::RouteClass;

#[test]
fn observe_mode_never_enables_dynamic_rate_limits() -> Result<(), Box<dyn std::error::Error>> {
    let config = GuardConfig::from_toml(include_str!("../../../../configs/vps-guard.smoke.toml"))?;
    let runtime = EdgeRuntimeConfig::try_from_guard(&config)?;

    assert!(!runtime.enforces_dynamic_protection());
    assert_eq!(runtime.rate_limit(RouteClass::General), None);
    assert_eq!(runtime.rate_limit(RouteClass::Strict), None);
    assert_eq!(runtime.rate_limit(RouteClass::Upload), None);
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
