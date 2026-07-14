//! 애플리케이션 profile 회귀 테스트입니다.

use super::{ApplicationProfile, RouteKind, classify};

#[test]
fn gnuboard5_search_is_expensive_and_query_is_removed() {
    let route = classify(
        ApplicationProfile::Gnuboard5,
        "/bbs/search.php?stx=secret&page=99",
    );
    assert_eq!(route.normalized_route, "/bbs/search.php");
    assert_eq!(route.kind, RouteKind::Search);
    assert_eq!(route.base_cost, 10);
}

#[test]
fn gnuboard5_admin_and_write_paths_keep_legacy_semantics() {
    assert_eq!(
        classify(ApplicationProfile::Gnuboard5, "/adm/config_form.php").kind,
        RouteKind::Admin
    );
    assert_eq!(
        classify(ApplicationProfile::Gnuboard5, "/bbs/write_update.php").kind,
        RouteKind::Write
    );
}

#[test]
fn gnuboard7_api_auth_admin_search_and_upload_are_distinct() {
    assert_eq!(
        classify(ApplicationProfile::Gnuboard7, "/api/auth/login").kind,
        RouteKind::Authentication
    );
    assert_eq!(
        classify(ApplicationProfile::Gnuboard7, "/api/admin/modules/install").kind,
        RouteKind::Admin
    );
    assert_eq!(
        classify(ApplicationProfile::Gnuboard7, "/api/search?q=private").kind,
        RouteKind::Search
    );
    assert_eq!(
        classify(ApplicationProfile::Gnuboard7, "/api/me/avatar").kind,
        RouteKind::Upload
    );
}

#[test]
fn gnuboard7_does_not_apply_gnuboard5_adm_rules() {
    assert_eq!(
        classify(ApplicationProfile::Gnuboard7, "/adm/config_form.php").kind,
        RouteKind::Dynamic
    );
}

#[test]
fn generic_php_profile_keeps_dynamic_entrypoints_visible() {
    let route = classify(ApplicationProfile::Php, "/custom/report.php?id=123");
    assert_eq!(route.kind, RouteKind::Dynamic);
    assert_eq!(route.normalized_route, "/custom/report.php");
}

#[test]
fn wordpress_xmlrpc_is_remote_procedure_cost() {
    let route = classify(ApplicationProfile::Wordpress, "/xmlrpc.php");
    assert_eq!(route.kind, RouteKind::RemoteProcedure);
    assert_eq!(route.base_cost, 15);
}

#[test]
fn ids_are_bounded_in_route_key() {
    let route = classify(
        ApplicationProfile::Wordpress,
        "/posts/123/550e8400-e29b-41d4-a716-446655440000",
    );
    assert_eq!(route.normalized_route, "/posts/:id/:id");
}

#[test]
fn static_asset_is_low_cost() {
    let route = classify(ApplicationProfile::Gnuboard5, "/theme/app/main.CSS?v=2");
    assert_eq!(route.kind, RouteKind::Static);
    assert_eq!(route.base_cost, 1);
}
