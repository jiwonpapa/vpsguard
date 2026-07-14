//! 애플리케이션 profile 회귀 테스트입니다.

use super::{ApplicationProfile, RouteKind, classify};

#[test]
fn gnuboard_search_is_expensive_and_query_is_removed() {
    let route = classify(
        ApplicationProfile::Gnuboard,
        "/bbs/search.php?stx=secret&page=99",
    );
    assert_eq!(route.normalized_route, "/bbs/search.php");
    assert_eq!(route.kind, RouteKind::Search);
    assert_eq!(route.base_cost, 10);
}

#[test]
fn wordpress_xmlrpc_is_api_cost() {
    let route = classify(ApplicationProfile::Wordpress, "/xmlrpc.php");
    assert_eq!(route.kind, RouteKind::Api);
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
    let route = classify(ApplicationProfile::Gnuboard, "/theme/app/main.CSS?v=2");
    assert_eq!(route.kind, RouteKind::Static);
    assert_eq!(route.base_cost, 1);
}
