//! HTTP redirect와 ACME 예외 회귀 테스트입니다.

use super::https_redirect_location;

#[test]
fn redirects_plain_http_to_canonical_https() {
    assert_eq!(
        https_redirect_location(
            true,
            false,
            Some("www.example.com"),
            "example.com:80",
            "/board?page=1",
        ),
        Some("https://www.example.com/board?page=1".to_owned())
    );
}

#[test]
fn keeps_https_and_http01_challenge_on_the_current_listener() {
    assert_eq!(
        https_redirect_location(true, true, None, "example.com", "/"),
        None
    );
    assert_eq!(
        https_redirect_location(
            true,
            false,
            None,
            "example.com",
            "/.well-known/acme-challenge/token",
        ),
        None
    );
}
