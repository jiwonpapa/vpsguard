//! Direct edge response header regression tests.

use super::{build_redirect_header, build_text_header};

#[test]
fn text_header_contains_length_retry_and_correlation() -> Result<(), Box<dyn std::error::Error>> {
    let response = build_text_header(
        429,
        12,
        "vpg-0123456789abcdef-0000000000000001",
        Some(60),
        &[("allow", "GET, HEAD".to_owned())],
    )?;

    assert_eq!(response.status.as_u16(), 429);
    assert_eq!(response.headers["content-length"], "12");
    assert_eq!(response.headers["retry-after"], "60");
    assert_eq!(response.headers["allow"], "GET, HEAD");
    assert_eq!(response.headers["x-vps-guard"], "guard-edge");
    assert_eq!(
        response.headers["x-request-id"],
        "vpg-0123456789abcdef-0000000000000001"
    );
    Ok(())
}

#[test]
fn redirect_header_has_no_body_and_preserves_location() -> Result<(), Box<dyn std::error::Error>> {
    let response = build_redirect_header(
        "https://example.com/path",
        "vpg-0123456789abcdef-0000000000000002",
    )?;

    assert_eq!(response.status.as_u16(), 308);
    assert_eq!(response.headers["location"], "https://example.com/path");
    assert_eq!(response.headers["content-length"], "0");
    Ok(())
}

#[test]
fn text_header_omits_retry_when_no_retry_is_requested() -> Result<(), Box<dyn std::error::Error>> {
    let response = build_text_header(400, 3, "vpg-0123456789abcdef-0000000000000003", None, &[])?;

    assert_eq!(response.status.as_u16(), 400);
    assert!(!response.headers.contains_key("retry-after"));
    assert_eq!(
        response.headers["content-type"],
        "text/plain; charset=utf-8"
    );
    Ok(())
}
