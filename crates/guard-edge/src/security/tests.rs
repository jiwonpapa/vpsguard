//! Response 보안 policy 회귀 테스트입니다.

use guard_core::config::{CspMode, InspectionMode, SecurityConfig};
use guard_profiles::ApplicationProfile;
use pingora_http::{RequestHeader, ResponseHeader};

use super::{FramingViolation, ResponseSecurityPolicy, rejects_method, validate_request_framing};

#[test]
fn applies_g7_report_only_headers_without_weakening_origin_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityConfig {
        hsts_max_age_seconds: 86_400,
        ..SecurityConfig::default()
    };
    let policy = ResponseSecurityPolicy::from_config(
        &config,
        InspectionMode::Profiled,
        ApplicationProfile::Gnuboard7,
    );
    let mut response = ResponseHeader::build(200, Some(8))?;
    response.insert_header("server", "origin/1.0")?;
    response.insert_header("x-powered-by", "PHP/8.3")?;
    response.insert_header("referrer-policy", "no-referrer")?;

    policy.apply(&mut response, true)?;

    assert!(!response.headers.contains_key("server"));
    assert!(!response.headers.contains_key("x-powered-by"));
    assert_eq!(response.headers["x-content-type-options"], "nosniff");
    assert_eq!(response.headers["referrer-policy"], "no-referrer");
    assert_eq!(
        response.headers["strict-transport-security"],
        "max-age=86400"
    );
    let csp = response.headers["content-security-policy-report-only"].to_str()?;
    assert!(csp.contains("script-src 'self'"));
    assert!(!csp.contains("script-src 'self' 'unsafe-inline'"));
    Ok(())
}

#[test]
fn protocol_only_keeps_baseline_but_skips_app_csp() -> Result<(), Box<dyn std::error::Error>> {
    let policy = ResponseSecurityPolicy::from_config(
        &SecurityConfig::default(),
        InspectionMode::ProtocolOnly,
        ApplicationProfile::Gnuboard7,
    );
    let mut response = ResponseHeader::build(200, Some(4))?;
    policy.apply(&mut response, false)?;
    assert_eq!(response.headers["x-content-type-options"], "nosniff");
    assert!(
        !response
            .headers
            .contains_key("content-security-policy-report-only")
    );
    assert!(!response.headers.contains_key("strict-transport-security"));
    Ok(())
}

#[test]
fn enforce_uses_site_policy_and_dangerous_methods_are_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityConfig {
        csp_mode: CspMode::Enforce,
        csp_policy: Some("default-src 'none'".to_owned()),
        ..SecurityConfig::default()
    };
    let policy = ResponseSecurityPolicy::from_config(
        &config,
        InspectionMode::Profiled,
        ApplicationProfile::Php,
    );
    let mut response = ResponseHeader::build(200, Some(4))?;
    policy.apply(&mut response, false)?;
    assert_eq!(
        response.headers["content-security-policy"],
        "default-src 'none'"
    );
    assert!(rejects_method("TRACE"));
    assert!(rejects_method("track"));
    assert!(rejects_method("Connect"));
    assert!(!rejects_method("GET"));
    assert!(!rejects_method("OPTIONS"));
    Ok(())
}

#[test]
fn rejects_ambiguous_request_framing_before_origin() -> Result<(), Box<dyn std::error::Error>> {
    let mut duplicate_host = RequestHeader::build("POST", b"/", Some(4))?;
    duplicate_host.append_header("host", "example.test")?;
    duplicate_host.append_header("host", "evil.test")?;
    assert_eq!(
        validate_request_framing(&[], &duplicate_host),
        Err(FramingViolation::DuplicateHost)
    );

    let mut duplicate_length = RequestHeader::build("POST", b"/", Some(4))?;
    duplicate_length.append_header("content-length", "4")?;
    duplicate_length.append_header("content-length", "5")?;
    assert_eq!(
        validate_request_framing(&[], &duplicate_length),
        Err(FramingViolation::DuplicateContentLength)
    );

    let mut conflicting = RequestHeader::build("POST", b"/", Some(4))?;
    conflicting.insert_header("content-length", "4")?;
    conflicting.insert_header("transfer-encoding", "chunked")?;
    assert_eq!(
        validate_request_framing(&[], &conflicting),
        Err(FramingViolation::ConflictingLengthSignals)
    );

    let mut invalid_te = RequestHeader::build("POST", b"/", Some(4))?;
    invalid_te.insert_header("transfer-encoding", "gzip, chunked")?;
    assert_eq!(
        validate_request_framing(&[], &invalid_te),
        Err(FramingViolation::InvalidTransferEncoding)
    );

    let mut valid = RequestHeader::build("POST", b"/", Some(2))?;
    valid.insert_header("host", "example.test")?;
    valid.insert_header("content-length", "4")?;
    assert_eq!(validate_request_framing(&[], &valid), Ok(()));

    let mut pingora_normalized = RequestHeader::build("POST", b"/", Some(2))?;
    pingora_normalized.insert_header("host", "example.test")?;
    pingora_normalized.insert_header("transfer-encoding", "chunked")?;
    let raw = b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert_eq!(
        validate_request_framing(raw, &pingora_normalized),
        Err(FramingViolation::ConflictingLengthSignals)
    );
    Ok(())
}
