//! 관리자 계정, TOTP·복구 code와 영속 session 회귀 테스트입니다.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, HeaderValue};
use secrecy::SecretString;
use totp_rs::{Algorithm, Secret, TOTP};

use super::{
    AuthError, BootstrapStore, LoginRateLimiter, LoginSecondFactor, SessionStore, UiAccessPolicy,
    session_cookie,
};
use crate::auth_store::AuthRepository;

fn totp_code(secret_base32: &str, username: &str, now: i64) -> Result<String, AuthError> {
    let secret = Secret::Encoded(secret_base32.to_owned())
        .to_bytes()
        .map_err(|_| AuthError::Crypto)?;
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret,
        Some("VPSGuard".to_owned()),
        username.to_owned(),
    )
    .map_err(|_| AuthError::Crypto)?;
    let timestamp = u64::try_from(now).map_err(|_| AuthError::Clock)?;
    Ok(totp.generate(timestamp))
}

fn cookie_header(set_cookie: &str) -> &str {
    set_cookie.split(';').next().unwrap_or(set_cookie)
}

#[test]
fn account_totp_and_recovery_login_are_distinct_and_one_time()
-> Result<(), Box<dyn std::error::Error>> {
    let store = SessionStore::in_memory(60)?;
    let now = 1_784_108_000_i64;
    let password = "correct horse battery staple";
    let enrollment = store.start_enrollment(
        "g7devops".to_owned(),
        SecretString::from(password.to_owned()),
        now,
    )?;
    let code = totp_code(&enrollment.secret_base32, "g7devops", now)?;
    let completed = store.confirm_enrollment(&enrollment.enrollment_id, &code, true, now)?;
    assert_eq!(completed.recovery_codes.len(), 10);
    assert!(
        completed
            .session
            .set_cookie
            .contains("__Host-vps_guard_session")
    );
    assert!(completed.session.set_cookie.contains("; Secure"));

    let login = store.login(
        "G7DEVOPS".to_owned(),
        SecretString::from(password.to_owned()),
        LoginSecondFactor::Totp(code),
        true,
        now,
    )?;
    assert_eq!(login.actor, "g7devops");

    let recovery_code = completed
        .recovery_codes
        .first()
        .ok_or("recovery code missing")?
        .clone();
    let recovery_login = store.login(
        "g7devops".to_owned(),
        SecretString::from(password.to_owned()),
        LoginSecondFactor::RecoveryCode(recovery_code.clone()),
        true,
        now,
    )?;
    assert_eq!(
        recovery_login.authentication_method.as_str(),
        "password_recovery"
    );
    let reused = store.login(
        "g7devops".to_owned(),
        SecretString::from(password.to_owned()),
        LoginSecondFactor::RecoveryCode(recovery_code),
        true,
        now,
    );
    assert!(matches!(reused, Err(AuthError::InvalidCredentials)));

    let wrong_password = store.login(
        "g7devops".to_owned(),
        SecretString::from("wrong password with enough length".to_owned()),
        LoginSecondFactor::Totp("000000".to_owned()),
        true,
        now,
    );
    let unknown_account = store.login(
        "unknown".to_owned(),
        SecretString::from("wrong password with enough length".to_owned()),
        LoginSecondFactor::Totp("000000".to_owned()),
        true,
        now,
    );
    assert!(matches!(wrong_password, Err(AuthError::InvalidCredentials)));
    assert!(matches!(
        unknown_account,
        Err(AuthError::InvalidCredentials)
    ));
    Ok(())
}

#[test]
fn auth_database_contains_no_plaintext_password_totp_recovery_or_session_secret()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("control.sqlite3");
    let repository = Arc::new(AuthRepository::open(&database)?);
    let store = SessionStore::new(repository, 10)?;
    let now = super::unix_seconds()?;
    let password = "database plaintext sentinel password";
    let enrollment = store.start_enrollment(
        "secret.scan".to_owned(),
        SecretString::from(password.to_owned()),
        now,
    )?;
    let totp_secret = enrollment.secret_base32.clone();
    let code = totp_code(&totp_secret, "secret.scan", now)?;
    let completed = store.confirm_enrollment(&enrollment.enrollment_id, &code, false, now)?;
    let recovery = completed
        .recovery_codes
        .first()
        .ok_or("recovery code missing")?
        .clone();
    let raw_session = cookie_header(&completed.session.set_cookie)
        .split_once('=')
        .map(|(_, value)| value)
        .ok_or("session cookie malformed")?
        .to_owned();
    drop(store);

    let mut persisted = std::fs::read(&database)?;
    let wal = database.with_file_name("control.sqlite3-wal");
    if wal.exists() {
        persisted.extend(std::fs::read(wal)?);
    }
    let text = String::from_utf8_lossy(&persisted);
    for secret in [password, &totp_secret, &recovery, &raw_session] {
        assert!(!text.contains(secret));
    }
    Ok(())
}

#[test]
fn session_survives_control_restart_without_persisting_cookie_or_csrf_plaintext()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("control.sqlite3");
    let issued = {
        let repository = Arc::new(AuthRepository::open(&database)?);
        let store = SessionStore::new(repository, 10)?;
        store.issue_break_glass(false, super::unix_seconds()?)?
    };
    let raw_cookie = cookie_header(&issued.set_cookie).to_owned();
    let repository = Arc::new(AuthRepository::open(&database)?);
    let restarted = SessionStore::new(repository, 10)?;
    let mut headers = HeaderMap::new();
    headers.insert("cookie", HeaderValue::from_str(&raw_cookie)?);
    let (csrf, identity) = restarted.resume(&headers)?.ok_or("session missing")?;
    assert_eq!(csrf, issued.csrf_token);
    assert_eq!(identity.actor, "break-glass");

    let database_bytes = std::fs::read(&database)?;
    let database_text = String::from_utf8_lossy(&database_bytes);
    assert!(!database_text.contains(raw_cookie.split('=').nth(1).unwrap_or_default()));
    assert!(!database_text.contains(&issued.csrf_token));
    Ok(())
}

#[test]
fn session_requires_matching_csrf_and_logout_revokes_it() -> Result<(), Box<dyn std::error::Error>>
{
    let store = SessionStore::in_memory(10)?;
    let issued = store.issue_break_glass(false, super::unix_seconds()?)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        "cookie",
        HeaderValue::from_str(cookie_header(&issued.set_cookie))?,
    );
    assert!(store.authenticate(&headers)?.is_some());
    assert!(store.authorize(&headers)?.is_none());
    headers.insert("x-csrf-token", HeaderValue::from_str(&issued.csrf_token)?);
    assert!(store.authorize(&headers)?.is_some());
    assert!(store.logout(&headers, false)?.is_some());
    assert!(store.authenticate(&headers)?.is_none());
    Ok(())
}

#[test]
fn login_limiter_is_bounded_and_recovers_after_window() {
    let limiter = LoginRateLimiter::new(2);
    let start = Instant::now();
    assert!(limiter.allow_at(start));
    assert!(limiter.allow_at(start + Duration::from_secs(1)));
    assert!(!limiter.allow_at(start + Duration::from_secs(2)));
    assert!(limiter.allow_at(start + Duration::from_secs(61)));
}

#[test]
fn login_code_is_single_use_and_wrong_attempt_does_not_destroy_it()
-> Result<(), Box<dyn std::error::Error>> {
    let store = BootstrapStore::new();
    let issued = store
        .issue(Duration::from_secs(300))
        .ok_or("code issue failed")?;
    assert!(!store.consume("wrong-code"));
    assert!(store.consume(&issued.code));
    assert!(!store.consume(&issued.code));
    Ok(())
}

#[test]
fn public_ui_policy_requires_exact_host_and_origin() -> Result<(), Box<dyn std::error::Error>> {
    let config = guard_core::config::UiConfig {
        bind: "127.0.0.1:7727".parse()?,
        public_host: Some("guard.example.com".to_owned()),
        admin_socket: "/tmp/admin.sock".into(),
        login_rate_limit_rpm: 10,
        language: "ko".to_owned(),
    };
    let policy = UiAccessPolicy::from_config(&config);
    assert!(policy.accepts_host(Some("guard.example.com:443")));
    assert!(!policy.accepts_host(Some("example.com")));
    let mut headers = HeaderMap::new();
    headers.insert(
        "origin",
        HeaderValue::from_static("https://guard.example.com"),
    );
    assert!(policy.accepts_origin(&headers));
    headers.insert("origin", HeaderValue::from_static("https://evil.example"));
    assert!(!policy.accepts_origin(&headers));
    Ok(())
}

#[test]
fn cookie_builder_keeps_host_prefix_and_strict_attributes() {
    let cookie = session_cookie("opaque", true);
    assert!(cookie.starts_with("__Host-vps_guard_session=opaque"));
    assert!(cookie.contains("Path=/"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Strict"));
    assert!(cookie.contains("Secure"));
}
