//! 관리자 계정, TOTP·복구 code와 영속 session 회귀 테스트입니다.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use totp_rs::{Algorithm, Secret, TOTP};

use super::{
    AccountAuthenticator, AuthError, BootstrapStore, LoginRateLimiter, LoginSecondFactor,
    SessionStore, UiAccessPolicy, session_cookie,
};
use crate::auth_store::AuthRepository;
use crate::pam_auth::{
    PamAuthError, PamAuthenticator, PamCredentials, PamIdentity, PamPasswordCredentials,
};
use crate::pam_mfa::{PamMfaEnrollmentComplete, PamMfaEnrollmentStart, PamMfaMethod};

#[derive(Default)]
struct FakePam {
    configured: Mutex<bool>,
}

impl PamAuthenticator for FakePam {
    fn setup_required(&self) -> Result<bool, PamAuthError> {
        Ok(!*self
            .configured
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    fn start_enrollment(
        &self,
        credentials: PamPasswordCredentials,
        _now: i64,
    ) -> Result<PamMfaEnrollmentStart, PamAuthError> {
        if credentials.username != "operator"
            || credentials.password.expose_secret() != "server-password"
        {
            return Err(PamAuthError::InvalidCredentials);
        }
        Ok(PamMfaEnrollmentStart {
            enrollment_id: "fake-enrollment".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            otpauth_uri: "otpauth://totp/VPSGuard:operator".to_owned(),
            expires_in_seconds: 600,
        })
    }

    fn confirm_enrollment(
        &self,
        enrollment_id: &str,
        totp_code: &str,
        _now: i64,
    ) -> Result<PamMfaEnrollmentComplete, PamAuthError> {
        if enrollment_id != "fake-enrollment" || totp_code != "123456" {
            return Err(PamAuthError::InvalidTotp);
        }
        *self
            .configured
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        Ok(PamMfaEnrollmentComplete {
            actor: "operator".to_owned(),
            recovery_codes: vec!["AAAAAAAA-BBBBBBBB-CCCCCCCC-DDDDDDDD".to_owned()],
        })
    }

    fn authenticate(&self, credentials: PamCredentials) -> Result<PamIdentity, PamAuthError> {
        if !self.setup_required()?
            && credentials.username == "operator"
            && credentials.password.expose_secret() == "server-password"
            && credentials.second_factor.expose_secret() == "123456"
        {
            Ok(PamIdentity {
                actor: credentials.username,
                mfa_method: PamMfaMethod::Totp,
            })
        } else {
            Err(PamAuthError::InvalidCredentials)
        }
    }
}

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
fn pam_login_issues_session_without_a_local_password_verifier()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = Arc::new(AuthRepository::in_memory()?);
    let pam = Arc::new(FakePam::default());
    let store = SessionStore::with_authenticator(
        Arc::clone(&repository),
        10,
        AccountAuthenticator::Pam(pam),
    )?;
    let now = super::unix_seconds()?;
    assert!(store.setup_required()?);
    assert!(store.enrollment_enabled());
    let stale = store.issue_session(
        "operator".to_owned(),
        super::AuthenticationMethod::PamMfa,
        false,
        now,
    )?;
    let mut stale_headers = HeaderMap::new();
    stale_headers.insert(
        "cookie",
        HeaderValue::from_str(cookie_header(&stale.set_cookie))?,
    );
    assert!(store.authenticate(&stale_headers)?.is_none());
    let break_glass = store.issue_break_glass(false, now)?;
    let mut break_glass_headers = HeaderMap::new();
    break_glass_headers.insert(
        "cookie",
        HeaderValue::from_str(cookie_header(&break_glass.set_cookie))?,
    );
    assert!(store.authenticate(&break_glass_headers)?.is_some());
    let enrollment = store.start_enrollment(
        "operator".to_owned(),
        SecretString::from("server-password".to_owned()),
        now,
    )?;
    let complete = store.confirm_enrollment(&enrollment.enrollment_id, "123456", true, now)?;
    assert_eq!(complete.session.actor, "operator");
    assert_eq!(complete.recovery_codes.len(), 1);
    assert!(!store.setup_required()?);
    let issued = store.login(
        "operator".to_owned(),
        SecretString::from("server-password".to_owned()),
        LoginSecondFactor::Totp("123456".to_owned()),
        true,
        now,
    )?;
    assert_eq!(issued.actor, "operator");
    assert_eq!(issued.authentication_method.as_str(), "pam_mfa");
    assert!(!repository.is_configured()?);
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
        public_port: 443,
        tls_termination: guard_core::config::UiTlsTermination::Edge,
        auth_provider: guard_core::config::AdminAuthProvider::Local,
        pam_service: "vps-guard".to_owned(),
        pam_allowed_group: "vpsguard-admin".to_owned(),
        admin_socket: "/tmp/admin.sock".into(),
        privileged_socket: "/tmp/privileged.sock".into(),
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
