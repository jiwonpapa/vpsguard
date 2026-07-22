//! 전용 관리자 계정, TOTP·복구 코드와 hash-only 영속 session을 제공합니다.

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Argon2, Params};
use axum::http::HeaderMap;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use guard_core::config::{AdminAuthProvider, UiConfig};
use hmac::{Hmac, Mac};
use secrecy::zeroize::Zeroize;
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use serde::Serialize;
use sha2::Sha256;
use thiserror::Error;
use totp_rs::{Algorithm, TOTP};

use crate::auth_store::{
    AuthRepository, AuthStoreError, NewAdminAccount, NewStoredSession, StoredAdminAccount,
};
use crate::pam_auth::{PamAuthenticator, PamCredentials, privileged_authenticator};

const SESSION_COOKIE: &str = "vps_guard_session";
const SECURE_SESSION_COOKIE: &str = "__Host-vps_guard_session";
const SESSION_TTL_SECONDS: i64 = 12 * 60 * 60;
const ENROLLMENT_TTL_SECONDS: i64 = 10 * 60;
const LOGIN_CODE_CONTEXT: &[u8] = b"vpsguard-login-code-v1";
const SESSION_CONTEXT: &[u8] = b"vpsguard-session-v2";
const CSRF_TOKEN_CONTEXT: &[u8] = b"vpsguard-csrf-token-v2";
const CSRF_STORE_CONTEXT: &[u8] = b"vpsguard-csrf-store-v2";
const RECOVERY_CODE_CONTEXT: &[u8] = b"vpsguard-recovery-code-v1";
const ENROLLMENT_CONTEXT: &[u8] = b"vpsguard-enrollment-v1";
const RECOVERY_CODE_COUNT: usize = 10;
const PASSWORD_MIN_CHARS: usize = 12;
const PASSWORD_MAX_BYTES: usize = 1_024;
const TOTP_SECRET_BYTES: usize = 20;
const TOTP_KDF_SALT_BYTES: usize = 16;
const TOTP_NONCE_BYTES: usize = 24;

type HmacSha256 = Hmac<Sha256>;

/// 관리자 인증·암호·저장 실패입니다.
#[derive(Debug, Error)]
pub enum AuthError {
    /// 인증 저장소 실패입니다.
    #[error(transparent)]
    Store(#[from] AuthStoreError),
    /// 관리자 ID 형식이 잘못됐습니다.
    #[error("관리자 ID는 영문·숫자로 시작하는 3~32자의 영문·숫자·점·밑줄·하이픈이어야 합니다")]
    InvalidUsername,
    /// 비밀번호 길이 정책을 충족하지 못했습니다.
    #[error("비밀번호는 12자 이상 1,024 byte 이하여야 합니다")]
    WeakPassword,
    /// 이미 최초 관리자가 등록됐습니다.
    #[error("관리자 계정이 이미 등록됐습니다")]
    AlreadyConfigured,
    /// 등록 session이 없거나 만료됐습니다.
    #[error("관리자 등록 session이 없거나 만료됐습니다")]
    EnrollmentUnavailable,
    /// 선택한 provider가 VPSGuard password 등록을 사용하지 않습니다.
    #[error("PAM mode에서는 VPSGuard password 등록을 사용하지 않습니다")]
    EnrollmentDisabled,
    /// TOTP code 형식 또는 값이 잘못됐습니다.
    #[error("2단계 인증 code가 올바르지 않습니다")]
    InvalidTotp,
    /// ID, 비밀번호 또는 2단계 인증값이 일치하지 않습니다.
    #[error("관리자 인증 정보가 올바르지 않습니다")]
    InvalidCredentials,
    /// 로그인 시도 한도를 초과했습니다.
    #[error("관리자 로그인 시도 한도를 초과했습니다")]
    RateLimited,
    /// 암호 연산 또는 CSPRNG가 실패했습니다.
    #[error("관리자 인증 암호 연산에 실패했습니다")]
    Crypto,
    /// system clock을 UNIX timestamp로 변환하지 못했습니다.
    #[error("관리자 인증 system clock이 올바르지 않습니다")]
    Clock,
    /// PAM credential·계정·group 검증 실패입니다.
    #[error("Linux-PAM 인증 또는 계정 검증에 실패했습니다")]
    Pam,
}

/// 새로 만든 단회 로그인 코드입니다.
///
/// 원문 code를 포함하므로 의도적인 로그 출력을 막기 위해 `Debug`를 구현하지 않습니다.
pub(crate) struct IssuedLoginCode {
    pub(crate) code: String,
    pub(crate) expires_in_seconds: u64,
}

struct LoginCredential {
    digest: [u8; 32],
    expires_at: SystemTime,
}

/// memory에 원문을 보관하지 않는 단회 로그인 code 저장소입니다.
pub(crate) struct BootstrapStore {
    credential: Mutex<Option<LoginCredential>>,
}

impl BootstrapStore {
    /// 비어 있는 저장소를 만듭니다.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            credential: Mutex::new(None),
        }
    }

    /// 기존 code를 폐기하고 새 code를 발급합니다.
    pub(crate) fn issue(&self, ttl: Duration) -> Option<IssuedLoginCode> {
        let code = random_hex_token().ok()?;
        let digest = keyed_digest(LOGIN_CODE_CONTEXT, code.as_bytes()).ok()?;
        *self.lock_credential() = Some(LoginCredential {
            digest,
            expires_at: SystemTime::now() + ttl,
        });
        Some(IssuedLoginCode {
            code,
            expires_in_seconds: ttl.as_secs(),
        })
    }

    /// 일치하는 code만 한 번 소비하며 원격 오입력만으로 정상 code를 폐기하지 않습니다.
    pub(crate) fn consume(&self, candidate: &str) -> bool {
        self.consume_at(candidate, SystemTime::now())
    }

    fn consume_at(&self, candidate: &str, now: SystemTime) -> bool {
        let mut slot = self.lock_credential();
        let Some(credential) = slot.as_mut() else {
            return false;
        };
        if credential.expires_at <= now {
            *slot = None;
            return false;
        }
        let Ok(mut mac) = <HmacSha256 as Mac>::new_from_slice(LOGIN_CODE_CONTEXT) else {
            *slot = None;
            return false;
        };
        mac.update(candidate.as_bytes());
        if mac.verify_slice(&credential.digest).is_ok() {
            *slot = None;
            return true;
        }
        false
    }

    fn lock_credential(&self) -> MutexGuard<'_, Option<LoginCredential>> {
        self.credential
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// 관리 listener가 수락할 Host·Origin과 cookie transport 정책입니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UiAccessPolicy {
    expected_host: String,
    allowed_origin: String,
    secure_cookie: bool,
}

impl UiAccessPolicy {
    /// 검증된 UI 설정에서 public 또는 loopback 접근 정책을 만듭니다.
    #[must_use]
    pub(crate) fn from_config(config: &UiConfig) -> Self {
        config.public_host.as_ref().map_or_else(
            || Self {
                expected_host: config.bind.to_string(),
                allowed_origin: format!("http://{}", config.bind),
                secure_cookie: false,
            },
            |host| Self {
                expected_host: host.to_ascii_lowercase(),
                allowed_origin: if config.public_port == 443 {
                    format!("https://{}", host.to_ascii_lowercase())
                } else {
                    format!(
                        "https://{}:{}",
                        host.to_ascii_lowercase(),
                        config.public_port
                    )
                },
                secure_cookie: true,
            },
        )
    }

    /// request Host가 유일하게 설정된 관리 authority인지 확인합니다.
    pub(crate) fn accepts_host(&self, candidate: Option<&str>) -> bool {
        let Some(candidate) = candidate.map(str::trim) else {
            return false;
        };
        if self.secure_cookie {
            candidate
                .split(':')
                .next()
                .map(|host| host.trim_end_matches('.'))
                .is_some_and(|host| host.eq_ignore_ascii_case(&self.expected_host))
        } else {
            candidate.eq_ignore_ascii_case(&self.expected_host)
        }
    }

    /// state-changing request의 browser Origin을 정확히 확인합니다.
    pub(crate) fn accepts_origin(&self, headers: &HeaderMap) -> bool {
        headers
            .get("origin")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value == self.allowed_origin)
    }

    /// session cookie에 Secure를 붙여야 하는지 반환합니다.
    pub(crate) const fn secure_cookie(&self) -> bool {
        self.secure_cookie
    }
}

/// 운영 session을 발급한 인증 방법입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AuthenticationMethod {
    /// 관리자 비밀번호와 TOTP를 모두 확인했습니다.
    PasswordTotp,
    /// 관리자 비밀번호와 일회용 복구 코드를 확인했습니다.
    PasswordRecovery,
    /// Linux-PAM password와 PAM stack의 두 번째 factor를 확인했습니다.
    PamMfa,
    /// root local 단회 code를 사용한 break-glass session입니다.
    BreakGlass,
}

impl AuthenticationMethod {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::PasswordTotp => "password_totp",
            Self::PasswordRecovery => "password_recovery",
            Self::PamMfa => "pam_mfa",
            Self::BreakGlass => "break_glass",
        }
    }
}

/// session cookie와 CSRF 원문을 포함하는 발급 결과입니다.
///
/// 원문 credential의 우발적 로그 출력을 막기 위해 `Debug`를 구현하지 않습니다.
pub(crate) struct IssuedSession {
    pub(crate) csrf_token: String,
    pub(crate) set_cookie: String,
    pub(crate) expires_in_seconds: u64,
    pub(crate) actor: String,
    pub(crate) authentication_method: AuthenticationMethod,
}

/// 검증된 session의 actor와 인증 방법입니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionIdentity {
    pub(crate) actor: String,
    pub(crate) authentication_method: String,
    pub(crate) expires_in_seconds: u64,
}

/// 최초 TOTP 등록을 위해 한 번만 화면에 반환하는 자료입니다.
///
/// TOTP 원문을 포함하므로 `Debug`를 구현하지 않습니다.
pub(crate) struct EnrollmentStart {
    pub(crate) enrollment_id: String,
    pub(crate) secret_base32: String,
    pub(crate) otpauth_uri: String,
    pub(crate) expires_in_seconds: u64,
}

/// 최초 등록 완료와 함께 한 번만 반환하는 복구 code와 session입니다.
///
/// 원문 credential을 포함하므로 `Debug`를 구현하지 않습니다.
pub(crate) struct EnrollmentComplete {
    pub(crate) recovery_codes: Vec<String>,
    pub(crate) session: IssuedSession,
}

/// 일반 로그인에 사용할 두 번째 인증 factor입니다.
pub(crate) enum LoginSecondFactor {
    /// 6자리 TOTP code입니다.
    Totp(String),
    /// 일회용 recovery code입니다.
    RecoveryCode(String),
}

struct SealedTotpSecret {
    ciphertext: Vec<u8>,
    kdf_salt: [u8; TOTP_KDF_SALT_BYTES],
    nonce: [u8; TOTP_NONCE_BYTES],
}

struct PendingEnrollment {
    enrollment_digest: [u8; 32],
    username: String,
    password_hash: String,
    sealed_totp: SealedTotpSecret,
    totp_secret: SecretSlice<u8>,
    expires_at: i64,
}

struct PreparedSession {
    issued: IssuedSession,
    session_digest: [u8; 32],
    csrf_digest: [u8; 32],
    expires_at: i64,
}

struct LoginRateLimiter {
    limit: usize,
    attempts: Mutex<VecDeque<Instant>>,
}

impl LoginRateLimiter {
    fn new(limit: u32) -> Self {
        Self {
            limit: usize::try_from(limit).unwrap_or(60),
            attempts: Mutex::new(VecDeque::with_capacity(
                usize::try_from(limit).unwrap_or(60),
            )),
        }
    }

    fn allow(&self) -> bool {
        self.allow_at(Instant::now())
    }

    fn allow_at(&self, now: Instant) -> bool {
        let mut attempts = self
            .attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while attempts.front().is_some_and(|attempt| {
            now.saturating_duration_since(*attempt) >= Duration::from_secs(60)
        }) {
            attempts.pop_front();
        }
        if attempts.len() >= self.limit {
            return false;
        }
        attempts.push_back(now);
        true
    }
}

/// 관리자 계정·TOTP와 영속 session을 조율하는 인증 service입니다.
pub(crate) struct SessionStore {
    repository: std::sync::Arc<AuthRepository>,
    pending_enrollment: Mutex<Option<PendingEnrollment>>,
    dummy_password_hash: String,
    login_limiter: LoginRateLimiter,
    authenticator: AccountAuthenticator,
}

enum AccountAuthenticator {
    Local,
    Pam(std::sync::Arc<dyn PamAuthenticator>),
}

impl SessionStore {
    /// 운영 인증 service를 만들고 timing equalization용 Argon2id verifier를 준비합니다.
    #[cfg(test)]
    pub(crate) fn new(
        repository: std::sync::Arc<AuthRepository>,
        login_rate_limit_rpm: u32,
    ) -> Result<Self, AuthError> {
        Self::with_authenticator(
            repository,
            login_rate_limit_rpm,
            AccountAuthenticator::Local,
        )
    }

    /// UI 설정에 따라 local 또는 Linux-PAM 인증 service를 만듭니다.
    pub(crate) fn from_ui_config(
        repository: std::sync::Arc<AuthRepository>,
        config: &UiConfig,
    ) -> Result<Self, AuthError> {
        let authenticator = match config.auth_provider {
            AdminAuthProvider::Local => AccountAuthenticator::Local,
            AdminAuthProvider::Pam => AccountAuthenticator::Pam(privileged_authenticator(
                config.privileged_socket.clone(),
                &config.pam_service,
                &config.pam_allowed_group,
            )),
        };
        Self::with_authenticator(repository, config.login_rate_limit_rpm, authenticator)
    }

    fn with_authenticator(
        repository: std::sync::Arc<AuthRepository>,
        login_rate_limit_rpm: u32,
        authenticator: AccountAuthenticator,
    ) -> Result<Self, AuthError> {
        let dummy_password =
            SecretString::from("vpsguard-dummy-password-not-an-account".to_owned());
        Ok(Self {
            repository,
            pending_enrollment: Mutex::new(None),
            dummy_password_hash: hash_password(&dummy_password)?,
            login_limiter: LoginRateLimiter::new(login_rate_limit_rpm),
            authenticator,
        })
    }

    /// unit·API test용 memory 인증 service입니다.
    #[cfg(test)]
    pub(crate) fn in_memory(login_rate_limit_rpm: u32) -> Result<Self, AuthError> {
        Self::new(
            std::sync::Arc::new(AuthRepository::in_memory()?),
            login_rate_limit_rpm,
        )
    }

    /// 최초 관리자 등록 필요 여부를 반환합니다.
    pub(crate) fn setup_required(&self) -> Result<bool, AuthError> {
        match &self.authenticator {
            AccountAuthenticator::Local => Ok(!self.repository.is_configured()?),
            AccountAuthenticator::Pam(_) => Ok(false),
        }
    }

    /// VPSGuard 전용 password/TOTP 등록 화면이 활성인지 반환합니다.
    pub(crate) const fn enrollment_enabled(&self) -> bool {
        matches!(&self.authenticator, AccountAuthenticator::Local)
    }

    /// UI에 노출할 활성 credential provider를 반환합니다.
    pub(crate) const fn auth_provider(&self) -> AdminAuthProvider {
        match &self.authenticator {
            AccountAuthenticator::Local => AdminAuthProvider::Local,
            AccountAuthenticator::Pam(_) => AdminAuthProvider::Pam,
        }
    }

    /// 단회 bootstrap 검증 후 실행할 관리자 ID·비밀번호 정책 검사입니다.
    pub(crate) fn validate_new_credentials(
        username: &str,
        password: &str,
    ) -> Result<(), AuthError> {
        normalize_username(username)?;
        validate_password(password)
    }

    /// 최초 관리자 TOTP 등록 session을 시작합니다.
    pub(crate) fn start_enrollment(
        &self,
        username: String,
        password: SecretString,
        now: i64,
    ) -> Result<EnrollmentStart, AuthError> {
        if !self.enrollment_enabled() {
            return Err(AuthError::EnrollmentDisabled);
        }
        if self.repository.is_configured()? {
            return Err(AuthError::AlreadyConfigured);
        }
        let username = normalize_username(&username)?;
        validate_password(password.expose_secret())?;
        let password_hash = hash_password(&password)?;
        let secret = random_bytes::<TOTP_SECRET_BYTES>()?;
        let sealed_totp = seal_totp_secret(&password, &username, &secret)?;
        let totp = totp(&username, &secret)?;
        let enrollment_id = random_token()?;
        let enrollment_digest = keyed_digest(ENROLLMENT_CONTEXT, enrollment_id.as_bytes())?;
        *self.lock_pending() = Some(PendingEnrollment {
            enrollment_digest,
            username,
            password_hash,
            sealed_totp,
            totp_secret: SecretSlice::from(secret.to_vec()),
            expires_at: now.saturating_add(ENROLLMENT_TTL_SECONDS),
        });
        Ok(EnrollmentStart {
            enrollment_id,
            secret_base32: totp.get_secret_base32(),
            otpauth_uri: totp.get_url(),
            expires_in_seconds: u64::try_from(ENROLLMENT_TTL_SECONDS).unwrap_or(600),
        })
    }

    /// TOTP를 확인하고 최초 계정·복구 code와 첫 session을 원자에 가깝게 확정합니다.
    pub(crate) fn confirm_enrollment(
        &self,
        enrollment_id: &str,
        totp_code: &str,
        secure_cookie: bool,
        now: i64,
    ) -> Result<EnrollmentComplete, AuthError> {
        if !self.enrollment_enabled() {
            return Err(AuthError::EnrollmentDisabled);
        }
        validate_totp_shape(totp_code)?;
        let mut pending_slot = self.lock_pending();
        let Some(pending) = pending_slot.as_ref() else {
            return Err(AuthError::EnrollmentUnavailable);
        };
        if pending.expires_at <= now
            || !constant_time_digest_eq(
                ENROLLMENT_CONTEXT,
                enrollment_id.as_bytes(),
                &pending.enrollment_digest,
            )
        {
            if pending.expires_at <= now {
                *pending_slot = None;
            }
            return Err(AuthError::EnrollmentUnavailable);
        }
        let now_u64 = u64::try_from(now).map_err(|_| AuthError::Clock)?;
        let totp = totp(&pending.username, pending.totp_secret.expose_secret())?;
        if !totp.check(totp_code, now_u64) {
            return Err(AuthError::InvalidTotp);
        }
        let (recovery_codes, recovery_digests) = generate_recovery_codes()?;
        let account = NewAdminAccount {
            username: &pending.username,
            password_hash: &pending.password_hash,
            totp_ciphertext: &pending.sealed_totp.ciphertext,
            totp_kdf_salt: &pending.sealed_totp.kdf_salt,
            totp_nonce: &pending.sealed_totp.nonce,
        };
        let actor = pending.username.clone();
        let prepared = prepare_session(
            actor,
            AuthenticationMethod::PasswordTotp,
            secure_cookie,
            now,
        )?;
        let stored_session = NewStoredSession {
            session_digest: &prepared.session_digest,
            csrf_digest: &prepared.csrf_digest,
            actor: &prepared.issued.actor,
            authentication_method: prepared.issued.authentication_method.as_str(),
            issued_at: now,
            expires_at: prepared.expires_at,
        };
        if !self.repository.create_initial_admin_and_session(
            &account,
            &recovery_digests,
            &stored_session,
            now,
        )? {
            *pending_slot = None;
            return Err(AuthError::AlreadyConfigured);
        }
        *pending_slot = None;
        Ok(EnrollmentComplete {
            recovery_codes,
            session: prepared.issued,
        })
    }

    /// ID·비밀번호와 TOTP 또는 recovery code를 검증하고 session을 발급합니다.
    pub(crate) fn login(
        &self,
        username: String,
        password: SecretString,
        second_factor: LoginSecondFactor,
        secure_cookie: bool,
        now: i64,
    ) -> Result<IssuedSession, AuthError> {
        if let AccountAuthenticator::Pam(authenticator) = &self.authenticator {
            let second_factor = match second_factor {
                LoginSecondFactor::Totp(code) | LoginSecondFactor::RecoveryCode(code) => code,
            };
            let identity = authenticator
                .authenticate(PamCredentials {
                    username,
                    password,
                    second_factor: SecretString::from(second_factor),
                })
                .map_err(|_error| AuthError::Pam)?;
            return self.issue_session(
                identity.actor,
                AuthenticationMethod::PamMfa,
                secure_cookie,
                now,
            );
        }
        let normalized =
            normalize_username(&username).unwrap_or_else(|_| username.to_ascii_lowercase());
        let account = self.repository.account(&normalized)?;
        let hash = account
            .as_ref()
            .map_or(self.dummy_password_hash.as_str(), |value| {
                value.password_hash.as_str()
            });
        let password_valid = verify_password(hash, &password);
        let Some(account) = account.filter(|_| password_valid) else {
            return Err(AuthError::InvalidCredentials);
        };
        match second_factor {
            LoginSecondFactor::Totp(code) => {
                validate_totp_shape(&code).map_err(|_| AuthError::InvalidCredentials)?;
                let secret = unseal_totp_secret(&password, &account)?;
                let now_u64 = u64::try_from(now).map_err(|_| AuthError::Clock)?;
                if !totp(&account.username, secret.expose_secret())?.check(&code, now_u64) {
                    return Err(AuthError::InvalidCredentials);
                }
                self.issue_session(
                    account.username,
                    AuthenticationMethod::PasswordTotp,
                    secure_cookie,
                    now,
                )
            }
            LoginSecondFactor::RecoveryCode(code) => {
                let normalized_code =
                    normalize_recovery_code(&code).ok_or(AuthError::InvalidCredentials)?;
                let digest = keyed_digest(RECOVERY_CODE_CONTEXT, normalized_code.as_bytes())?;
                let prepared = prepare_session(
                    account.username,
                    AuthenticationMethod::PasswordRecovery,
                    secure_cookie,
                    now,
                )?;
                let stored = NewStoredSession {
                    session_digest: &prepared.session_digest,
                    csrf_digest: &prepared.csrf_digest,
                    actor: &prepared.issued.actor,
                    authentication_method: prepared.issued.authentication_method.as_str(),
                    issued_at: now,
                    expires_at: prepared.expires_at,
                };
                if !self
                    .repository
                    .consume_recovery_code_and_insert_session(account.id, &digest, &stored, now)?
                {
                    return Err(AuthError::InvalidCredentials);
                }
                Ok(prepared.issued)
            }
        }
    }

    /// login·bootstrap·등록 확인에 공통 시도 한도를 적용합니다.
    pub(crate) fn allow_login_attempt(&self) -> Result<(), AuthError> {
        if self.login_limiter.allow() {
            Ok(())
        } else {
            Err(AuthError::RateLimited)
        }
    }

    /// root local 단회 code 검증 뒤 break-glass session을 발급합니다.
    pub(crate) fn issue_break_glass(
        &self,
        secure_cookie: bool,
        now: i64,
    ) -> Result<IssuedSession, AuthError> {
        self.issue_session(
            "break-glass".to_owned(),
            AuthenticationMethod::BreakGlass,
            secure_cookie,
            now,
        )
    }

    /// Cookie session을 검증하고 actor를 반환합니다.
    pub(crate) fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<SessionIdentity>, AuthError> {
        let Some(raw_session) = session_id(headers) else {
            return Ok(None);
        };
        let digest = keyed_digest(SESSION_CONTEXT, raw_session.as_bytes())?;
        let now = unix_seconds()?;
        Ok(self
            .repository
            .session(&digest, now)?
            .map(|session| SessionIdentity {
                actor: session.actor,
                authentication_method: session.authentication_method,
                expires_in_seconds: u64::try_from(session.expires_at.saturating_sub(now))
                    .unwrap_or(0),
            }))
    }

    /// Cookie session과 CSRF header를 함께 검증합니다.
    pub(crate) fn authorize(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<SessionIdentity>, AuthError> {
        let Some(raw_session) = session_id(headers) else {
            return Ok(None);
        };
        let Some(csrf) = headers
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok())
        else {
            return Ok(None);
        };
        let session_digest = keyed_digest(SESSION_CONTEXT, raw_session.as_bytes())?;
        let now = unix_seconds()?;
        let Some(session) = self.repository.session(&session_digest, now)? else {
            return Ok(None);
        };
        if !constant_time_digest_eq(CSRF_STORE_CONTEXT, csrf.as_bytes(), &session.csrf_digest) {
            return Ok(None);
        }
        Ok(Some(SessionIdentity {
            actor: session.actor,
            authentication_method: session.authentication_method,
            expires_in_seconds: u64::try_from(session.expires_at.saturating_sub(now)).unwrap_or(0),
        }))
    }

    /// 유효 Cookie session에서 재시작 후에도 CSRF token과 actor를 복원합니다.
    pub(crate) fn resume(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<(String, SessionIdentity)>, AuthError> {
        let Some(raw_session) = session_id(headers) else {
            return Ok(None);
        };
        let digest = keyed_digest(SESSION_CONTEXT, raw_session.as_bytes())?;
        let now = unix_seconds()?;
        let Some(session) = self.repository.session(&digest, now)? else {
            return Ok(None);
        };
        Ok(Some((
            csrf_token(raw_session)?,
            SessionIdentity {
                actor: session.actor,
                authentication_method: session.authentication_method,
                expires_in_seconds: u64::try_from(session.expires_at.saturating_sub(now))
                    .unwrap_or(0),
            },
        )))
    }

    /// 현재 session을 폐기하고 만료 cookie header를 반환합니다.
    pub(crate) fn logout(
        &self,
        headers: &HeaderMap,
        secure_cookie: bool,
    ) -> Result<Option<String>, AuthError> {
        let Some(raw_session) = session_id(headers) else {
            return Ok(None);
        };
        let digest = keyed_digest(SESSION_CONTEXT, raw_session.as_bytes())?;
        self.repository.delete_session(&digest)?;
        Ok(Some(expired_cookie(secure_cookie)))
    }

    /// 현재 actor의 모든 session을 폐기합니다.
    pub(crate) fn revoke_all(&self, headers: &HeaderMap) -> Result<Option<u64>, AuthError> {
        let Some(identity) = self.authenticate(headers)? else {
            return Ok(None);
        };
        Ok(Some(
            self.repository.delete_actor_sessions(&identity.actor)?,
        ))
    }

    fn issue_session(
        &self,
        actor: String,
        method: AuthenticationMethod,
        secure_cookie: bool,
        now: i64,
    ) -> Result<IssuedSession, AuthError> {
        let prepared = prepare_session(actor, method, secure_cookie, now)?;
        self.repository.insert_session(&NewStoredSession {
            session_digest: &prepared.session_digest,
            csrf_digest: &prepared.csrf_digest,
            actor: &prepared.issued.actor,
            authentication_method: prepared.issued.authentication_method.as_str(),
            issued_at: now,
            expires_at: prepared.expires_at,
        })?;
        Ok(prepared.issued)
    }

    fn lock_pending(&self) -> MutexGuard<'_, Option<PendingEnrollment>> {
        self.pending_enrollment
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn prepare_session(
    actor: String,
    method: AuthenticationMethod,
    secure_cookie: bool,
    now: i64,
) -> Result<PreparedSession, AuthError> {
    let raw_session = random_token()?;
    let csrf_token = csrf_token(&raw_session)?;
    let session_digest = keyed_digest(SESSION_CONTEXT, raw_session.as_bytes())?;
    let csrf_digest = keyed_digest(CSRF_STORE_CONTEXT, csrf_token.as_bytes())?;
    Ok(PreparedSession {
        issued: IssuedSession {
            csrf_token,
            set_cookie: session_cookie(&raw_session, secure_cookie),
            expires_in_seconds: u64::try_from(SESSION_TTL_SECONDS).unwrap_or(43_200),
            actor,
            authentication_method: method,
        },
        session_digest,
        csrf_digest,
        expires_at: now.saturating_add(SESSION_TTL_SECONDS),
    })
}

fn normalize_username(username: &str) -> Result<String, AuthError> {
    let username = username.trim();
    let valid = (3..=32).contains(&username.len())
        && username.is_ascii()
        && username
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if !valid {
        return Err(AuthError::InvalidUsername);
    }
    Ok(username.to_ascii_lowercase())
}

fn validate_password(password: &str) -> Result<(), AuthError> {
    if password.chars().count() < PASSWORD_MIN_CHARS || password.len() > PASSWORD_MAX_BYTES {
        return Err(AuthError::WeakPassword);
    }
    Ok(())
}

fn validate_totp_shape(code: &str) -> Result<(), AuthError> {
    if code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit()) {
        Ok(())
    } else {
        Err(AuthError::InvalidTotp)
    }
}

fn hash_password(password: &SecretString) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.expose_secret().as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| AuthError::Crypto)
}

fn verify_password(encoded_hash: &str, password: &SecretString) -> bool {
    PasswordHash::new(encoded_hash).ok().is_some_and(|hash| {
        Argon2::default()
            .verify_password(password.expose_secret().as_bytes(), &hash)
            .is_ok()
    })
}

fn seal_totp_secret(
    password: &SecretString,
    username: &str,
    secret: &[u8],
) -> Result<SealedTotpSecret, AuthError> {
    let salt = random_bytes::<TOTP_KDF_SALT_BYTES>()?;
    let nonce = random_bytes::<TOTP_NONCE_BYTES>()?;
    let mut key = derive_totp_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| AuthError::Crypto)?;
    key.zeroize();
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: secret,
                aad: username.as_bytes(),
            },
        )
        .map_err(|_| AuthError::Crypto)?;
    Ok(SealedTotpSecret {
        ciphertext,
        kdf_salt: salt,
        nonce,
    })
}

fn unseal_totp_secret(
    password: &SecretString,
    account: &StoredAdminAccount,
) -> Result<SecretSlice<u8>, AuthError> {
    let salt: [u8; TOTP_KDF_SALT_BYTES] = account
        .totp_kdf_salt
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::Crypto)?;
    let nonce: [u8; TOTP_NONCE_BYTES] = account
        .totp_nonce
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::Crypto)?;
    let mut key = derive_totp_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| AuthError::Crypto)?;
    key.zeroize();
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &account.totp_ciphertext,
                aad: account.username.as_bytes(),
            },
        )
        .map_err(|_| AuthError::InvalidCredentials)?;
    Ok(SecretSlice::from(plaintext))
}

fn derive_totp_key(
    password: &SecretString,
    salt: &[u8; TOTP_KDF_SALT_BYTES],
) -> Result<[u8; 32], AuthError> {
    let mut key = [0_u8; 32];
    let params = Params::new(19 * 1_024, 2, 1, Some(32)).map_err(|_| AuthError::Crypto)?;
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut key)
        .map_err(|_| AuthError::Crypto)?;
    Ok(key)
}

fn totp(username: &str, secret: &[u8]) -> Result<TOTP, AuthError> {
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_vec(),
        Some("VPSGuard".to_owned()),
        username.to_owned(),
    )
    .map_err(|_| AuthError::Crypto)
}

fn generate_recovery_codes() -> Result<(Vec<String>, Vec<[u8; 32]>), AuthError> {
    let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    let mut digests = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _index in 0..RECOVERY_CODE_COUNT {
        let bytes = random_bytes::<16>()?;
        let mut normalized = String::with_capacity(32);
        for byte in bytes {
            normalized.push_str(&format!("{byte:02X}"));
        }
        let display = format!(
            "{}-{}-{}-{}",
            &normalized[0..8],
            &normalized[8..16],
            &normalized[16..24],
            &normalized[24..32]
        );
        digests.push(keyed_digest(RECOVERY_CODE_CONTEXT, normalized.as_bytes())?);
        codes.push(display);
    }
    Ok((codes, digests))
}

fn normalize_recovery_code(code: &str) -> Option<String> {
    let normalized = code
        .bytes()
        .filter(|byte| *byte != b'-' && !byte.is_ascii_whitespace())
        .map(char::from)
        .collect::<String>()
        .to_ascii_uppercase();
    (normalized.len() == 32 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(normalized)
}

fn random_token() -> Result<String, AuthError> {
    Ok(URL_SAFE_NO_PAD.encode(random_bytes::<32>()?))
}

fn random_hex_token() -> Result<String, AuthError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = random_bytes::<32>()?;
    let mut token = String::with_capacity(64);
    for byte in bytes {
        token.push(char::from(HEX[usize::from(byte >> 4)]));
        token.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(token)
}

fn random_bytes<const N: usize>() -> Result<[u8; N], AuthError> {
    let mut bytes = [0_u8; N];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| AuthError::Crypto)?;
    Ok(bytes)
}

fn keyed_digest(context: &[u8], value: &[u8]) -> Result<[u8; 32], AuthError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(context).map_err(|_| AuthError::Crypto)?;
    mac.update(value);
    let bytes = mac.finalize().into_bytes();
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&bytes);
    Ok(digest)
}

fn constant_time_digest_eq(context: &[u8], value: &[u8], expected: &[u8]) -> bool {
    <HmacSha256 as Mac>::new_from_slice(context)
        .ok()
        .is_some_and(|mut mac| {
            mac.update(value);
            mac.verify_slice(expected).is_ok()
        })
}

fn csrf_token(raw_session: &str) -> Result<String, AuthError> {
    Ok(URL_SAFE_NO_PAD.encode(keyed_digest(CSRF_TOKEN_CONTEXT, raw_session.as_bytes())?))
}

fn session_cookie(raw_session: &str, secure: bool) -> String {
    let secure_attribute = if secure { "; Secure" } else { "" };
    let cookie_name = if secure {
        SECURE_SESSION_COOKIE
    } else {
        SESSION_COOKIE
    };
    format!(
        "{cookie_name}={raw_session}; Max-Age={SESSION_TTL_SECONDS}; Path=/; HttpOnly; SameSite=Strict{secure_attribute}"
    )
}

fn expired_cookie(secure: bool) -> String {
    let secure_attribute = if secure { "; Secure" } else { "" };
    let cookie_name = if secure {
        SECURE_SESSION_COOKIE
    } else {
        SESSION_COOKIE
    };
    format!("{cookie_name}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict{secure_attribute}")
}

fn session_id(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("cookie")
        .and_then(|value| value.to_str().ok())
        .and_then(find_session_cookie)
}

fn find_session_cookie(header: &str) -> Option<&str> {
    header.split(';').find_map(|entry| {
        let (name, value) = entry.trim().split_once('=')?;
        (name == SESSION_COOKIE || name == SECURE_SESSION_COOKIE).then_some(value)
    })
}

pub(crate) fn unix_seconds() -> Result<i64, AuthError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthError::Clock)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| AuthError::Clock)
}

#[cfg(test)]
mod tests;
