//! 단회 로그인 코드, 관리 Host와 bounded session·CSRF 검증을 제공합니다.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use axum::http::HeaderMap;
use guard_core::config::UiConfig;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

const SESSION_COOKIE: &str = "vps_guard_session";
const SECURE_SESSION_COOKIE: &str = "__Host-vps_guard_session";
const MAX_SESSIONS: usize = 128;
const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);
const LOGIN_CODE_CONTEXT: &[u8] = b"vpsguard-login-code-v1";

type HmacSha256 = Hmac<Sha256>;

struct Session {
    csrf_token: String,
    expires_at: SystemTime,
}

/// session 발급 결과입니다.
/// Cookie와 CSRF 원문을 포함하므로 `Debug`를 구현하지 않습니다.
pub(crate) struct IssuedSession {
    pub(crate) csrf_token: String,
    pub(crate) set_cookie: String,
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
        let code = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let digest = login_code_digest(&code)?;
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
        let Some(mut mac) = HmacSha256::new_from_slice(LOGIN_CODE_CONTEXT).ok() else {
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
                allowed_origin: format!("https://{}", host.to_ascii_lowercase()),
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

/// memory에만 존재하는 bounded 운영 session 저장소입니다.
pub(crate) struct SessionStore {
    sessions: Mutex<HashMap<String, Session>>,
    ttl: Duration,
}

impl SessionStore {
    /// 기본 12시간 session 저장소를 만듭니다.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::with_capacity(MAX_SESSIONS)),
            ttl: SESSION_TTL,
        }
    }

    /// 새 session과 별도 CSRF token을 발급합니다.
    pub(crate) fn issue(&self, secure: bool) -> IssuedSession {
        let session_id = Uuid::new_v4().simple().to_string();
        let csrf_token = Uuid::new_v4().simple().to_string();
        let mut sessions = self.lock();
        let now = SystemTime::now();
        sessions.retain(|_, session| session.expires_at > now);
        if sessions.len() >= MAX_SESSIONS
            && let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, session)| session.expires_at)
                .map(|(id, _)| id.clone())
        {
            sessions.remove(&oldest);
        }
        sessions.insert(
            session_id.clone(),
            Session {
                csrf_token: csrf_token.clone(),
                expires_at: now + self.ttl,
            },
        );
        let secure_attribute = if secure { "; Secure" } else { "" };
        let cookie_name = if secure {
            SECURE_SESSION_COOKIE
        } else {
            SESSION_COOKIE
        };
        IssuedSession {
            csrf_token,
            set_cookie: format!(
                "{cookie_name}={session_id}; Max-Age={}; Path=/; HttpOnly; SameSite=Strict{secure_attribute}",
                self.ttl.as_secs()
            ),
        }
    }

    /// Cookie session과 CSRF header를 함께 검증합니다.
    pub(crate) fn authorize(&self, headers: &HeaderMap) -> bool {
        let session_id = session_id(headers);
        let csrf = headers
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok());
        let (Some(session_id), Some(csrf)) = (session_id, csrf) else {
            return false;
        };
        self.lock().get(session_id).is_some_and(|session| {
            session.expires_at > SystemTime::now() && session.csrf_token == csrf
        })
    }

    /// Read-only 민감 API에 사용할 Cookie session만 검증합니다.
    pub(crate) fn authenticate(&self, headers: &HeaderMap) -> bool {
        let Some(session_id) = session_id(headers) else {
            return false;
        };
        self.lock()
            .get(session_id)
            .is_some_and(|session| session.expires_at > SystemTime::now())
    }

    /// 유효한 Cookie session의 CSRF token과 남은 시간을 복원합니다.
    pub(crate) fn resume(&self, headers: &HeaderMap) -> Option<(String, u64)> {
        let session_id = session_id(headers)?;
        let now = SystemTime::now();
        self.lock().get(session_id).and_then(|session| {
            session
                .expires_at
                .duration_since(now)
                .ok()
                .map(|remaining| (session.csrf_token.clone(), remaining.as_secs()))
        })
    }

    /// 설정된 session TTL입니다.
    pub(crate) const fn ttl_seconds(&self) -> u64 {
        self.ttl.as_secs()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Session>> {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn login_code_digest(code: &str) -> Option<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(LOGIN_CODE_CONTEXT).ok()?;
    mac.update(code.as_bytes());
    let bytes = mac.finalize().into_bytes();
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&bytes);
    Some(digest)
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

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use axum::http::{HeaderMap, HeaderValue};

    use guard_core::config::UiConfig;

    use super::{BootstrapStore, SessionStore, UiAccessPolicy};

    #[test]
    fn session_requires_matching_csrf() -> Result<(), Box<dyn std::error::Error>> {
        let store = SessionStore::new();
        let issued = store.issue(false);
        let mut headers = HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_str(&issued.set_cookie)?);
        assert!(store.authenticate(&headers));
        assert!(!store.authorize(&headers));
        headers.insert("x-csrf-token", HeaderValue::from_str(&issued.csrf_token)?);
        assert!(store.authorize(&headers));
        Ok(())
    }

    #[test]
    fn login_code_is_single_use_and_raw_value_is_not_stored()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = BootstrapStore::new();
        let issued = store
            .issue(Duration::from_secs(300))
            .ok_or("code issue failed")?;
        assert!(store.consume(&issued.code));
        assert!(!store.consume(&issued.code));
        Ok(())
    }

    #[test]
    fn wrong_login_codes_do_not_allow_remote_knockout() -> Result<(), Box<dyn std::error::Error>> {
        let store = BootstrapStore::new();
        let issued = store
            .issue(Duration::from_secs(300))
            .ok_or("code issue failed")?;
        for _attempt in 0..5 {
            assert!(!store.consume("wrong-code"));
        }
        assert!(store.consume(&issued.code));
        Ok(())
    }

    #[test]
    fn expired_login_code_is_rejected_and_removed() -> Result<(), Box<dyn std::error::Error>> {
        let store = BootstrapStore::new();
        let issued = store
            .issue(Duration::from_secs(60))
            .ok_or("code issue failed")?;
        assert!(!store.consume_at(&issued.code, SystemTime::now() + Duration::from_secs(61)));
        assert!(!store.consume(&issued.code));
        Ok(())
    }

    #[test]
    fn public_ui_policy_requires_exact_host_and_origin() -> Result<(), Box<dyn std::error::Error>> {
        let config = UiConfig {
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
}
