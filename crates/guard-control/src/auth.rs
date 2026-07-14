//! Loopback 운영 UI의 bounded session과 CSRF double-submit 검증입니다.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use axum::http::HeaderMap;
use uuid::Uuid;

const SESSION_COOKIE: &str = "vps_guard_session";
const MAX_SESSIONS: usize = 128;

#[derive(Debug, Clone)]
struct Session {
    csrf_token: String,
    expires_at: SystemTime,
}

/// session 발급 결과입니다.
#[derive(Debug, Clone)]
pub(crate) struct IssuedSession {
    pub(crate) csrf_token: String,
    pub(crate) set_cookie: String,
}

/// memory에만 존재하는 짧은 운영 session 저장소입니다.
#[derive(Debug)]
pub(crate) struct SessionStore {
    sessions: Mutex<HashMap<String, Session>>,
    ttl: Duration,
}

impl SessionStore {
    /// 기본 30분 session 저장소를 만듭니다.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::with_capacity(MAX_SESSIONS)),
            ttl: Duration::from_secs(30 * 60),
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
        IssuedSession {
            csrf_token,
            set_cookie: format!(
                "{SESSION_COOKIE}={session_id}; Max-Age={}; Path=/; HttpOnly; SameSite=Strict{secure_attribute}",
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

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Session>> {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
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
        (name == SESSION_COOKIE).then_some(value)
    })
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::SessionStore;

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
}
