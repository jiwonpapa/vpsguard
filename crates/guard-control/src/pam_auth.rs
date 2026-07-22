//! Linux-PAM 서버 계정과 전용 Unix group 기반 관리 인증을 제공합니다.

use std::path::PathBuf;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::Mutex;

use secrecy::SecretString;
use thiserror::Error;

#[cfg(any(test, target_os = "linux"))]
const MIN_HUMAN_UID: u32 = 1_000;
#[cfg(any(test, target_os = "linux"))]
const MAX_HUMAN_UID_EXCLUSIVE: u32 = 60_000;

/// PAM 호출에 전달할 web credential입니다.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct PamCredentials {
    pub(crate) username: String,
    pub(crate) password: SecretString,
    pub(crate) second_factor: SecretString,
}

/// PAM과 Unix identity 검증을 통과한 actor입니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PamIdentity {
    pub(crate) actor: String,
}

/// PAM 인증·계정·group 검증 실패입니다.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum PamAuthError {
    #[error("PAM 인증 정보가 올바르지 않습니다")]
    InvalidCredentials,
    #[error("PAM 계정이 잠겼거나 만료됐습니다")]
    AccountRejected,
    #[error("root 또는 system 계정은 관리 UI에 로그인할 수 없습니다")]
    SystemAccount,
    #[error("PAM 계정이 허용 Unix group에 속하지 않습니다")]
    GroupRejected,
    #[error("PAM stack이 두 번째 인증 factor를 요구하지 않았습니다")]
    MfaNotEnforced,
    #[error("동시에 다른 PAM 인증이 실행 중입니다")]
    Busy,
    #[error("이 platform에서 Linux-PAM을 사용할 수 없습니다")]
    Unavailable,
}

/// 실제 PAM 또는 test fake의 credential 검증 경계입니다.
pub(crate) trait PamAuthenticator: Send + Sync {
    fn authenticate(&self, credentials: PamCredentials) -> Result<PamIdentity, PamAuthError>;
}

/// 현재 Linux host의 PAM authenticator를 생성합니다.
#[cfg(target_os = "linux")]
pub(crate) fn system_authenticator(
    service: &str,
    allowed_group: &str,
) -> Result<Arc<dyn PamAuthenticator>, PamAuthError> {
    platform::build(service, allowed_group)
}

/// PAM credential을 root helper socket으로 전달하는 bounded authenticator를 생성합니다.
pub(crate) fn privileged_authenticator(
    socket: PathBuf,
    service: &str,
    allowed_group: &str,
) -> Arc<dyn PamAuthenticator> {
    Arc::new(PrivilegedPamAuthenticator {
        socket,
        service: service.to_owned(),
        allowed_group: allowed_group.to_owned(),
    })
}

struct PrivilegedPamAuthenticator {
    socket: PathBuf,
    service: String,
    allowed_group: String,
}

impl PamAuthenticator for PrivilegedPamAuthenticator {
    fn authenticate(&self, credentials: PamCredentials) -> Result<PamIdentity, PamAuthError> {
        crate::privileged::authenticate(
            &self.socket,
            &self.service,
            &self.allowed_group,
            credentials,
        )
    }
}

#[cfg(any(test, target_os = "linux"))]
fn validate_unix_identity(
    username: &str,
    uid: u32,
    groups: &[String],
    allowed_group: &str,
) -> Result<PamIdentity, PamAuthError> {
    if username.eq_ignore_ascii_case("root")
        || !(MIN_HUMAN_UID..MAX_HUMAN_UID_EXCLUSIVE).contains(&uid)
    {
        return Err(PamAuthError::SystemAccount);
    }
    if !groups.iter().any(|group| group == allowed_group) {
        return Err(PamAuthError::GroupRejected);
    }
    Ok(PamIdentity {
        actor: username.to_owned(),
    })
}

#[cfg(target_os = "linux")]
mod platform {
    use std::ffi::{CStr, CString};

    use pam_client::{Context, ConversationHandler, ErrorCode, Flag};
    use secrecy::{ExposeSecret, SecretString};
    use uzers::get_user_by_name;

    use super::{
        Arc, Mutex, PamAuthError, PamAuthenticator, PamCredentials, PamIdentity,
        validate_unix_identity,
    };

    struct WebConversation {
        username: String,
        password: SecretString,
        second_factor: SecretString,
        secret_prompts: usize,
    }

    impl ConversationHandler for WebConversation {
        fn prompt_echo_on(&mut self, _prompt: &CStr) -> Result<CString, ErrorCode> {
            CString::new(self.username.as_bytes()).map_err(|_| ErrorCode::CONV_ERR)
        }

        fn prompt_echo_off(&mut self, _prompt: &CStr) -> Result<CString, ErrorCode> {
            self.secret_prompts = self.secret_prompts.saturating_add(1);
            let value = if self.secret_prompts == 1 {
                self.password.expose_secret()
            } else if self.secret_prompts == 2 {
                self.second_factor.expose_secret()
            } else {
                return Err(ErrorCode::CONV_ERR);
            };
            CString::new(value.as_bytes()).map_err(|_| ErrorCode::CONV_ERR)
        }

        fn text_info(&mut self, _message: &CStr) {}

        fn error_msg(&mut self, _message: &CStr) {}
    }

    struct LinuxPamAuthenticator {
        service: String,
        allowed_group: String,
        gate: Mutex<()>,
    }

    impl PamAuthenticator for LinuxPamAuthenticator {
        fn authenticate(&self, credentials: PamCredentials) -> Result<PamIdentity, PamAuthError> {
            let _lease = self.gate.try_lock().map_err(|_| PamAuthError::Busy)?;
            let conversation = WebConversation {
                username: credentials.username.clone(),
                password: credentials.password,
                second_factor: credentials.second_factor,
                secret_prompts: 0,
            };
            let mut context =
                Context::new(&self.service, Some(&credentials.username), conversation)
                    .map_err(|_| PamAuthError::Unavailable)?;
            context
                .authenticate(Flag::DISALLOW_NULL_AUTHTOK)
                .map_err(|_| PamAuthError::InvalidCredentials)?;
            if context.conversation().secret_prompts < 2 {
                return Err(PamAuthError::MfaNotEnforced);
            }
            context
                .acct_mgmt(Flag::DISALLOW_NULL_AUTHTOK)
                .map_err(|_| PamAuthError::AccountRejected)?;
            let username = context.user().map_err(|_| PamAuthError::AccountRejected)?;
            let user = get_user_by_name(&username).ok_or(PamAuthError::AccountRejected)?;
            let groups = user
                .groups()
                .ok_or(PamAuthError::GroupRejected)?
                .into_iter()
                .map(|group| group.name().to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            validate_unix_identity(&username, user.uid(), &groups, &self.allowed_group)
        }
    }

    pub(super) fn build(
        service: &str,
        allowed_group: &str,
    ) -> Result<Arc<dyn PamAuthenticator>, PamAuthError> {
        Ok(Arc::new(LinuxPamAuthenticator {
            service: service.to_owned(),
            allowed_group: allowed_group.to_owned(),
            gate: Mutex::new(()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{PamAuthError, validate_unix_identity};

    #[test]
    fn unix_identity_rejects_root_system_and_wrong_group() {
        assert_eq!(
            validate_unix_identity("root", 0, &["vpsguard-admin".to_owned()], "vpsguard-admin"),
            Err(PamAuthError::SystemAccount)
        );
        assert_eq!(
            validate_unix_identity(
                "daemon-user",
                998,
                &["vpsguard-admin".to_owned()],
                "vpsguard-admin"
            ),
            Err(PamAuthError::SystemAccount)
        );
        assert_eq!(
            validate_unix_identity("operator", 1000, &["sudo".to_owned()], "vpsguard-admin"),
            Err(PamAuthError::GroupRejected)
        );
    }

    #[test]
    fn unix_identity_accepts_only_human_allowlisted_user() -> Result<(), PamAuthError> {
        let identity = validate_unix_identity(
            "operator",
            1000,
            &["sudo".to_owned(), "vpsguard-admin".to_owned()],
            "vpsguard-admin",
        )?;
        assert_eq!(identity.actor, "operator");
        Ok(())
    }
}
