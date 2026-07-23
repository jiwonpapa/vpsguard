//! Linux-PAM 서버 계정과 전용 Unix group 기반 관리 인증을 제공합니다.

use std::path::PathBuf;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::Mutex;

use secrecy::SecretString;
use thiserror::Error;

use crate::pam_mfa::{PamMfaEnrollmentComplete, PamMfaEnrollmentStart, PamMfaMethod};

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

/// Linux-PAM의 서버 비밀번호 검증에만 전달하는 credential입니다.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct PamPasswordCredentials {
    pub(crate) username: String,
    pub(crate) password: SecretString,
}

/// PAM과 Unix identity 검증을 통과한 actor입니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PamIdentity {
    pub(crate) actor: String,
    pub(crate) mfa_method: PamMfaMethod,
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
    #[error("PAM 관리자 TOTP 등록이 필요합니다")]
    MfaNotEnrolled,
    #[error("PAM 관리자 등록 session이 없거나 만료됐습니다")]
    EnrollmentUnavailable,
    #[error("PAM 관리자가 이미 등록됐습니다")]
    AlreadyConfigured,
    #[error("PAM 관리자 TOTP가 올바르지 않습니다")]
    InvalidTotp,
    #[error("동시에 다른 PAM 인증이 실행 중입니다")]
    Busy,
    #[error("이 platform에서 Linux-PAM을 사용할 수 없습니다")]
    Unavailable,
}

/// 실제 PAM 또는 test fake의 credential 검증 경계입니다.
pub(crate) trait PamAuthenticator: Send + Sync {
    /// 최초 PAM 관리자 TOTP 등록 필요 여부를 반환합니다.
    fn setup_required(&self) -> Result<bool, PamAuthError>;

    /// 서버 계정 검증 뒤 PAM 관리자 TOTP 등록을 시작합니다.
    fn start_enrollment(
        &self,
        credentials: PamPasswordCredentials,
        now: i64,
    ) -> Result<PamMfaEnrollmentStart, PamAuthError>;

    /// TOTP 확인 뒤 PAM 관리자 credential을 원자 저장합니다.
    fn confirm_enrollment(
        &self,
        enrollment_id: &str,
        totp_code: &str,
        now: i64,
    ) -> Result<PamMfaEnrollmentComplete, PamAuthError>;

    /// 서버 비밀번호와 등록된 TOTP 또는 복구 코드를 검증합니다.
    fn authenticate(&self, credentials: PamCredentials) -> Result<PamIdentity, PamAuthError>;
}

/// Linux-PAM 서버 비밀번호·계정·group 검증 경계입니다.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) trait PamPasswordAuthenticator: Send + Sync {
    /// 두 번째 인증 factor와 분리해 서버 비밀번호와 account 상태만 검증합니다.
    fn authenticate_password(
        &self,
        credentials: PamPasswordCredentials,
    ) -> Result<String, PamAuthError>;
}

/// 현재 Linux host의 비밀번호 전용 PAM authenticator를 생성합니다.
#[cfg(target_os = "linux")]
pub(crate) fn system_password_authenticator(
    service: &str,
    allowed_group: &str,
) -> Result<Arc<dyn PamPasswordAuthenticator>, PamAuthError> {
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
    fn setup_required(&self) -> Result<bool, PamAuthError> {
        crate::privileged::pam_setup_required(&self.socket, &self.service, &self.allowed_group)
    }

    fn start_enrollment(
        &self,
        credentials: PamPasswordCredentials,
        now: i64,
    ) -> Result<PamMfaEnrollmentStart, PamAuthError> {
        crate::privileged::start_pam_enrollment(
            &self.socket,
            &self.service,
            &self.allowed_group,
            credentials,
            now,
        )
    }

    fn confirm_enrollment(
        &self,
        enrollment_id: &str,
        totp_code: &str,
        now: i64,
    ) -> Result<PamMfaEnrollmentComplete, PamAuthError> {
        crate::privileged::confirm_pam_enrollment(
            &self.socket,
            &self.service,
            &self.allowed_group,
            enrollment_id,
            totp_code,
            now,
        )
    }

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
) -> Result<String, PamAuthError> {
    if username.eq_ignore_ascii_case("root")
        || !(MIN_HUMAN_UID..MAX_HUMAN_UID_EXCLUSIVE).contains(&uid)
    {
        return Err(PamAuthError::SystemAccount);
    }
    if !groups.iter().any(|group| group == allowed_group) {
        return Err(PamAuthError::GroupRejected);
    }
    Ok(username.to_owned())
}

#[cfg(target_os = "linux")]
mod platform {
    use std::ffi::{CStr, CString};

    use pam_client::{Context, ConversationHandler, ErrorCode, Flag};
    use secrecy::{ExposeSecret, SecretString};
    use uzers::get_user_by_name;

    use super::{
        Arc, Mutex, PamAuthError, PamPasswordAuthenticator, PamPasswordCredentials,
        validate_unix_identity,
    };

    struct WebConversation {
        username: String,
        password: SecretString,
        secret_prompts: usize,
    }

    impl ConversationHandler for WebConversation {
        fn prompt_echo_on(&mut self, _prompt: &CStr) -> Result<CString, ErrorCode> {
            CString::new(self.username.as_bytes()).map_err(|_| ErrorCode::CONV_ERR)
        }

        fn prompt_echo_off(&mut self, _prompt: &CStr) -> Result<CString, ErrorCode> {
            self.secret_prompts = self.secret_prompts.saturating_add(1);
            if self.secret_prompts != 1 {
                return Err(ErrorCode::CONV_ERR);
            }
            CString::new(self.password.expose_secret().as_bytes()).map_err(|_| ErrorCode::CONV_ERR)
        }

        fn text_info(&mut self, _message: &CStr) {}

        fn error_msg(&mut self, _message: &CStr) {}
    }

    struct LinuxPamPasswordAuthenticator {
        service: String,
        allowed_group: String,
        gate: Mutex<()>,
    }

    impl PamPasswordAuthenticator for LinuxPamPasswordAuthenticator {
        fn authenticate_password(
            &self,
            credentials: PamPasswordCredentials,
        ) -> Result<String, PamAuthError> {
            let _lease = self.gate.try_lock().map_err(|_| PamAuthError::Busy)?;
            let conversation = WebConversation {
                username: credentials.username.clone(),
                password: credentials.password,
                secret_prompts: 0,
            };
            let mut context =
                Context::new(&self.service, Some(&credentials.username), conversation)
                    .map_err(|_| PamAuthError::Unavailable)?;
            context
                .authenticate(Flag::DISALLOW_NULL_AUTHTOK)
                .map_err(|_| PamAuthError::InvalidCredentials)?;
            if context.conversation().secret_prompts != 1 {
                return Err(PamAuthError::Unavailable);
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
    ) -> Result<Arc<dyn PamPasswordAuthenticator>, PamAuthError> {
        Ok(Arc::new(LinuxPamPasswordAuthenticator {
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
        assert_eq!(identity, "operator");
        Ok(())
    }
}
