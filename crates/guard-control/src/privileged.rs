//! Root 권한을 PAM·UFW 두 작업으로 제한하는 local IPC helper를 제공합니다.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(any(target_os = "linux", test))]
use guard_core::config::FirewallMode;
use guard_system::{CommandError, CommandOutput, UfwExecutor};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use crate::pam_auth::{PamAuthError, PamCredentials, PamIdentity, PamPasswordCredentials};
use crate::pam_mfa::{PamMfaEnrollmentComplete, PamMfaEnrollmentStart, PamMfaMethod};

const MAX_REQUEST_BYTES: u64 = 32 * 1024;
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
const IPC_TIMEOUT: Duration = Duration::from_secs(8);

#[cfg(any(target_os = "linux", test))]
const fn ufw_mode_allows_mutation(mode: FirewallMode) -> bool {
    matches!(mode, FirewallMode::StandaloneUfw)
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum PrivilegedRequest {
    PamSetupStatus {
        service: String,
        allowed_group: String,
    },
    PamEnrollmentStart {
        service: String,
        allowed_group: String,
        username: String,
        password: String,
        now: i64,
    },
    PamEnrollmentConfirm {
        service: String,
        allowed_group: String,
        enrollment_id: String,
        totp_code: String,
        now: i64,
    },
    PamAuthenticate {
        service: String,
        allowed_group: String,
        username: String,
        password: String,
        second_factor: String,
    },
    Ufw {
        arguments: Vec<String>,
    },
}

impl PrivilegedRequest {
    fn zeroize_secrets(&mut self) {
        match self {
            Self::PamEnrollmentStart { password, .. } => password.zeroize(),
            Self::PamEnrollmentConfirm {
                enrollment_id,
                totp_code,
                ..
            } => {
                enrollment_id.zeroize();
                totp_code.zeroize();
            }
            Self::PamAuthenticate {
                password,
                second_factor,
                ..
            } => {
                password.zeroize();
                second_factor.zeroize();
            }
            Self::PamSetupStatus { .. } | Self::Ufw { .. } => {}
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
enum PrivilegedResponse {
    PamSetupStatus {
        setup_required: bool,
    },
    PamEnrollmentStarted {
        enrollment_id: String,
        secret_base32: String,
        otpauth_uri: String,
        expires_in_seconds: u64,
    },
    PamEnrollmentCompleted {
        actor: String,
        recovery_codes: Vec<String>,
    },
    PamAuthenticated {
        actor: String,
        mfa_method: PamMfaMethod,
    },
    UfwOutput {
        output: CommandOutput,
    },
    Error {
        code: String,
    },
}

/// 최소 권한 helper IPC 실패입니다.
#[derive(Debug, Error)]
pub enum PrivilegedError {
    /// socket I/O가 실패했습니다.
    #[error("privileged helper I/O 실패: {0}")]
    Io(#[from] std::io::Error),
    /// bounded JSON 계약이 깨졌습니다.
    #[error("privileged helper protocol 실패")]
    Protocol,
    /// helper가 작업을 거부했습니다.
    #[error("privileged helper가 작업을 거부했습니다: {0}")]
    Rejected(String),
    /// Linux root helper가 아닌 platform입니다.
    #[error("privileged helper는 Linux에서만 실행할 수 있습니다")]
    Unsupported,
}

fn round_trip(
    path: &Path,
    request: &mut PrivilegedRequest,
) -> Result<PrivilegedResponse, PrivilegedError> {
    let mut stream = StdUnixStream::connect(path)?;
    stream.set_read_timeout(Some(IPC_TIMEOUT))?;
    stream.set_write_timeout(Some(IPC_TIMEOUT))?;
    let mut payload = serde_json::to_vec(&*request).map_err(|_| PrivilegedError::Protocol)?;
    request.zeroize_secrets();
    if payload.len() > usize::try_from(MAX_REQUEST_BYTES).unwrap_or(usize::MAX) {
        payload.zeroize();
        return Err(PrivilegedError::Protocol);
    }
    let write_result = stream.write_all(&payload);
    payload.zeroize();
    write_result?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = Vec::new();
    stream
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut response)?;
    if response.len() > usize::try_from(MAX_RESPONSE_BYTES).unwrap_or(usize::MAX) {
        return Err(PrivilegedError::Protocol);
    }
    serde_json::from_slice(&response).map_err(|_| PrivilegedError::Protocol)
}

/// Root helper의 봉인 PAM credential 존재 여부를 조회합니다.
pub(crate) fn pam_setup_required(
    path: &Path,
    service: &str,
    allowed_group: &str,
) -> Result<bool, PamAuthError> {
    let mut request = PrivilegedRequest::PamSetupStatus {
        service: service.to_owned(),
        allowed_group: allowed_group.to_owned(),
    };
    match round_trip(path, &mut request).map_err(|_| PamAuthError::Unavailable)? {
        PrivilegedResponse::PamSetupStatus { setup_required } => Ok(setup_required),
        PrivilegedResponse::Error { code } => Err(pam_error(&code)),
        _ => Err(PamAuthError::Unavailable),
    }
}

/// Root helper에서 서버 계정을 검증하고 PAM TOTP 등록을 시작합니다.
pub(crate) fn start_pam_enrollment(
    path: &Path,
    service: &str,
    allowed_group: &str,
    credentials: PamPasswordCredentials,
    now: i64,
) -> Result<PamMfaEnrollmentStart, PamAuthError> {
    let mut request = PrivilegedRequest::PamEnrollmentStart {
        service: service.to_owned(),
        allowed_group: allowed_group.to_owned(),
        username: credentials.username,
        password: credentials.password.expose_secret().to_owned(),
        now,
    };
    match round_trip(path, &mut request).map_err(|_| PamAuthError::Unavailable)? {
        PrivilegedResponse::PamEnrollmentStarted {
            enrollment_id,
            secret_base32,
            otpauth_uri,
            expires_in_seconds,
        } => Ok(PamMfaEnrollmentStart {
            enrollment_id,
            secret_base32,
            otpauth_uri,
            expires_in_seconds,
        }),
        PrivilegedResponse::Error { code } => Err(pam_error(&code)),
        _ => Err(PamAuthError::Unavailable),
    }
}

/// Root helper에서 PAM TOTP를 확인하고 credential을 봉인합니다.
pub(crate) fn confirm_pam_enrollment(
    path: &Path,
    service: &str,
    allowed_group: &str,
    enrollment_id: &str,
    totp_code: &str,
    now: i64,
) -> Result<PamMfaEnrollmentComplete, PamAuthError> {
    let mut request = PrivilegedRequest::PamEnrollmentConfirm {
        service: service.to_owned(),
        allowed_group: allowed_group.to_owned(),
        enrollment_id: enrollment_id.to_owned(),
        totp_code: totp_code.to_owned(),
        now,
    };
    match round_trip(path, &mut request).map_err(|_| PamAuthError::Unavailable)? {
        PrivilegedResponse::PamEnrollmentCompleted {
            actor,
            recovery_codes,
        } => Ok(PamMfaEnrollmentComplete {
            actor,
            recovery_codes,
        }),
        PrivilegedResponse::Error { code } => Err(pam_error(&code)),
        _ => Err(PamAuthError::Unavailable),
    }
}

pub(crate) fn authenticate(
    path: &Path,
    service: &str,
    allowed_group: &str,
    credentials: PamCredentials,
) -> Result<PamIdentity, PamAuthError> {
    let mut request = PrivilegedRequest::PamAuthenticate {
        service: service.to_owned(),
        allowed_group: allowed_group.to_owned(),
        username: credentials.username,
        password: credentials.password.expose_secret().to_owned(),
        second_factor: credentials.second_factor.expose_secret().to_owned(),
    };
    match round_trip(path, &mut request).map_err(|_| PamAuthError::Unavailable)? {
        PrivilegedResponse::PamAuthenticated { actor, mfa_method } => {
            Ok(PamIdentity { actor, mfa_method })
        }
        PrivilegedResponse::Error { code } => Err(pam_error(&code)),
        _ => Err(PamAuthError::Unavailable),
    }
}

fn pam_error(code: &str) -> PamAuthError {
    match code {
        "account_rejected" => PamAuthError::AccountRejected,
        "system_account" => PamAuthError::SystemAccount,
        "group_rejected" => PamAuthError::GroupRejected,
        "mfa_not_enrolled" => PamAuthError::MfaNotEnrolled,
        "enrollment_unavailable" => PamAuthError::EnrollmentUnavailable,
        "already_configured" => PamAuthError::AlreadyConfigured,
        "invalid_totp" => PamAuthError::InvalidTotp,
        "busy" => PamAuthError::Busy,
        "invalid_credentials" => PamAuthError::InvalidCredentials,
        _ => PamAuthError::Unavailable,
    }
}

/// Root helper를 통해서만 UFW를 실행하는 client입니다.
#[derive(Debug, Clone)]
pub(crate) struct PrivilegedUfwExecutor {
    socket: PathBuf,
}

impl PrivilegedUfwExecutor {
    pub(crate) fn new(socket: PathBuf) -> Self {
        Self { socket }
    }
}

impl UfwExecutor for PrivilegedUfwExecutor {
    fn run(&self, arguments: &[String]) -> Result<CommandOutput, CommandError> {
        let mut request = PrivilegedRequest::Ufw {
            arguments: arguments.to_vec(),
        };
        match round_trip(&self.socket, &mut request) {
            Ok(PrivilegedResponse::UfwOutput { output }) => Ok(output),
            Ok(PrivilegedResponse::Error { code }) => Err(CommandError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                code,
            ))),
            Ok(
                PrivilegedResponse::PamSetupStatus { .. }
                | PrivilegedResponse::PamEnrollmentStarted { .. }
                | PrivilegedResponse::PamEnrollmentCompleted { .. }
                | PrivilegedResponse::PamAuthenticated { .. },
            ) => Err(CommandError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "helper response mismatch",
            ))),
            Err(error) => Err(CommandError::Io(std::io::Error::other(error))),
        }
    }
}

/// 설정에 고정된 PAM/UFW root helper를 실행합니다.
///
/// # Errors
///
/// Linux root, 설정, socket 또는 요청 검증 실패를 반환합니다.
pub async fn run_privileged_from_path(config_path: &Path) -> Result<(), PrivilegedError> {
    platform::run(config_path).await
}

#[cfg(target_os = "linux")]
mod platform {
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;

    use guard_core::{GuardConfig, config::FirewallMode};
    use guard_system::{SystemUfwExecutor, UfwController, UfwExecutor};
    use secrecy::SecretString;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::Semaphore;
    use uzers::get_user_by_name;
    use zeroize::Zeroize;

    use super::{
        MAX_REQUEST_BYTES, PrivilegedError, PrivilegedRequest, PrivilegedResponse,
        ufw_mode_allows_mutation,
    };
    use crate::pam_auth::{PamAuthError, PamPasswordCredentials, system_password_authenticator};
    use crate::pam_mfa::{PamMfaError, PamMfaManager};

    pub(super) async fn run(config_path: &Path) -> Result<(), PrivilegedError> {
        if !rustix::process::geteuid().is_root() {
            return Err(PrivilegedError::Rejected("root_required".to_owned()));
        }
        let source = fs::read_to_string(config_path)?;
        let config = GuardConfig::from_toml(&source).map_err(|_| PrivilegedError::Protocol)?;
        let service_uid = get_user_by_name("vps-guard")
            .ok_or_else(|| PrivilegedError::Rejected("service_user_missing".to_owned()))?
            .uid();
        let mut activation = listenfd::ListenFd::from_env();
        let std_listener = activation
            .take_unix_listener(0)?
            .ok_or_else(|| PrivilegedError::Rejected("socket_activation_required".to_owned()))?;
        std_listener.set_nonblocking(true)?;
        let listener = UnixListener::from_std(std_listener)?;
        let gate = Arc::new(Semaphore::new(8));
        let pam_mfa = Arc::new(PamMfaManager::system());
        loop {
            let (stream, _) = listener.accept().await?;
            let peer_uid = stream.peer_cred()?.uid();
            if peer_uid != service_uid && peer_uid != 0 {
                continue;
            }
            let Ok(permit) = Arc::clone(&gate).try_acquire_owned() else {
                continue;
            };
            let pam_service = config.ui.pam_service.clone();
            let allowed_group = config.ui.pam_allowed_group.clone();
            let ssh_port = config.firewall.ssh_port;
            let firewall_mode = config.firewall.mode;
            let pam_mfa = Arc::clone(&pam_mfa);
            tokio::spawn(async move {
                let _permit = permit;
                let _result = handle(
                    stream,
                    pam_service,
                    allowed_group,
                    firewall_mode,
                    ssh_port,
                    pam_mfa,
                )
                .await;
            });
        }
    }

    async fn handle(
        mut stream: UnixStream,
        pam_service: String,
        allowed_group: String,
        firewall_mode: FirewallMode,
        ssh_port: u16,
        pam_mfa: Arc<PamMfaManager>,
    ) -> Result<(), PrivilegedError> {
        let mut payload = Vec::new();
        (&mut stream)
            .take(MAX_REQUEST_BYTES + 1)
            .read_to_end(&mut payload)
            .await?;
        let response = if payload.len() > usize::try_from(MAX_REQUEST_BYTES).unwrap_or(usize::MAX) {
            payload.zeroize();
            PrivilegedResponse::Error {
                code: "request_too_large".to_owned(),
            }
        } else {
            let request = serde_json::from_slice::<PrivilegedRequest>(&payload);
            payload.zeroize();
            match request {
                Ok(request) => {
                    dispatch(
                        request,
                        &pam_service,
                        &allowed_group,
                        firewall_mode,
                        ssh_port,
                        pam_mfa,
                    )
                    .await
                }
                Err(_) => PrivilegedResponse::Error {
                    code: "protocol".to_owned(),
                },
            }
        };
        let bytes = serde_json::to_vec(&response).map_err(|_| PrivilegedError::Protocol)?;
        stream.write_all(&bytes).await?;
        stream.shutdown().await?;
        Ok(())
    }

    async fn dispatch(
        request: PrivilegedRequest,
        pam_service: &str,
        allowed_group: &str,
        firewall_mode: FirewallMode,
        ssh_port: u16,
        pam_mfa: Arc<PamMfaManager>,
    ) -> PrivilegedResponse {
        match request {
            PrivilegedRequest::PamSetupStatus {
                service,
                allowed_group: requested_group,
            } if service == pam_service && requested_group == allowed_group => {
                match pam_mfa.setup_required() {
                    Ok(setup_required) => PrivilegedResponse::PamSetupStatus { setup_required },
                    Err(error) => PrivilegedResponse::Error {
                        code: pam_mfa_code(error).to_owned(),
                    },
                }
            }
            PrivilegedRequest::PamSetupStatus { .. } => PrivilegedResponse::Error {
                code: "policy_mismatch".to_owned(),
            },
            PrivilegedRequest::PamEnrollmentStart {
                service,
                allowed_group: requested_group,
                username,
                password,
                now,
            } if service == pam_service && requested_group == allowed_group => {
                let service = service.clone();
                let group = requested_group.clone();
                let pam_mfa = Arc::clone(&pam_mfa);
                match tokio::task::spawn_blocking(move || {
                    let authenticator = system_password_authenticator(&service, &group)?;
                    let actor = authenticator.authenticate_password(PamPasswordCredentials {
                        username,
                        password: SecretString::from(password),
                    })?;
                    pam_mfa.start_enrollment(actor, now).map_err(map_mfa_error)
                })
                .await
                {
                    Ok(Ok(enrollment)) => PrivilegedResponse::PamEnrollmentStarted {
                        enrollment_id: enrollment.enrollment_id,
                        secret_base32: enrollment.secret_base32,
                        otpauth_uri: enrollment.otpauth_uri,
                        expires_in_seconds: enrollment.expires_in_seconds,
                    },
                    Ok(Err(error)) => PrivilegedResponse::Error {
                        code: pam_code(error).to_owned(),
                    },
                    Err(_) => PrivilegedResponse::Error {
                        code: "unavailable".to_owned(),
                    },
                }
            }
            PrivilegedRequest::PamEnrollmentStart { .. } => PrivilegedResponse::Error {
                code: "policy_mismatch".to_owned(),
            },
            PrivilegedRequest::PamEnrollmentConfirm {
                service,
                allowed_group: requested_group,
                enrollment_id,
                totp_code,
                now,
            } if service == pam_service && requested_group == allowed_group => {
                match pam_mfa.confirm_enrollment(&enrollment_id, &totp_code, now) {
                    Ok(complete) => PrivilegedResponse::PamEnrollmentCompleted {
                        actor: complete.actor,
                        recovery_codes: complete.recovery_codes,
                    },
                    Err(error) => PrivilegedResponse::Error {
                        code: pam_mfa_code(error).to_owned(),
                    },
                }
            }
            PrivilegedRequest::PamEnrollmentConfirm { .. } => PrivilegedResponse::Error {
                code: "policy_mismatch".to_owned(),
            },
            PrivilegedRequest::PamAuthenticate {
                service,
                allowed_group: requested_group,
                username,
                password,
                second_factor,
            } if service == pam_service && requested_group == allowed_group => {
                let service = service.clone();
                let group = requested_group.clone();
                match tokio::task::spawn_blocking(move || {
                    let authenticator = system_password_authenticator(&service, &group)?;
                    let actor = authenticator.authenticate_password(PamPasswordCredentials {
                        username,
                        password: SecretString::from(password),
                    })?;
                    let mfa_method = pam_mfa
                        .verify(&actor, &second_factor, unix_seconds())
                        .map_err(map_mfa_error)?;
                    Ok::<_, PamAuthError>((actor, mfa_method))
                })
                .await
                {
                    Ok(Ok((actor, mfa_method))) => {
                        PrivilegedResponse::PamAuthenticated { actor, mfa_method }
                    }
                    Ok(Err(error)) => PrivilegedResponse::Error {
                        code: pam_code(error).to_owned(),
                    },
                    Err(_) => PrivilegedResponse::Error {
                        code: "unavailable".to_owned(),
                    },
                }
            }
            PrivilegedRequest::PamAuthenticate { .. } => PrivilegedResponse::Error {
                code: "policy_mismatch".to_owned(),
            },
            PrivilegedRequest::Ufw { arguments } if ufw_mode_allows_mutation(firewall_mode) => {
                let result = tokio::task::spawn_blocking(move || {
                    validate_ufw_arguments(&arguments, ssh_port)?;
                    SystemUfwExecutor::default()
                        .run(&arguments)
                        .map_err(|error| {
                            tracing::warn!(
                                log_schema_version = guard_core::correlation::LOG_SCHEMA_VERSION,
                                component = "guard-privileged",
                                error_code = "PRIVILEGED_UFW_COMMAND_FAILED",
                                error = %error,
                                "validated UFW command failed"
                            );
                            "ufw_failed"
                        })
                })
                .await;
                match result {
                    Ok(Ok(output)) => PrivilegedResponse::UfwOutput { output },
                    Ok(Err(code)) => PrivilegedResponse::Error {
                        code: code.to_owned(),
                    },
                    Err(_) => PrivilegedResponse::Error {
                        code: "unavailable".to_owned(),
                    },
                }
            }
            PrivilegedRequest::Ufw { .. } => PrivilegedResponse::Error {
                code: "ownership_denied".to_owned(),
            },
        }
    }

    fn validate_ufw_arguments(arguments: &[String], ssh_port: u16) -> Result<(), &'static str> {
        if arguments == ["status", "numbered"] {
            return Ok(());
        }
        if arguments.len() == 3 && arguments[0] == "--force" && arguments[1] == "delete" {
            let number = arguments[2].parse::<u32>().map_err(|_| "ufw_arguments")?;
            let (snapshot, _) = UfwController::default()
                .snapshot()
                .map_err(|_| "ufw_status_failed")?;
            return snapshot
                .owned_rules
                .iter()
                .any(|rule| rule.number == number)
                .then_some(())
                .ok_or("ufw_foreign_delete");
        }
        guard_system::validate_ufw_add_arguments(arguments, ssh_port).map_err(|_| "ufw_arguments")
    }

    const fn pam_code(error: PamAuthError) -> &'static str {
        match error {
            PamAuthError::InvalidCredentials => "invalid_credentials",
            PamAuthError::AccountRejected => "account_rejected",
            PamAuthError::SystemAccount => "system_account",
            PamAuthError::GroupRejected => "group_rejected",
            PamAuthError::MfaNotEnrolled => "mfa_not_enrolled",
            PamAuthError::EnrollmentUnavailable => "enrollment_unavailable",
            PamAuthError::AlreadyConfigured => "already_configured",
            PamAuthError::InvalidTotp => "invalid_totp",
            PamAuthError::Busy => "busy",
            PamAuthError::Unavailable => "unavailable",
        }
    }

    const fn pam_mfa_code(error: PamMfaError) -> &'static str {
        match error {
            PamMfaError::AlreadyConfigured => "already_configured",
            PamMfaError::EnrollmentUnavailable => "enrollment_unavailable",
            PamMfaError::InvalidTotp => "invalid_totp",
            PamMfaError::NotConfigured => "mfa_not_enrolled",
            PamMfaError::InvalidFactor => "invalid_credentials",
            PamMfaError::Storage | PamMfaError::Crypto | PamMfaError::InvalidUsername => {
                "unavailable"
            }
        }
    }

    const fn map_mfa_error(error: PamMfaError) -> PamAuthError {
        match error {
            PamMfaError::AlreadyConfigured => PamAuthError::AlreadyConfigured,
            PamMfaError::EnrollmentUnavailable => PamAuthError::EnrollmentUnavailable,
            PamMfaError::InvalidTotp => PamAuthError::InvalidTotp,
            PamMfaError::NotConfigured => PamAuthError::MfaNotEnrolled,
            PamMfaError::InvalidFactor => PamAuthError::InvalidCredentials,
            PamMfaError::Storage | PamMfaError::Crypto | PamMfaError::InvalidUsername => {
                PamAuthError::Unavailable
            }
        }
    }

    fn unix_seconds() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_secs()).ok())
            .unwrap_or(0)
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::{Path, PrivilegedError};

    pub(super) async fn run(_config_path: &Path) -> Result<(), PrivilegedError> {
        Err(PrivilegedError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privileged_ufw_is_enabled_only_for_standalone_ownership() {
        assert!(ufw_mode_allows_mutation(FirewallMode::StandaloneUfw));
        assert!(!ufw_mode_allows_mutation(FirewallMode::JwAgentDelegated));
        assert!(!ufw_mode_allows_mutation(FirewallMode::Disabled));
    }
}
