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

use crate::pam_auth::{PamAuthError, PamCredentials, PamIdentity};

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
        if let Self::PamAuthenticate {
            password,
            second_factor,
            ..
        } = self
        {
            password.zeroize();
            second_factor.zeroize();
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
enum PrivilegedResponse {
    PamAuthenticated { actor: String },
    UfwOutput { output: CommandOutput },
    Error { code: String },
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
    let payload = serde_json::to_vec(&*request).map_err(|_| PrivilegedError::Protocol)?;
    request.zeroize_secrets();
    if payload.len() > usize::try_from(MAX_REQUEST_BYTES).unwrap_or(usize::MAX) {
        return Err(PrivilegedError::Protocol);
    }
    stream.write_all(&payload)?;
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
        PrivilegedResponse::PamAuthenticated { actor } => Ok(PamIdentity { actor }),
        PrivilegedResponse::Error { code } => Err(match code.as_str() {
            "account_rejected" => PamAuthError::AccountRejected,
            "system_account" => PamAuthError::SystemAccount,
            "group_rejected" => PamAuthError::GroupRejected,
            "mfa_not_enforced" => PamAuthError::MfaNotEnforced,
            "busy" => PamAuthError::Busy,
            "invalid_credentials" => PamAuthError::InvalidCredentials,
            _ => PamAuthError::Unavailable,
        }),
        PrivilegedResponse::UfwOutput { .. } => Err(PamAuthError::Unavailable),
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
            Ok(PrivilegedResponse::PamAuthenticated { .. }) => Err(CommandError::Io(
                std::io::Error::new(std::io::ErrorKind::InvalidData, "helper response mismatch"),
            )),
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

    use super::{
        MAX_REQUEST_BYTES, PrivilegedError, PrivilegedRequest, PrivilegedResponse,
        ufw_mode_allows_mutation,
    };
    use crate::pam_auth::{PamAuthError, PamCredentials, system_authenticator};

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
            tokio::spawn(async move {
                let _permit = permit;
                let _result =
                    handle(stream, pam_service, allowed_group, firewall_mode, ssh_port).await;
            });
        }
    }

    async fn handle(
        mut stream: UnixStream,
        pam_service: String,
        allowed_group: String,
        firewall_mode: FirewallMode,
        ssh_port: u16,
    ) -> Result<(), PrivilegedError> {
        let mut payload = Vec::new();
        (&mut stream)
            .take(MAX_REQUEST_BYTES + 1)
            .read_to_end(&mut payload)
            .await?;
        let response = if payload.len() > usize::try_from(MAX_REQUEST_BYTES).unwrap_or(usize::MAX) {
            PrivilegedResponse::Error {
                code: "request_too_large".to_owned(),
            }
        } else {
            match serde_json::from_slice::<PrivilegedRequest>(&payload) {
                Ok(request) => {
                    dispatch(
                        request,
                        &pam_service,
                        &allowed_group,
                        firewall_mode,
                        ssh_port,
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
    ) -> PrivilegedResponse {
        match request {
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
                    let authenticator = system_authenticator(&service, &group)?;
                    authenticator.authenticate(PamCredentials {
                        username,
                        password: SecretString::from(password),
                        second_factor: SecretString::from(second_factor),
                    })
                })
                .await
                {
                    Ok(Ok(identity)) => PrivilegedResponse::PamAuthenticated {
                        actor: identity.actor,
                    },
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
            PamAuthError::MfaNotEnforced => "mfa_not_enforced",
            PamAuthError::Busy => "busy",
            PamAuthError::Unavailable => "unavailable",
        }
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
