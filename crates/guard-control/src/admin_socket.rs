//! Peer credential을 검증하는 local 관리자 socket과 단회 코드 발급을 구현합니다.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use guard_core::correlation::LOG_SCHEMA_VERSION;
use guard_core::{
    ADMIN_PROTOCOL_VERSION, AdminCommand, AdminErrorCode, AdminRequest, AdminResponse,
};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::warn;

use crate::api::AppState;

const MAX_REQUEST_BYTES: usize = 4_096;
const MIN_LOGIN_TTL_SECONDS: u64 = 60;
const MAX_LOGIN_TTL_SECONDS: u64 = 600;

/// local 관리자 socket 준비 실패입니다.
#[derive(Debug, Error)]
pub(crate) enum AdminSocketError {
    /// directory, stale socket, bind 또는 permission 작업 실패입니다.
    #[error("관리 socket 준비 실패: operation={operation}, path={path}, cause={source}")]
    Io {
        /// 실패한 파일 작업입니다.
        operation: &'static str,
        /// 대상 socket 또는 directory입니다.
        path: String,
        /// 원본 I/O 오류입니다.
        source: std::io::Error,
    },
}

/// root와 service owner만 사용할 수 있는 local 관리자 socket을 시작합니다.
///
/// # Errors
///
/// parent directory, stale socket 제거, bind, metadata 또는 mode 설정 실패를 반환합니다.
pub(crate) fn spawn_admin_socket(
    app: Arc<AppState>,
    path: PathBuf,
) -> Result<(), AdminSocketError> {
    let parent = path.parent().ok_or_else(|| AdminSocketError::Io {
        operation: "parent",
        path: path.display().to_string(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "관리 socket parent가 없습니다",
        ),
    })?;
    fs::create_dir_all(parent).map_err(|source| socket_io("create_dir_all", parent, source))?;
    if path.exists() {
        fs::remove_file(&path).map_err(|source| socket_io("remove_stale", &path, source))?;
    }
    let listener = UnixListener::bind(&path).map_err(|source| socket_io("bind", &path, source))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(|source| socket_io("chmod", &path, source))?;
    let owner_uid = fs::metadata(&path)
        .map_err(|source| socket_io("metadata", &path, source))?
        .uid();
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _address)) => {
                    let app = Arc::clone(&app);
                    tokio::spawn(async move {
                        if let Err(error) = handle_connection(stream, app, owner_uid).await {
                            warn!(
                                log_schema_version = LOG_SCHEMA_VERSION,
                                component = "guard-control",
                                error_code = "CONTROL_ADMIN_REQUEST_FAILED",
                                error = %error,
                                "local admin request failed"
                            );
                        }
                    });
                }
                Err(error) => warn!(
                    log_schema_version = LOG_SCHEMA_VERSION,
                    component = "guard-control",
                    error_code = "CONTROL_ADMIN_SOCKET_ACCEPT_FAILED",
                    error = %error,
                    "local admin socket accept failed"
                ),
            }
        }
    });
    Ok(())
}

async fn handle_connection(
    mut stream: UnixStream,
    app: Arc<AppState>,
    owner_uid: u32,
) -> Result<(), std::io::Error> {
    let peer_uid = stream.peer_cred().ok().map(|credential| credential.uid());
    if !peer_uid.is_some_and(|uid| peer_allowed(uid, owner_uid)) {
        return write_response(
            &mut stream,
            &error_response(
                AdminErrorCode::UnauthorizedPeer,
                "허용되지 않은 local 사용자입니다.",
                "로그인 코드를 발급하지 않았습니다.",
                "root 권한으로 명령을 다시 실행하십시오.",
            ),
        )
        .await;
    }
    let bytes = match tokio::time::timeout(Duration::from_secs(2), read_request(&mut stream)).await
    {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => return Err(error),
        Err(_elapsed) => {
            return write_response(
                &mut stream,
                &error_response(
                    AdminErrorCode::InvalidRequest,
                    "관리 요청 읽기 시간이 초과됐습니다.",
                    "로그인 코드를 발급하지 않았습니다.",
                    "CLI 명령을 다시 실행하십시오.",
                ),
            )
            .await;
        }
    };
    let response = serde_json::from_slice::<AdminRequest>(&bytes).map_or_else(
        |_| {
            error_response(
                AdminErrorCode::InvalidRequest,
                "관리 요청 JSON이 올바르지 않습니다.",
                "로그인 코드를 발급하지 않았습니다.",
                "같은 버전의 vps-guard CLI를 사용하십시오.",
            )
        },
        |request| execute_request(&app, request),
    );
    write_response(&mut stream, &response).await
}

fn execute_request(app: &AppState, request: AdminRequest) -> AdminResponse {
    if request.schema_version != ADMIN_PROTOCOL_VERSION {
        return error_response(
            AdminErrorCode::InvalidRequest,
            "지원하지 않는 관리 protocol 버전입니다.",
            "로그인 코드를 발급하지 않았습니다.",
            "Control과 같은 버전의 vps-guard CLI를 사용하십시오.",
        );
    }
    match request.command {
        AdminCommand::IssueLoginCode { ttl_seconds }
            if (MIN_LOGIN_TTL_SECONDS..=MAX_LOGIN_TTL_SECONDS).contains(&ttl_seconds) =>
        {
            app.bootstrap
                .issue(Duration::from_secs(ttl_seconds))
                .map_or_else(
                    || {
                        error_response(
                            AdminErrorCode::InternalFailure,
                            "로그인 code 검증값을 만들지 못했습니다.",
                            "로그인 코드를 발급하지 않았습니다.",
                            "Control 상태를 확인하고 다시 시도하십시오.",
                        )
                    },
                    |issued| AdminResponse::LoginCode {
                        schema_version: ADMIN_PROTOCOL_VERSION,
                        login_code: issued.code,
                        expires_in_seconds: issued.expires_in_seconds,
                    },
                )
        }
        AdminCommand::IssueLoginCode { .. } => error_response(
            AdminErrorCode::InvalidRequest,
            "로그인 code TTL 범위가 올바르지 않습니다.",
            "로그인 코드를 발급하지 않았습니다.",
            "60초 이상 600초 이하 TTL을 사용하십시오.",
        ),
    }
}

async fn read_request(stream: &mut UnixStream) -> Result<Vec<u8>, std::io::Error> {
    let mut bytes = Vec::with_capacity(256);
    loop {
        let mut chunk = [0_u8; 512];
        let length = stream.read(&mut chunk).await?;
        if length == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..length]);
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "관리 요청이 크기 제한을 초과했습니다",
            ));
        }
        if bytes.last() == Some(&b'\n') {
            break;
        }
    }
    Ok(bytes)
}

async fn write_response(
    stream: &mut UnixStream,
    response: &AdminResponse,
) -> Result<(), std::io::Error> {
    let mut encoded = serde_json::to_vec(response)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    encoded.push(b'\n');
    stream.write_all(&encoded).await?;
    stream.shutdown().await
}

fn error_response(
    code: AdminErrorCode,
    problem: &str,
    impact: &str,
    next_action: &str,
) -> AdminResponse {
    AdminResponse::Error {
        schema_version: ADMIN_PROTOCOL_VERSION,
        code,
        problem: problem.to_owned(),
        impact: impact.to_owned(),
        next_action: next_action.to_owned(),
    }
}

const fn peer_allowed(peer_uid: u32, owner_uid: u32) -> bool {
    peer_uid == 0 || peer_uid == owner_uid
}

fn socket_io(operation: &'static str, path: &Path, source: std::io::Error) -> AdminSocketError {
    AdminSocketError::Io {
        operation,
        path: path.display().to_string(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::peer_allowed;

    #[test]
    fn only_root_or_service_owner_is_authorized() {
        assert!(peer_allowed(0, 991));
        assert!(peer_allowed(991, 991));
        assert!(!peer_allowed(1000, 991));
    }
}
