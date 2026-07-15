//! `vps-guard` 운영 CLI 진입점입니다.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use guard_core::{
    ADMIN_PROTOCOL_VERSION, AdminCommand, AdminRequest, AdminResponse, GuardConfig, GuardState,
    PolicySnapshot,
};
use guard_system::{AtomicJsonStore, MutationPlan, PlannedChange};
use thiserror::Error;
use time::OffsetDateTime;

#[derive(Debug, Parser)]
#[command(name = "vps-guard", version, about = "VPSGuard 운영 CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// versioned TOML을 parse하고 의미 검증합니다.
    CheckConfig {
        /// 검사할 config 경로입니다.
        #[arg(short, long)]
        config: PathBuf,
    },
    /// 변경 없이 shadow 설치 plan을 JSON으로 출력합니다.
    Plan {
        /// 검사할 config 경로입니다.
        #[arg(short, long)]
        config: PathBuf,
    },
    /// 원자 저장된 control 상태를 JSON으로 출력합니다.
    Status {
        /// state JSON 경로입니다.
        #[arg(short, long, default_value = "/var/lib/vps-guard/state.json")]
        state: PathBuf,
    },
    /// policy schema, hash와 TTL을 검증합니다.
    VerifyPolicy {
        /// policy JSON 경로입니다.
        #[arg(short, long)]
        policy: PathBuf,
    },
    /// local peer credential로 짧은 단회 웹 로그인 코드를 발급합니다.
    IssueLoginCode {
        /// Control local 관리자 socket입니다.
        #[arg(short, long, default_value = "/run/vps-guard/admin.sock")]
        socket: PathBuf,
        /// 로그인 코드 유효시간입니다.
        #[arg(long, default_value_t = 300)]
        ttl_seconds: u64,
    },
}

#[derive(Debug, Error)]
enum CliError {
    #[error("파일을 읽지 못했습니다: path={path}, cause={source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error(transparent)]
    Config(#[from] guard_core::ConfigError),
    #[error(transparent)]
    Store(#[from] guard_system::StoreError),
    #[error("JSON 처리 실패: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Policy(#[from] guard_core::PolicyError),
    #[error(transparent)]
    Plan(#[from] guard_system::PlanError),
    #[error(transparent)]
    State(#[from] guard_core::StateError),
    #[error("관리 socket 요청 실패: operation={operation}, path={path}, cause={source}")]
    AdminSocket {
        /// 실패한 socket 작업입니다.
        operation: &'static str,
        /// 대상 socket입니다.
        path: String,
        /// 원본 I/O 오류입니다.
        source: std::io::Error,
    },
    #[error("관리 응답 처리 실패: {0}")]
    AdminResponse(serde_json::Error),
    #[error("관리 명령 거부: code={code}, problem={problem}, impact={impact}, next={next_action}")]
    AdminRejected {
        /// 안정적인 오류 code입니다.
        code: String,
        /// 발생한 문제입니다.
        problem: String,
        /// 수행되지 않은 작업 또는 영향입니다.
        impact: String,
        /// 다음 조치입니다.
        next_action: String,
    },
    #[error("로그인 code TTL은 60..=600초여야 합니다: actual={0}")]
    InvalidLoginTtl(u64),
}

fn main() -> ExitCode {
    match execute(Cli::parse()) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("VPSGuard 오류: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute(cli: Cli) -> Result<String, CliError> {
    match cli.command {
        Command::CheckConfig { config } => {
            let parsed = read_config(&config)?;
            Ok(format!(
                "config valid: schema={} edge={} origin={} ui={} inspection={}",
                parsed.schema_version,
                parsed.edge.http_bind,
                parsed.origin.address,
                parsed.ui.bind,
                parsed.detection.inspection.as_str()
            ))
        }
        Command::Plan { config } => {
            let parsed = read_config(&config)?;
            let plan = shadow_plan(&parsed);
            plan.validate()?;
            Ok(serde_json::to_string_pretty(&plan)?)
        }
        Command::Status { state } => {
            let store = AtomicJsonStore::<GuardState>::new(state);
            let state = store.read()?;
            state.validate()?;
            Ok(serde_json::to_string_pretty(&state)?)
        }
        Command::VerifyPolicy { policy } => {
            let source = read(&policy)?;
            let policy: PolicySnapshot = serde_json::from_str(&source)?;
            policy.validate_at(OffsetDateTime::now_utc())?;
            Ok(format!("policy valid: version={}", policy.policy_version))
        }
        Command::IssueLoginCode {
            socket,
            ttl_seconds,
        } => issue_login_code(&socket, ttl_seconds),
    }
}

fn issue_login_code(socket: &Path, ttl_seconds: u64) -> Result<String, CliError> {
    if !(60..=600).contains(&ttl_seconds) {
        return Err(CliError::InvalidLoginTtl(ttl_seconds));
    }
    let mut stream = UnixStream::connect(socket)
        .map_err(|source| admin_socket_error("connect", socket, source))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|source| admin_socket_error("set_read_timeout", socket, source))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|source| admin_socket_error("set_write_timeout", socket, source))?;
    let request = AdminRequest {
        schema_version: ADMIN_PROTOCOL_VERSION,
        command: AdminCommand::IssueLoginCode { ttl_seconds },
    };
    let mut encoded = serde_json::to_vec(&request).map_err(CliError::AdminResponse)?;
    encoded.push(b'\n');
    stream
        .write_all(&encoded)
        .map_err(|source| admin_socket_error("write", socket, source))?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|source| admin_socket_error("shutdown_write", socket, source))?;
    let mut response = Vec::with_capacity(512);
    stream
        .take(8_193)
        .read_to_end(&mut response)
        .map_err(|source| admin_socket_error("read", socket, source))?;
    if response.len() > 8_192 {
        return Err(admin_socket_error(
            "read",
            socket,
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "관리 응답이 크기 제한을 초과했습니다",
            ),
        ));
    }
    match serde_json::from_slice::<AdminResponse>(&response).map_err(CliError::AdminResponse)? {
        AdminResponse::LoginCode {
            schema_version,
            login_code,
            expires_in_seconds,
        } if schema_version == ADMIN_PROTOCOL_VERSION => Ok(format!(
            "VPSGuard 단회 로그인 코드: {login_code}\n유효시간: {expires_in_seconds}초"
        )),
        AdminResponse::LoginCode { schema_version, .. } => Err(CliError::AdminRejected {
            code: "UNSUPPORTED_RESPONSE_VERSION".to_owned(),
            problem: format!("관리 응답 버전을 지원하지 않습니다: {schema_version}"),
            impact: "로그인 코드를 표시하지 않았습니다.".to_owned(),
            next_action: "Control과 같은 버전의 CLI를 사용하십시오.".to_owned(),
        }),
        AdminResponse::Error {
            code,
            problem,
            impact,
            next_action,
            ..
        } => Err(CliError::AdminRejected {
            code: format!("{code:?}"),
            problem,
            impact,
            next_action,
        }),
    }
}

fn admin_socket_error(operation: &'static str, path: &Path, source: std::io::Error) -> CliError {
    CliError::AdminSocket {
        operation,
        path: path.display().to_string(),
        source,
    }
}

fn read_config(path: &PathBuf) -> Result<GuardConfig, CliError> {
    GuardConfig::from_toml(&read(path)?).map_err(CliError::Config)
}

fn read(path: &PathBuf) -> Result<String, CliError> {
    fs::read_to_string(path).map_err(|source| CliError::Read {
        path: path.display().to_string(),
        source,
    })
}

fn shadow_plan(config: &GuardConfig) -> MutationPlan {
    MutationPlan {
        schema_version: 1,
        operation_id: format!("shadow-{}", config.schema_version),
        changes: vec![
            PlannedChange::WriteOwnedFile {
                path: PathBuf::from("/etc/vps-guard/config.toml"),
            },
            PlannedChange::WriteOwnedFile {
                path: PathBuf::from("/var/lib/vps-guard/state.json"),
            },
            PlannedChange::RestartOwnedService {
                unit: "vps-guard-control.service".to_owned(),
            },
            PlannedChange::RestartOwnedService {
                unit: "vps-guard-edge.service".to_owned(),
            },
        ],
        preserve: vec![
            "ssh".to_owned(),
            "certificates".to_owned(),
            "site-data".to_owned(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::{read_config, shadow_plan};

    #[test]
    fn smoke_config_produces_safe_plan() -> Result<(), Box<dyn std::error::Error>> {
        let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../configs/vps-guard.smoke.toml");
        let config = read_config(&config_path)?;
        assert_eq!(shadow_plan(&config).validate(), Ok(()));
        Ok(())
    }
}
