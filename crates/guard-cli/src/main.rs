//! `vps-guard` 운영 CLI 진입점입니다.

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use guard_core::{
    ADMIN_PROTOCOL_VERSION, AdminCommand, AdminRequest, AdminResponse, GuardConfig, GuardState,
    PolicySnapshot,
};
use guard_system::{
    AtomicJsonStore, DeploymentRestoreDriver, DeploymentStateConfig, DeploymentStateStore,
    IngressTopology, MutationPlan, OperationKind, OperationPlan, OperationState, PlannedChange,
    SnapshotResource, deployment_restore_plan, execute_operation,
};
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
    /// 짧은 순단 apply·restore transaction plan과 상태를 관리합니다.
    Ops {
        /// 운영 transaction 하위 명령입니다.
        #[command(subcommand)]
        command: OpsCommand,
    },
}

#[derive(Debug, Subcommand)]
enum OpsCommand {
    /// 변경하지 않고 bounded snapshot 범위와 시간 예산 plan을 생성합니다.
    Plan {
        /// 재개와 중복 실행 보고에 사용할 식별자입니다.
        #[arg(long)]
        operation_id: String,
        /// 수행할 작업 종류입니다.
        #[arg(long, value_enum)]
        kind: OpsKindArg,
        /// release commit 또는 snapshot 식별자입니다.
        #[arg(long)]
        release_id: String,
        /// 현재 public ingress topology입니다.
        #[arg(long, value_enum)]
        source: TopologyArg,
        /// 완료 후 public ingress topology입니다.
        #[arg(long, value_enum)]
        target: TopologyArg,
        /// 정확히 snapshot할 Nginx ingress 파일입니다.
        #[arg(long, required = true)]
        ingress_file: Vec<PathBuf>,
        /// fingerprint만 보존할 공개 인증서 파일입니다.
        #[arg(long)]
        certificate: PathBuf,
        /// plan을 원자 저장할 선택 경로입니다.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// 원자 저장된 operation ledger를 출력합니다.
    Status {
        /// transaction state JSON 경로입니다.
        #[arg(
            long,
            default_value = "/var/backups/vps-guard/transactions/active/state.json"
        )]
        state: PathBuf,
    },
    /// VPSGuard-owned first-install snapshot·검증·복원을 실행합니다.
    DeploymentState {
        /// deployment state 하위 명령입니다.
        #[command(subcommand)]
        command: DeploymentStateCommand,
    },
}

#[derive(Debug, Subcommand)]
enum DeploymentStateCommand {
    /// 변경 없이 Rust driver의 bounded scope를 출력합니다.
    Plan,
    /// 현재 VPSGuard-owned 상태를 snapshot합니다.
    Snapshot,
    /// snapshot checksum, machine과 protected boundary를 검증합니다.
    Verify {
        /// 검증할 `deploy-*` direct child입니다.
        snapshot: PathBuf,
    },
    /// typed transaction과 자동 rollback으로 snapshot을 복구합니다.
    Restore {
        /// 복구할 `deploy-*` direct child입니다.
        snapshot: PathBuf,
        /// retry마다 새 값을 사용하는 선택 transaction 식별자입니다.
        #[arg(long)]
        operation_id: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OpsKindArg {
    Apply,
    Restore,
    Update,
    BypassEnable,
    BypassDisable,
}

impl From<OpsKindArg> for OperationKind {
    fn from(value: OpsKindArg) -> Self {
        match value {
            OpsKindArg::Apply => Self::Apply,
            OpsKindArg::Restore => Self::Restore,
            OpsKindArg::Update => Self::Update,
            OpsKindArg::BypassEnable => Self::BypassEnable,
            OpsKindArg::BypassDisable => Self::BypassDisable,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TopologyArg {
    NginxPublic,
    VpsGuardPublic,
}

impl From<TopologyArg> for IngressTopology {
    fn from(value: TopologyArg) -> Self {
        match value {
            TopologyArg::NginxPublic => Self::NginxPublic,
            TopologyArg::VpsGuardPublic => Self::VpsGuardPublic,
        }
    }
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
    OperationContract(#[from] guard_system::OperationContractError),
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
    #[error(transparent)]
    DeploymentState(#[from] guard_system::DeploymentStateError),
    #[error(transparent)]
    OperationEngine(#[from] guard_system::OperationEngineError),
    #[error("VPS_GUARD_RESTORE_CONFIRM=restore-deployment-snapshot 확인값이 필요합니다")]
    MissingRestoreConfirmation,
    #[error("deployment snapshot 이름이 UTF-8 deploy-* 식별자가 아닙니다: {0}")]
    InvalidSnapshotName(String),
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
                "config valid: schema={} edge={} origin={} ui={} inspection={} csp={} auth_rpm={}",
                parsed.schema_version,
                parsed.edge.http_bind,
                parsed.origin.address,
                parsed.ui.bind,
                parsed.detection.inspection.as_str(),
                parsed.security.csp_mode.as_str(),
                parsed.security.auth_rate_limit_rpm
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
        Command::Ops { command } => execute_ops(command),
    }
}

fn execute_ops(command: OpsCommand) -> Result<String, CliError> {
    match command {
        OpsCommand::Plan {
            operation_id,
            kind,
            release_id,
            source,
            target,
            ingress_file,
            certificate,
            output,
        } => {
            let mut resources = default_operation_resources();
            resources.extend(
                ingress_file
                    .into_iter()
                    .map(|path| SnapshotResource::IngressFile { path }),
            );
            resources.push(SnapshotResource::CertificateFingerprint { path: certificate });
            resources.push(SnapshotResource::ListenerInventory);
            let plan = OperationPlan::new(
                operation_id,
                kind.into(),
                release_id,
                source.into(),
                target.into(),
                resources,
            );
            plan.validate()?;
            let plan_sha256 = plan.sha256()?;
            if let Some(path) = output {
                AtomicJsonStore::<OperationPlan>::new(&path).write(&plan)?;
                Ok(format!(
                    "operation plan saved: path={} sha256={plan_sha256}",
                    path.display()
                ))
            } else {
                Ok(format!(
                    "plan_sha256={plan_sha256}\n{}",
                    serde_json::to_string_pretty(&plan)?
                ))
            }
        }
        OpsCommand::Status { state } => {
            let state = AtomicJsonStore::<OperationState>::new(state).read()?;
            Ok(serde_json::to_string_pretty(&state)?)
        }
        OpsCommand::DeploymentState { command } => execute_deployment_state(command),
    }
}

fn execute_deployment_state(command: DeploymentStateCommand) -> Result<String, CliError> {
    let config = deployment_state_config();
    match command {
        DeploymentStateCommand::Plan => {
            let plan = deployment_restore_plan("deployment-restore-plan", "deployment-snapshot");
            plan.validate()?;
            Ok(format!(
                "driver=guard-system\nsnapshot_root={}\nrestore_scope=vpsguard-owned-only\nprotected=ssh,nginx,certificates,g7-site,non-vpsguard-listeners\nplan_sha256={}",
                config.snapshot_root.display(),
                plan.sha256()?
            ))
        }
        DeploymentStateCommand::Snapshot => {
            let mut store = DeploymentStateStore::new(config);
            let snapshot = store.create_snapshot()?;
            Ok(format!("snapshot={}", snapshot.display()))
        }
        DeploymentStateCommand::Verify { snapshot } => {
            let mut store = DeploymentStateStore::new(config);
            store.verify_snapshot(&snapshot)?;
            Ok(format!("protected=pass\nsnapshot={}", snapshot.display()))
        }
        DeploymentStateCommand::Restore {
            snapshot,
            operation_id,
        } => {
            if env::var("VPS_GUARD_RESTORE_CONFIRM").as_deref() != Ok("restore-deployment-snapshot")
            {
                return Err(CliError::MissingRestoreConfirmation);
            }
            let snapshot_id = snapshot
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| name.starts_with("deploy-"))
                .ok_or_else(|| CliError::InvalidSnapshotName(snapshot.display().to_string()))?;
            let operation_id = operation_id.unwrap_or_else(|| {
                format!("deployment-restore-{snapshot_id}-{}", std::process::id())
            });
            let plan = deployment_restore_plan(&operation_id, snapshot_id);
            let (state_path, lock_path) = deployment_operation_paths(&config, &operation_id);
            let checkpoint_path = state_path.with_file_name("rollback.json");
            let store = DeploymentStateStore::new(config);
            let mut driver =
                DeploymentRestoreDriver::with_checkpoint(store, &snapshot, checkpoint_path)?;
            let state = execute_operation(&plan, &state_path, lock_path, &mut driver)?;
            let rollback_snapshot = driver
                .rollback_snapshot()
                .map_or_else(|| "none".to_owned(), |path| path.display().to_string());
            Ok(format!(
                "restore=pass\nsnapshot={}\ntransaction_status={:?}\ntransaction_state={}\nrollback_snapshot={rollback_snapshot}",
                snapshot.display(),
                state.status,
                state_path.display()
            ))
        }
    }
}

fn deployment_state_config() -> DeploymentStateConfig {
    let snapshot_root = env::var_os("VPS_GUARD_SNAPSHOT_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/backups/vps-guard/deployments"));
    match env::var_os("VPS_GUARD_TEST_ROOT") {
        Some(root) => DeploymentStateConfig::fixture(PathBuf::from(root), snapshot_root),
        None => DeploymentStateConfig::production(snapshot_root),
    }
}

fn deployment_operation_paths(
    config: &DeploymentStateConfig,
    operation_id: &str,
) -> (PathBuf, PathBuf) {
    if config.test_root.is_some() {
        (
            config
                .snapshot_root
                .join("transactions")
                .join(operation_id)
                .join("state.json"),
            config.snapshot_root.join("operation.lock"),
        )
    } else {
        (
            PathBuf::from("/var/backups/vps-guard/transactions")
                .join(operation_id)
                .join("state.json"),
            PathBuf::from("/run/vps-guard/operation.lock"),
        )
    }
}

fn default_operation_resources() -> Vec<SnapshotResource> {
    [
        "/usr/local/bin/vps-guard",
        "/usr/local/bin/vps-guard-control",
        "/usr/local/bin/vps-guard-edge",
        "/usr/local/lib/vps-guard/current",
        "/etc/vps-guard/config.toml",
        "/etc/systemd/system/vps-guard-control.service",
        "/etc/systemd/system/vps-guard-edge.service",
    ]
    .into_iter()
    .map(|path| SnapshotResource::OwnedPath {
        path: PathBuf::from(path),
    })
    .chain(
        [
            "nginx.service",
            "vps-guard-control.service",
            "vps-guard-edge.service",
        ]
        .into_iter()
        .map(|unit| SnapshotResource::Service {
            unit: unit.to_owned(),
        }),
    )
    .collect()
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
