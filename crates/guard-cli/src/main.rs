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
    ApacheIngressConfig, ApacheIngressDirection, ApacheIngressDriver, AtomicJsonStore,
    DeploymentRestoreDriver, DeploymentStateConfig, DeploymentStateStore, IngressApplyDriver,
    IngressRestoreDriver, IngressStateConfig, IngressStateStore, IngressSwitchConfig,
    IngressSwitchDirection, IngressSwitchDriver, IngressTopology, MutationPlan, OperationKind,
    OperationPlan, OperationState, PlannedChange, SnapshotResource, apache_ingress_plan,
    deployment_restore_plan, execute_operation, ingress_apply_plan, ingress_restore_plan,
    ingress_switch_plan,
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
    /// public ingress exact snapshot·검증·복원을 실행합니다.
    IngressState {
        /// ingress state 하위 명령입니다.
        #[command(subcommand)]
        command: IngressStateCommand,
    },
    /// 승인된 Nginx ingress 후보를 typed transaction으로 전환합니다.
    IngressSwitch {
        /// ingress switch 하위 명령입니다.
        #[command(subcommand)]
        command: IngressSwitchCommand,
    },
    /// Apache public TLS 유지형 request path를 typed transaction으로 전환합니다.
    ApacheIngress {
        /// Apache ingress 하위 명령입니다.
        #[command(subcommand)]
        command: ApacheIngressCommand,
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

#[derive(Debug, Subcommand)]
enum IngressStateCommand {
    /// 변경 없이 Rust driver의 bounded scope를 출력합니다.
    Plan,
    /// 현재 public ingress 상태를 snapshot합니다.
    Snapshot {
        /// 운영 snapshot 또는 rollback checkpoint label입니다.
        #[arg(long, default_value = "direct")]
        label: String,
    },
    /// snapshot checksum, machine과 protected listener를 검증합니다.
    Verify {
        /// 검증할 `direct-*` direct child입니다.
        snapshot: PathBuf,
    },
    /// typed transaction과 자동 rollback으로 ingress snapshot을 복구합니다.
    Restore {
        /// 복구할 `direct-*` direct child입니다.
        snapshot: PathBuf,
        /// retry마다 같은 값을 사용하는 선택 transaction 식별자입니다.
        #[arg(long)]
        operation_id: Option<String>,
    },
    /// staged direct TLS 후보를 public ingress에 적용합니다.
    ApplyDirect {
        /// `/tmp/vpsguard-direct.*` staging directory입니다.
        #[arg(long)]
        stage: PathBuf,
        /// 재개에 사용할 선택 transaction 식별자입니다.
        #[arg(long)]
        operation_id: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum IngressSwitchCommand {
    /// 변경 없이 방향·경로·시간 예산 plan을 출력합니다.
    Plan {
        /// 전환 방향입니다.
        #[arg(long, value_enum)]
        direction: IngressSwitchDirectionArg,
    },
    /// 후보를 적용하고 probe 실패 시 자동 rollback합니다.
    Apply {
        /// 전환 방향입니다.
        #[arg(long, value_enum)]
        direction: IngressSwitchDirectionArg,
        /// 재개에 사용할 선택 transaction 식별자입니다.
        #[arg(long)]
        operation_id: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ApacheIngressCommand {
    /// 변경 없이 방향·경로·시간 예산 plan을 출력합니다.
    Plan {
        /// 전환 방향입니다.
        #[arg(long, value_enum)]
        direction: ApacheIngressDirectionArg,
    },
    /// 후보를 적용하고 Apache configtest 또는 probe 실패 시 자동 rollback합니다.
    Apply {
        /// 전환 방향입니다.
        #[arg(long, value_enum)]
        direction: ApacheIngressDirectionArg,
        /// 외부 Linux builder가 만든 `/tmp/vpsguard-apache.*` staging directory입니다.
        #[arg(long)]
        stage: Option<PathBuf>,
        /// 재개에 사용할 선택 transaction 식별자입니다.
        #[arg(long)]
        operation_id: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ApacheIngressDirectionArg {
    ToEdge,
    ToApache,
}

impl From<ApacheIngressDirectionArg> for ApacheIngressDirection {
    fn from(value: ApacheIngressDirectionArg) -> Self {
        match value {
            ApacheIngressDirectionArg::ToEdge => Self::ToEdge,
            ApacheIngressDirectionArg::ToApache => Self::ToApache,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum IngressSwitchDirectionArg {
    ToEdge,
    ToNginx,
}

impl From<IngressSwitchDirectionArg> for IngressSwitchDirection {
    fn from(value: IngressSwitchDirectionArg) -> Self {
        match value {
            IngressSwitchDirectionArg::ToEdge => Self::ToEdge,
            IngressSwitchDirectionArg::ToNginx => Self::ToNginx,
        }
    }
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
    ApachePublic,
    ApacheGuarded,
}

impl From<TopologyArg> for IngressTopology {
    fn from(value: TopologyArg) -> Self {
        match value {
            TopologyArg::NginxPublic => Self::NginxPublic,
            TopologyArg::VpsGuardPublic => Self::VpsGuardPublic,
            TopologyArg::ApachePublic => Self::ApachePublic,
            TopologyArg::ApacheGuarded => Self::ApacheGuarded,
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
    IngressState(#[from] guard_system::IngressStateError),
    #[error(transparent)]
    OperationEngine(#[from] guard_system::OperationEngineError),
    #[error("VPS_GUARD_RESTORE_CONFIRM=restore-deployment-snapshot 확인값이 필요합니다")]
    MissingRestoreConfirmation,
    #[error("VPS_GUARD_DIRECT_RESTORE_CONFIRM=restore-direct-snapshot 확인값이 필요합니다")]
    MissingIngressRestoreConfirmation,
    #[error("VPS_GUARD_INGRESS_CONFIRM이 요청 방향과 일치해야 합니다: expected={0}")]
    MissingIngressSwitchConfirmation(&'static str),
    #[error("VPS_GUARD_APACHE_INGRESS_CONFIRM이 요청 방향과 일치해야 합니다: expected={0}")]
    MissingApacheIngressConfirmation(&'static str),
    #[error("VPS_GUARD_DIRECT_CONFIRM=g7devops:direct-tls 확인값이 필요합니다")]
    MissingDirectApplyConfirmation,
    #[error("deployment snapshot 이름이 UTF-8 deploy-* 식별자가 아닙니다: {0}")]
    InvalidSnapshotName(String),
    #[error("ingress snapshot 이름이 UTF-8 direct-* 식별자가 아닙니다: {0}")]
    InvalidIngressSnapshotName(String),
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
        OpsCommand::IngressState { command } => execute_ingress_state(command),
        OpsCommand::IngressSwitch { command } => execute_ingress_switch(command),
        OpsCommand::ApacheIngress { command } => execute_apache_ingress(command),
    }
}

fn execute_apache_ingress(command: ApacheIngressCommand) -> Result<String, CliError> {
    let (direction_arg, apply, stage, operation_id) = match command {
        ApacheIngressCommand::Plan { direction } => (direction, false, None, None),
        ApacheIngressCommand::Apply {
            direction,
            stage,
            operation_id,
        } => (direction, true, stage, operation_id),
    };
    let direction: ApacheIngressDirection = direction_arg.into();
    let expected = match direction {
        ApacheIngressDirection::ToEdge => "to-edge",
        ApacheIngressDirection::ToApache => "to-apache",
    };
    let mut config = apache_ingress_config();
    config.stage_root = stage;
    let operation_id = operation_id.unwrap_or_else(|| {
        format!(
            "apache-ingress-{}-{}",
            expected.trim_start_matches("to-"),
            std::process::id()
        )
    });
    let plan = apache_ingress_plan(&operation_id, direction, &config);
    plan.validate()?;
    if !apply {
        return Ok(format!(
            "driver=guard-system\ndirection={expected}\nactive={}\npublic_link={}\nguarded_candidate={}\nbypass_candidate={}\norigin={}\npreserve: SSH, certificate, site data, non-web listeners\nplan_sha256={}",
            config.active_vhost.display(),
            config.public_link.display(),
            config.guarded_candidate.display(),
            config.bypass_candidate.display(),
            config.origin_vhost.display(),
            plan.sha256()?
        ));
    }
    if env::var("VPS_GUARD_APACHE_INGRESS_CONFIRM").as_deref() != Ok(expected) {
        return Err(CliError::MissingApacheIngressConfirmation(expected));
    }
    let transaction = config.backup_root.join("transactions").join(&operation_id);
    let state_path = transaction.join("state.json");
    let checkpoint = transaction.join("rollback.json");
    let lock_path = if config.state.test_root.is_some() {
        config.backup_root.join("operation.lock")
    } else {
        PathBuf::from("/run/vps-guard/operation.lock")
    };
    let mut driver = ApacheIngressDriver::new(config, direction, checkpoint)?;
    let state = execute_operation(&plan, &state_path, lock_path, &mut driver)?;
    let rollback = driver
        .rollback_snapshot()
        .map_or_else(|| "none".to_owned(), |path| path.display().to_string());
    Ok(format!(
        "apache_ingress=pass\ndirection={expected}\ntransaction_status={:?}\ntransaction_state={}\nrollback_snapshot={rollback}",
        state.status,
        state_path.display()
    ))
}

fn execute_ingress_switch(command: IngressSwitchCommand) -> Result<String, CliError> {
    let (direction_arg, apply, operation_id) = match command {
        IngressSwitchCommand::Plan { direction } => (direction, false, None),
        IngressSwitchCommand::Apply {
            direction,
            operation_id,
        } => (direction, true, operation_id),
    };
    let direction: IngressSwitchDirection = direction_arg.into();
    let expected = match direction {
        IngressSwitchDirection::ToEdge => "to-edge",
        IngressSwitchDirection::ToNginx => "to-nginx",
    };
    let config = ingress_switch_config();
    let operation_id = operation_id.unwrap_or_else(|| {
        format!(
            "ingress-switch-{}-{}",
            expected.trim_start_matches("to-"),
            std::process::id()
        )
    });
    let plan = ingress_switch_plan(&operation_id, direction, &config);
    plan.validate()?;
    if !apply {
        return Ok(format!(
            "driver=guard-system\ndirection={expected}\nactive={}\nedge_candidate={}\nnginx_candidate={}\npreserve: SSH, certificates, site data\nplan_sha256={}",
            config.active_config.display(),
            config.edge_candidate.display(),
            config.nginx_candidate.display(),
            plan.sha256()?
        ));
    }
    if env::var("VPS_GUARD_INGRESS_CONFIRM").as_deref() != Ok(expected) {
        return Err(CliError::MissingIngressSwitchConfirmation(expected));
    }
    let transaction = config.backup_root.join("transactions").join(&operation_id);
    let state_path = transaction.join("state.json");
    let checkpoint = transaction.join("rollback.json");
    let lock_path = if config.state.test_root.is_some() {
        config.backup_root.join("operation.lock")
    } else {
        PathBuf::from("/run/vps-guard/operation.lock")
    };
    let mut driver = IngressSwitchDriver::new(config, direction, checkpoint)?;
    let state = execute_operation(&plan, &state_path, lock_path, &mut driver)?;
    let rollback = driver
        .rollback_snapshot()
        .map_or_else(|| "none".to_owned(), |path| path.display().to_string());
    Ok(format!(
        "ingress_switch=pass\ndirection={expected}\ntransaction_status={:?}\ntransaction_state={}\nrollback_snapshot={rollback}",
        state.status,
        state_path.display()
    ))
}

fn execute_ingress_state(command: IngressStateCommand) -> Result<String, CliError> {
    let config = ingress_state_config();
    match command {
        IngressStateCommand::Plan => {
            let plan = ingress_restore_plan(
                "ingress-restore-plan",
                "ingress-snapshot",
                IngressTopology::NginxPublic,
                IngressTopology::VpsGuardPublic,
            );
            plan.validate()?;
            Ok(format!(
                "driver=guard-system\nsnapshot_root={}\nrestore_scope=approved-ingress-only\nprotected=ssh,certificates,site,non-web-listeners\nplan_sha256={}",
                config.snapshot_root.display(),
                plan.sha256()?
            ))
        }
        IngressStateCommand::Snapshot { label } => {
            let mut store = IngressStateStore::new(config);
            let snapshot = store.create_snapshot(&label)?;
            Ok(format!("snapshot={}", snapshot.display()))
        }
        IngressStateCommand::Verify { snapshot } => {
            let mut store = IngressStateStore::new(config);
            store.verify_snapshot(&snapshot)?;
            Ok(format!("protected=pass\nsnapshot={}", snapshot.display()))
        }
        IngressStateCommand::Restore {
            snapshot,
            operation_id,
        } => {
            if env::var("VPS_GUARD_DIRECT_RESTORE_CONFIRM").as_deref()
                != Ok("restore-direct-snapshot")
            {
                return Err(CliError::MissingIngressRestoreConfirmation);
            }
            let snapshot_id = snapshot
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| name.starts_with("direct-"))
                .ok_or_else(|| {
                    CliError::InvalidIngressSnapshotName(snapshot.display().to_string())
                })?;
            let mut store = IngressStateStore::new(config.clone());
            let source = store.current_topology()?;
            let target = store.snapshot_topology(&snapshot)?;
            let operation_id = operation_id
                .unwrap_or_else(|| format!("ingress-restore-{snapshot_id}-{}", std::process::id()));
            let plan = ingress_restore_plan(&operation_id, snapshot_id, source, target);
            let (state_path, lock_path) = ingress_operation_paths(&config, &operation_id);
            let checkpoint_path = state_path.with_file_name("rollback.json");
            let mut driver =
                IngressRestoreDriver::with_checkpoint(store, &snapshot, checkpoint_path)?;
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
        IngressStateCommand::ApplyDirect {
            stage,
            operation_id,
        } => {
            if env::var("VPS_GUARD_DIRECT_CONFIRM").as_deref() != Ok("g7devops:direct-tls") {
                return Err(CliError::MissingDirectApplyConfirmation);
            }
            let operation_id = operation_id
                .unwrap_or_else(|| format!("direct-ingress-apply-{}", std::process::id()));
            let (state_path, lock_path) = ingress_operation_paths(&config, &operation_id);
            let transaction = state_path.parent().ok_or_else(|| {
                CliError::InvalidIngressSnapshotName(state_path.display().to_string())
            })?;
            let candidate_store =
                AtomicJsonStore::<PathBuf>::new(transaction.join("candidate.json"));
            let mut store = IngressStateStore::new(config);
            let candidate = if candidate_store.path().exists() {
                candidate_store.read()?
            } else {
                let candidate = store.create_direct_candidate_snapshot(&stage)?;
                candidate_store.write(&candidate)?;
                candidate
            };
            let candidate_id = candidate
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    CliError::InvalidIngressSnapshotName(candidate.display().to_string())
                })?;
            let plan = ingress_apply_plan(&operation_id, candidate_id);
            let mut driver = IngressApplyDriver::with_checkpoint(
                store,
                &candidate,
                transaction.join("rollback.json"),
            )?;
            let state = execute_operation(&plan, &state_path, lock_path, &mut driver)?;
            let rollback = driver
                .rollback_snapshot()
                .map_or_else(|| "none".to_owned(), |path| path.display().to_string());
            Ok(format!(
                "direct_apply=pass\ncandidate={}\ntransaction_status={:?}\ntransaction_state={}\nrollback_snapshot={rollback}",
                candidate.display(),
                state.status,
                state_path.display()
            ))
        }
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

fn ingress_state_config() -> IngressStateConfig {
    let snapshot_root = env::var_os("VPS_GUARD_DIRECT_SNAPSHOT_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/backups/vps-guard/ingress"));
    let mut config = match env::var_os("VPS_GUARD_TEST_ROOT") {
        Some(root) => IngressStateConfig::fixture(
            PathBuf::from(root),
            env::var_os("VPS_GUARD_FAKE_STATE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| snapshot_root.join("fixture-state")),
            snapshot_root,
        ),
        None => IngressStateConfig::production(snapshot_root),
    };
    config.fixture_cutover_ms = env::var("VPS_GUARD_TEST_CUTOVER_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
        .saturating_mul(1_000);
    config
}

fn ingress_switch_config() -> IngressSwitchConfig {
    let probe_url = env::var("VPS_GUARD_INGRESS_PROBE_URL").unwrap_or_default();
    let mut config = match env::var_os("VPS_GUARD_TEST_ROOT") {
        Some(root) => IngressSwitchConfig::fixture(
            PathBuf::from(root),
            env::var_os("VPS_GUARD_FAKE_STATE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/tmp/vps-guard-fixture-state")),
            env::var_os("VPS_GUARD_BACKUP_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/tmp/vps-guard-fixture-backups")),
        ),
        None => IngressSwitchConfig::production(probe_url),
    };
    if let Some(path) = env::var_os("VPS_GUARD_NGINX_ACTIVE") {
        config.active_config = PathBuf::from(path);
    }
    if let Some(path) = env::var_os("VPS_GUARD_NGINX_EDGE_CANDIDATE") {
        config.edge_candidate = PathBuf::from(path);
    }
    if let Some(path) = env::var_os("VPS_GUARD_NGINX_BYPASS_CANDIDATE") {
        config.nginx_candidate = PathBuf::from(path);
    }
    if let Some(path) = env::var_os("VPS_GUARD_INGRESS_STAGE") {
        config.stage_root = Some(PathBuf::from(path));
    }
    if let Some(path) = env::var_os("VPS_GUARD_BACKUP_ROOT") {
        config.backup_root = PathBuf::from(path);
    }
    config.fixture_probe_failure = env::var("VPS_GUARD_FAKE_CURL_FAIL").as_deref() == Ok("1");
    config
}

fn apache_ingress_config() -> ApacheIngressConfig {
    let probe_url = env::var("VPS_GUARD_APACHE_PROBE_URL").unwrap_or_default();
    let mut config = match env::var_os("VPS_GUARD_TEST_ROOT") {
        Some(root) => ApacheIngressConfig::fixture(
            PathBuf::from(root),
            env::var_os("VPS_GUARD_FAKE_STATE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/tmp/vps-guard-fixture-state")),
            env::var_os("VPS_GUARD_APACHE_BACKUP_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/tmp/vps-guard-apache-backups")),
        ),
        None => ApacheIngressConfig::production(probe_url),
    };
    if let Some(path) = env::var_os("VPS_GUARD_APACHE_ACTIVE") {
        config.active_vhost = PathBuf::from(path);
    }
    if let Some(path) = env::var_os("VPS_GUARD_APACHE_PUBLIC_LINK") {
        config.public_link = PathBuf::from(path);
    }
    if let Some(path) = env::var_os("VPS_GUARD_APACHE_CERTIFICATE") {
        config.certificate = PathBuf::from(path);
    }
    if let Some(path) = env::var_os("VPS_GUARD_APACHE_PROBE_CA") {
        config.probe_ca_certificate = Some(PathBuf::from(path));
    }
    if let Some(path) = env::var_os("VPS_GUARD_APACHE_BACKUP_ROOT") {
        config.backup_root = PathBuf::from(path);
    }
    config.fixture_probe_failure = env::var("VPS_GUARD_FAKE_CURL_FAIL").as_deref() == Ok("1");
    config
}

fn ingress_operation_paths(config: &IngressStateConfig, operation_id: &str) -> (PathBuf, PathBuf) {
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
        "/usr/local/bin/vps-guard-privileged",
        "/usr/local/bin/vps-guard-edge",
        "/usr/local/lib/vps-guard/current",
        "/etc/vps-guard/config.toml",
        "/etc/vps-guard/crawler-networks.json",
        "/etc/pam.d/vps-guard",
        "/etc/systemd/system/vps-guard-control.service",
        "/etc/systemd/system/vps-guard-privileged.service",
        "/etc/systemd/system/vps-guard-privileged.socket",
        "/etc/systemd/system/vps-guard-edge.service",
    ]
    .into_iter()
    .map(|path| SnapshotResource::OwnedPath {
        path: PathBuf::from(path),
    })
    .chain(std::iter::once(SnapshotResource::OwnedDirectoryPresence {
        path: PathBuf::from("/etc/vps-guard/apache"),
    }))
    .chain(
        [
            "nginx.service",
            "vps-guard-control.service",
            "vps-guard-privileged.service",
            "vps-guard-privileged.socket",
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
    use super::{
        IngressStateCommand, IngressSwitchCommand, IngressSwitchDirectionArg,
        execute_ingress_state, execute_ingress_switch, read_config, shadow_plan,
    };

    #[test]
    fn smoke_config_produces_safe_plan() -> Result<(), Box<dyn std::error::Error>> {
        let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../configs/vps-guard.smoke.toml");
        let config = read_config(&config_path)?;
        assert_eq!(shadow_plan(&config).validate(), Ok(()));
        Ok(())
    }

    #[test]
    fn ingress_plans_use_typed_drivers() -> Result<(), Box<dyn std::error::Error>> {
        let state = execute_ingress_state(IngressStateCommand::Plan)?;
        assert!(state.contains("driver=guard-system"));
        assert!(state.contains("restore_scope=approved-ingress-only"));

        let switch = execute_ingress_switch(IngressSwitchCommand::Plan {
            direction: IngressSwitchDirectionArg::ToEdge,
        })?;
        assert!(switch.contains("driver=guard-system"));
        assert!(switch.contains("direction=to-edge"));
        assert!(switch.contains("preserve: SSH, certificates, site data"));

        let bypass = execute_ingress_switch(IngressSwitchCommand::Plan {
            direction: IngressSwitchDirectionArg::ToNginx,
        })?;
        assert!(bypass.contains("direction=to-nginx"));
        Ok(())
    }
}
