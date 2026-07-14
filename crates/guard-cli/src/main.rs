//! `vps-guard` 운영 CLI 진입점입니다.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use guard_core::{GuardConfig, GuardState, PolicySnapshot};
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
                "config valid: schema={} edge={} origin={} ui={}",
                parsed.schema_version, parsed.edge.http_bind, parsed.origin.address, parsed.ui.bind
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
