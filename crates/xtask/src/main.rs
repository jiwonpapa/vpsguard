//! 저장소의 재현 가능한 개발·검증·릴리스 명령을 한 진입점으로 제공합니다.

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let mut arguments = env::args().skip(1);
    let Some(task) = arguments.next() else {
        eprintln!("usage: cargo xtask <check|test|coverage|integration|load|web|release> [target]");
        return ExitCode::from(2);
    };
    let release_target = arguments
        .next()
        .unwrap_or_else(|| "x86_64-unknown-linux-gnu".to_owned());
    let root = workspace_root();
    let result = match task.as_str() {
        "check" => script(&root, "scripts/check.sh", &[]),
        "test" => command(
            &root,
            "cargo",
            &[
                "nextest",
                "run",
                "--locked",
                "--workspace",
                "--all-features",
                "--profile",
                "ci",
            ],
        ),
        "coverage" => script(&root, "scripts/coverage-gate.sh", &[]),
        "integration" => script(&root, "scripts/integration-gate.sh", &[])
            .and_then(|()| script(&root, "scripts/ops-harness.sh", &[])),
        "load" => script(&root, "scripts/load-regression-gate.sh", &[]),
        "web" => command(&root.join("web"), "bun", &["run", "check"])
            .and_then(|()| command(&root.join("web"), "bun", &["run", "test:e2e"])),
        "release" => script(
            &root,
            "scripts/build-release.sh",
            &[release_target.as_str()],
        ),
        _ => {
            eprintln!("unknown xtask: {task}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask {task} failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

fn script(root: &Path, path: &str, arguments: &[&str]) -> Result<(), String> {
    let mut args = vec![path];
    args.extend_from_slice(arguments);
    command(root, "bash", &args)
}

fn command(root: &Path, program: &str, arguments: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(arguments)
        .current_dir(root)
        .status()
        .map_err(|error| format!("{program} 실행 실패: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} 종료 코드: {status}"))
    }
}
