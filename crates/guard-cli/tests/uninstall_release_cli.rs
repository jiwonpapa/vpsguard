//! OPS-006 CLI가 bounded release snapshot·restore 확인값을 강제하는 회귀입니다.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn uninstall_release_cli_round_trip_restores_exact_binaries()
-> Result<(), Box<dyn std::error::Error>> {
    let suffix = format!(
        "{}{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    );
    let temporary = std::env::temp_dir().join(format!("vpsguard-uninstall-cli-{suffix}"));
    let root = temporary.join("root");
    let snapshots = temporary.join("snapshots");
    let release_root = root.join("usr/local/lib/vps-guard/releases");
    let release = "0123456789abcdef0123456789abcdef01234567";
    write_release(&release_root, release)?;
    let common = [
        ("VPS_GUARD_TEST_ROOT", root.to_str().ok_or("root UTF-8")?),
        (
            "VPS_GUARD_UNINSTALL_SNAPSHOT_ROOT",
            snapshots.to_str().ok_or("snapshot UTF-8")?,
        ),
    ];
    let snapshot_output = run(
        ["ops", "uninstall-release", "snapshot"],
        &common,
        Some("snapshot-release-tree"),
    )?;
    let snapshot = stdout(&snapshot_output)?
        .lines()
        .find_map(|line| line.strip_prefix("uninstall_snapshot="))
        .map(PathBuf::from)
        .ok_or("snapshot output missing")?;
    run(
        [
            "ops",
            "uninstall-release",
            "verify",
            snapshot.to_str().ok_or("snapshot UTF-8")?,
        ],
        &common,
        None,
    )?;

    fs::remove_dir_all(&release_root)?;
    run(
        [
            "ops",
            "uninstall-release",
            "restore",
            snapshot.to_str().ok_or("snapshot UTF-8")?,
        ],
        &common,
        Some("restore-release-tree"),
    )?;
    assert_eq!(
        fs::read(release_root.join(release).join("bin/vps-guard"))?,
        b"vps-guard\n"
    );
    run(
        [
            "ops",
            "uninstall-release",
            "remove",
            snapshot.to_str().ok_or("snapshot UTF-8")?,
        ],
        &common,
        Some("remove-release-snapshot"),
    )?;
    assert!(!snapshot.exists());
    fs::remove_dir_all(temporary)?;
    Ok(())
}

fn write_release(root: &Path, release: &str) -> std::io::Result<()> {
    let bin = root.join(release).join("bin");
    fs::create_dir_all(&bin)?;
    for name in [
        "vps-guard",
        "vps-guard-control",
        "vps-guard-edge",
        "vps-guard-privileged",
    ] {
        let path = bin.join(name);
        fs::write(&path, format!("{name}\n"))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn run<const N: usize>(
    args: [&str; N],
    environment: &[(&str, &str)],
    confirmation: Option<&str>,
) -> Result<Output, Box<dyn std::error::Error>> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vps-guard"));
    command.args(args).envs(environment.iter().copied());
    if let Some(value) = confirmation {
        command.env("VPS_GUARD_UNINSTALL_RELEASE_CONFIRM", value);
    }
    let output = command.output()?;
    if !output.status.success() {
        return Err(format!(
            "CLI failed: status={}, stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output)
}

fn stdout(output: &Output) -> Result<&str, std::str::Utf8Error> {
    std::str::from_utf8(&output.stdout)
}
