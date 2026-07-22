//! OPS-009/OPS-010 배포 snapshot exact restore와 자동 rollback 회귀 테스트입니다.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::time::Duration;

use tempfile::tempdir;

use super::{
    DeploymentRestoreDriver, DeploymentStateConfig, DeploymentStateStore, deployment_restore_plan,
};
use crate::{
    OperationDriver, OperationEngineError, OperationPhase, OperationStatus, execute_operation,
};

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    snapshots: PathBuf,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let root = temp.path().join("root");
        let snapshots = temp.path().join("snapshots");
        for directory in [
            "usr/local/bin",
            "usr/local/lib/vps-guard/releases/release-old/bin",
            "usr/local/lib/vps-guard/releases/release-new/bin",
            "etc/vps-guard/secrets",
            "etc/nginx/sites-enabled",
            "etc/ssh",
            "etc/letsencrypt/live/example",
            "home/g7devops/public_html/app",
            ".vpsguard-test/systemd",
        ] {
            fs::create_dir_all(root.join(directory))?;
        }
        write(&root, "usr/local/bin/vps-guard", "old-binary\n")?;
        symlink(
            "/usr/local/lib/vps-guard/releases/release-old",
            root.join("usr/local/lib/vps-guard/current"),
        )?;
        write(&root, "etc/vps-guard/config.toml", "old-config\n")?;
        write(
            &root,
            "etc/vps-guard/secrets/cloudflare-token",
            "fixture-old-token\n",
        )?;
        fs::set_permissions(
            root.join("etc/vps-guard/secrets/cloudflare-token"),
            fs::Permissions::from_mode(0o600),
        )?;
        write(&root, "etc/nginx/sites-enabled/g7.conf", "nginx-original\n")?;
        write(&root, "etc/ssh/sshd_config", "ssh-original\n")?;
        write(
            &root,
            "etc/letsencrypt/live/example/fullchain.pem",
            "certificate-original\n",
        )?;
        write(
            &root,
            "home/g7devops/public_html/app/index.php",
            "site-original\n",
        )?;
        service_state(&root, "vps-guard-control.service", "enabled", "active")?;
        service_state(&root, "vps-guard-edge.service", "disabled", "inactive")?;
        Ok(Self {
            _temp: temp,
            root,
            snapshots,
        })
    }

    fn store(&self) -> DeploymentStateStore {
        DeploymentStateStore::new(DeploymentStateConfig::fixture(&self.root, &self.snapshots))
    }

    fn mutate_after_snapshot(&self) -> Result<(), Box<dyn std::error::Error>> {
        write(&self.root, "usr/local/bin/vps-guard", "new-binary\n")?;
        write(
            &self.root,
            "usr/local/bin/vps-guard-control",
            "new-control\n",
        )?;
        fs::remove_file(self.root.join("usr/local/lib/vps-guard/current"))?;
        symlink(
            "/usr/local/lib/vps-guard/releases/release-new",
            self.root.join("usr/local/lib/vps-guard/current"),
        )?;
        write(&self.root, "etc/vps-guard/config.toml", "new-config\n")?;
        write(
            &self.root,
            "etc/vps-guard/secrets/cloudflare-token",
            "fixture-new-token\n",
        )?;
        write(
            &self.root,
            "etc/nginx/sites-enabled/g7.conf",
            "nginx-user-change\n",
        )?;
        write(
            &self.root,
            "home/g7devops/public_html/app/index.php",
            "site-user-change\n",
        )?;
        write(
            &self.root,
            "etc/systemd/system/vps-guard-control.service",
            "new-unit\n",
        )?;
        fs::create_dir_all(self.root.join(".vpsguard-test"))?;
        write(&self.root, ".vpsguard-test/account-vps-guard", "present\n")?;
        service_state(
            &self.root,
            "vps-guard-control.service",
            "disabled",
            "inactive",
        )?;
        service_state(&self.root, "vps-guard-edge.service", "enabled", "active")?;
        Ok(())
    }
}

#[test]
fn snapshot_restore_preserves_owned_state_and_only_observes_protected_trees()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut store = fixture.store();
    let snapshot = store.create_snapshot()?;
    let protected = fs::read_to_string(snapshot.join("protected.tsv"))?;
    assert!(!protected.contains("nginx-original"));
    assert!(!protected.contains("site-original"));

    fixture.mutate_after_snapshot()?;
    store.restore_snapshot(&snapshot)?;

    assert_eq!(
        read(&fixture.root, "usr/local/bin/vps-guard")?,
        "old-binary\n"
    );
    assert!(
        !fixture
            .root
            .join("usr/local/bin/vps-guard-control")
            .exists()
    );
    assert_eq!(
        fs::read_link(fixture.root.join("usr/local/lib/vps-guard/current"))?,
        PathBuf::from("/usr/local/lib/vps-guard/releases/release-old")
    );
    assert_eq!(
        read(&fixture.root, "etc/vps-guard/config.toml")?,
        "old-config\n"
    );
    assert_eq!(
        fs::metadata(fixture.root.join("etc/vps-guard/secrets/cloudflare-token"))?
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        read(&fixture.root, "etc/nginx/sites-enabled/g7.conf")?,
        "nginx-user-change\n"
    );
    assert_eq!(
        read(&fixture.root, "home/g7devops/public_html/app/index.php")?,
        "site-user-change\n"
    );
    assert!(
        !fixture
            .root
            .join(".vpsguard-test/account-vps-guard")
            .exists()
    );
    assert_eq!(
        read(
            &fixture.root,
            ".vpsguard-test/systemd/vps-guard-control.service.active"
        )?,
        "active\n"
    );
    store.verify_snapshot(&snapshot)?;
    Ok(())
}

#[test]
fn checksum_tamper_is_rejected_before_owned_state_changes() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = Fixture::new()?;
    let mut store = fixture.store();
    let snapshot = store.create_snapshot()?;
    fixture.mutate_after_snapshot()?;
    fs::write(
        snapshot.join("payload/usr/local/bin/vps-guard"),
        "tampered\n",
    )?;

    let error = store
        .restore_snapshot(&snapshot)
        .map_or_else(|error| error.to_string(), |()| String::new());
    assert!(error.contains("checksum"));
    assert_eq!(
        read(&fixture.root, "usr/local/bin/vps-guard")?,
        "new-binary\n"
    );
    Ok(())
}

#[test]
fn restore_rejects_a_symlink_parent_without_touching_its_external_target()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut store = fixture.store();
    let snapshot = store.create_snapshot()?;
    let external = fixture._temp.path().join("external-vps-guard");
    fs::create_dir_all(&external)?;
    fs::write(external.join("config.toml"), "external-sentinel\n")?;
    fs::remove_dir_all(fixture.root.join("etc/vps-guard"))?;
    symlink(&external, fixture.root.join("etc/vps-guard"))?;

    let error = store
        .restore_snapshot(&snapshot)
        .map_or_else(|error| error.to_string(), |()| String::new());
    assert!(error.contains("symlink parent"));
    assert_eq!(
        fs::read_to_string(external.join("config.toml"))?,
        "external-sentinel\n"
    );
    Ok(())
}

#[test]
fn typed_driver_rolls_back_partial_restore_to_the_pre_attempt_snapshot()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut initial = fixture.store();
    let target = initial.create_snapshot()?;
    fixture.mutate_after_snapshot()?;
    let mut store = fixture.store();
    store.fail_after_first_mutation = true;
    let mut driver = DeploymentRestoreDriver::new(store, &target);
    let plan = deployment_restore_plan(
        "deployment-restore-fixture",
        target
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("snapshot"),
    );
    let result = execute_operation(
        &plan,
        fixture.snapshots.join("transactions/fixture/state.json"),
        fixture.snapshots.join("operation.lock"),
        &mut driver,
    );

    assert!(
        matches!(
            result,
            Err(OperationEngineError::OperationFailed {
                rollback_succeeded: true,
                ..
            })
        ),
        "unexpected operation result: {result:?}"
    );
    assert!(driver.rollback_snapshot().is_some());
    assert_eq!(
        read(&fixture.root, "usr/local/bin/vps-guard")?,
        "new-binary\n"
    );
    let state: crate::OperationState = serde_json::from_slice(&fs::read(
        fixture.snapshots.join("transactions/fixture/state.json"),
    )?)?;
    assert_eq!(state.status, OperationStatus::RolledBack);
    Ok(())
}

#[test]
fn rollback_checkpoint_survives_driver_reconstruction() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut initial = fixture.store();
    let target = initial.create_snapshot()?;
    fixture.mutate_after_snapshot()?;
    let checkpoint = fixture.snapshots.join("transactions/resume/rollback.json");
    let plan = deployment_restore_plan("deployment-restore-resume", "resume-snapshot");
    let mut first =
        DeploymentRestoreDriver::with_checkpoint(fixture.store(), &target, &checkpoint)?;
    first
        .run_phase(&plan, OperationPhase::Snapshot, Duration::from_secs(15))
        .map_err(|issue| std::io::Error::other(issue.cause))?;
    let expected = first.rollback_snapshot().map(Path::to_path_buf);
    drop(first);

    let resumed = DeploymentRestoreDriver::with_checkpoint(fixture.store(), &target, &checkpoint)?;
    assert_eq!(resumed.rollback_snapshot(), expected.as_deref());
    assert!(checkpoint.is_file());
    Ok(())
}

fn write(root: &Path, relative: &str, value: &str) -> Result<(), std::io::Error> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, value)
}

fn read(root: &Path, relative: &str) -> Result<String, std::io::Error> {
    fs::read_to_string(root.join(relative))
}

fn service_state(
    root: &Path,
    unit: &str,
    enabled: &str,
    active: &str,
) -> Result<(), std::io::Error> {
    write(
        root,
        &format!(".vpsguard-test/systemd/{unit}.enabled"),
        &format!("{enabled}\n"),
    )?;
    write(
        root,
        &format!(".vpsguard-test/systemd/{unit}.active"),
        &format!("{active}\n"),
    )
}
