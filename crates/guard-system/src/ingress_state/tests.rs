//! Public ingress snapshot·복원 transaction 회귀 테스트입니다.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::{
    ACTIVE_CONFIG, ACTIVE_NGINX, DEFAULT_DENY, DEFAULT_DENY_TARGET, EDGE_SERVICE,
    IngressApplyDriver, IngressRestoreDriver, IngressStateConfig, IngressStateStore,
    IngressSwitchConfig, IngressSwitchDirection, IngressSwitchDriver, NGINX_SERVICE,
    ingress_apply_plan, ingress_restore_plan, ingress_switch_plan,
};
use crate::{IngressTopology, OperationEngineError, execute_operation};

struct Fixture {
    _temporary: TempDir,
    root: PathBuf,
    state: PathBuf,
    snapshots: PathBuf,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("root");
        let state = temporary.path().join("state");
        let snapshots = temporary.path().join("snapshots");
        for directory in [
            "/etc/nginx/sites-available",
            "/etc/nginx/sites-enabled",
            "/etc/vps-guard",
            "/etc/systemd/system/vps-guard-edge.service.d",
            "/etc/letsencrypt/renewal-hooks/deploy",
            "/usr/local/libexec/vps-guard",
        ] {
            fs::create_dir_all(logical(&root, directory))?;
        }
        fs::create_dir_all(&state)?;
        fs::create_dir_all(&snapshots)?;
        fs::write(logical(&root, ACTIVE_NGINX), b"nginx-before\n")?;
        fs::write(logical(&root, ACTIVE_CONFIG), b"config-before\n")?;
        fs::set_permissions(
            logical(&root, ACTIVE_CONFIG),
            fs::Permissions::from_mode(0o640),
        )?;
        symlink(DEFAULT_DENY_TARGET, logical(&root, DEFAULT_DENY))?;
        for unit in [EDGE_SERVICE, NGINX_SERVICE] {
            fs::write(state.join(format!("{unit}.enabled")), b"enabled\n")?;
            fs::write(state.join(format!("{unit}.active")), b"active\n")?;
        }
        fs::write(state.join("edge-public"), b"false\n")?;
        fs::write(state.join("public-edge-header"), b"absent\n")?;
        fs::write(
            state.join("protected-listeners"),
            b"LISTEN 0 128 0.0.0.0:22 users:sshd\n",
        )?;
        Ok(Self {
            _temporary: temporary,
            root,
            state,
            snapshots,
        })
    }

    fn config(&self) -> IngressStateConfig {
        IngressStateConfig::fixture(&self.root, &self.state, &self.snapshots)
    }

    fn path(&self, logical_path: &str) -> PathBuf {
        logical(&self.root, logical_path)
    }

    fn mutate_to_edge(&self) -> Result<(), Box<dyn std::error::Error>> {
        fs::write(self.path(ACTIVE_NGINX), b"nginx-edge\n")?;
        fs::write(self.path(ACTIVE_CONFIG), b"config-edge\n")?;
        fs::remove_file(self.path(DEFAULT_DENY))?;
        fs::write(self.state.join("edge-public"), b"true\n")?;
        fs::write(self.state.join("public-edge-header"), b"present\n")?;
        Ok(())
    }
}

#[test]
fn snapshot_round_trip_restores_exact_ingress_state() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut store = IngressStateStore::new(fixture.config());
    let snapshot = store.create_snapshot("direct")?;

    fixture.mutate_to_edge()?;
    store.restore_snapshot(&snapshot)?;
    store.verify_restored_snapshot(&snapshot)?;

    assert_eq!(fs::read(fixture.path(ACTIVE_NGINX))?, b"nginx-before\n");
    assert_eq!(fs::read(fixture.path(ACTIVE_CONFIG))?, b"config-before\n");
    assert!(
        fs::symlink_metadata(fixture.path(DEFAULT_DENY))?
            .file_type()
            .is_symlink()
    );
    Ok(())
}

#[test]
fn corrupt_checksum_fails_before_mutation() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut store = IngressStateStore::new(fixture.config());
    let snapshot = store.create_snapshot("direct")?;
    fixture.mutate_to_edge()?;
    fs::write(snapshot.join("g7.conf"), b"tampered\n")?;

    let error = store.restore_snapshot(&snapshot).expect_err("must reject");
    assert!(error.to_string().contains("checksum"));
    assert_eq!(fs::read(fixture.path(ACTIVE_NGINX))?, b"nginx-edge\n");
    Ok(())
}

#[test]
fn legacy_v1_snapshot_remains_restorable() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut store = IngressStateStore::new(fixture.config());
    let snapshot = fixture.snapshots.join("direct-20260722T000000Z-1-direct");
    fs::create_dir(&snapshot)?;
    fs::copy(fixture.path(ACTIVE_NGINX), snapshot.join("g7.conf"))?;
    fs::copy(fixture.path(ACTIVE_CONFIG), snapshot.join("config.toml"))?;
    let manifest = format!(
        concat!(
            "schema_version|1\n",
            "machine_id_sha256|{}\n",
            "label|direct\n",
            "dropin|absent\n",
            "default_deny|present\n",
            "default_deny_target|/etc/nginx/sites-available/g7-default-deny.conf\n",
            "generic_certbot_hook|absent\n",
            "site_certbot_hook|absent\n",
            "edge_enabled|enabled\n",
            "edge_active|active\n",
            "nginx_enabled|enabled\n",
            "nginx_active|active\n",
            "edge_public|false\n",
            "public_edge_header|absent\n",
            "certificate_fingerprint|test-certificate\n"
        ),
        store.machine_id_hash()?
    );
    fs::write(snapshot.join("manifest.tsv"), manifest)?;
    super::files::write_checksums(&snapshot)?;

    fixture.mutate_to_edge()?;
    store.restore_snapshot(&snapshot)?;
    store.verify_restored_snapshot(&snapshot)?;
    assert_eq!(fs::read(fixture.path(ACTIVE_NGINX))?, b"nginx-before\n");
    assert_eq!(fs::read(fixture.path(ACTIVE_CONFIG))?, b"config-before\n");
    Ok(())
}

#[test]
fn symlink_parent_escape_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut store = IngressStateStore::new(fixture.config());
    let snapshot = store.create_snapshot("direct")?;
    let external = fixture._temporary.path().join("external");
    fs::create_dir_all(&external)?;
    fs::remove_dir_all(fixture.root.join("etc/vps-guard"))?;
    symlink(&external, fixture.root.join("etc/vps-guard"))?;

    let error = store.restore_snapshot(&snapshot).expect_err("must reject");
    assert!(error.to_string().contains("symlink parent"));
    assert!(!external.join("config.toml").exists());
    Ok(())
}

#[test]
fn partial_restore_automatically_rolls_back() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut snapshot_store = IngressStateStore::new(fixture.config());
    let target = snapshot_store.create_snapshot("direct")?;
    fixture.mutate_to_edge()?;

    let operation_id = "ingress-fault-rollback";
    let plan = ingress_restore_plan(
        operation_id,
        target
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("snapshot"),
        IngressTopology::VpsGuardPublic,
        IngressTopology::NginxPublic,
    );
    let transaction = fixture.snapshots.join("transactions").join(operation_id);
    let state_path = transaction.join("state.json");
    let lock_path = fixture.snapshots.join("operation.lock");
    let mut store = IngressStateStore::new(fixture.config());
    store.fail_after_first_mutation = true;
    let mut driver =
        IngressRestoreDriver::with_checkpoint(store, &target, transaction.join("rollback.json"))?;

    let result = execute_operation(&plan, &state_path, &lock_path, &mut driver);
    assert!(matches!(
        result,
        Err(OperationEngineError::OperationFailed {
            rollback_succeeded: true,
            ..
        })
    ));
    assert_eq!(fs::read(fixture.path(ACTIVE_NGINX))?, b"nginx-edge\n");
    assert_eq!(fs::read(fixture.path(ACTIVE_CONFIG))?, b"config-edge\n");
    Ok(())
}

#[test]
fn rollback_checkpoint_survives_driver_reconstruction() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut target_store = IngressStateStore::new(fixture.config());
    let target = target_store.create_snapshot("direct")?;
    fixture.mutate_to_edge()?;
    let checkpoint = fixture.snapshots.join("checkpoint.json");
    let rollback = {
        let mut driver = IngressRestoreDriver::with_checkpoint(
            IngressStateStore::new(fixture.config()),
            &target,
            &checkpoint,
        )?;
        let plan = ingress_restore_plan(
            "checkpoint-plan",
            target
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("snapshot"),
            IngressTopology::VpsGuardPublic,
            IngressTopology::NginxPublic,
        );
        use crate::OperationDriver as _;
        driver
            .run_phase(
                &plan,
                crate::OperationPhase::Snapshot,
                std::time::Duration::from_secs(5),
            )
            .map_err(|issue| issue.cause)?;
        driver.rollback_snapshot().expect("rollback").to_path_buf()
    };
    let driver = IngressRestoreDriver::with_checkpoint(
        IngressStateStore::new(fixture.config()),
        &target,
        &checkpoint,
    )?;
    assert_eq!(driver.rollback_snapshot(), Some(rollback.as_path()));
    Ok(())
}

#[test]
fn ingress_switch_round_trip_uses_typed_driver() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let backup_root = fixture._temporary.path().join("switch-backups");
    let config = switch_fixture(&fixture, &backup_root)?;
    run_switch(&config, IngressSwitchDirection::ToEdge, "switch-to-edge")?;
    assert_eq!(
        fs::read(fixture.path("/etc/nginx/conf.d/vps-guard-ingress.conf"))?,
        b"edge-candidate\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.state.join(format!("{EDGE_SERVICE}.active")))?,
        "active\n"
    );

    run_switch(&config, IngressSwitchDirection::ToNginx, "switch-to-nginx")?;
    assert_eq!(
        fs::read(fixture.path("/etc/nginx/conf.d/vps-guard-ingress.conf"))?,
        b"nginx-bypass\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.state.join(format!("{EDGE_SERVICE}.active")))?,
        "inactive\n"
    );
    Ok(())
}

#[test]
fn ingress_switch_probe_failure_restores_active_and_service()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let backup_root = fixture._temporary.path().join("switch-fault-backups");
    let mut config = switch_fixture(&fixture, &backup_root)?;
    config.fixture_probe_failure = true;
    let operation_id = "switch-probe-fault";
    let plan = ingress_switch_plan(operation_id, IngressSwitchDirection::ToEdge, &config);
    let transaction = backup_root.join("transactions").join(operation_id);
    let mut driver = IngressSwitchDriver::new(
        config,
        IngressSwitchDirection::ToEdge,
        transaction.join("rollback.json"),
    )?;
    let result = execute_operation(
        &plan,
        transaction.join("state.json"),
        backup_root.join("operation.lock"),
        &mut driver,
    );
    assert!(matches!(
        result,
        Err(OperationEngineError::OperationFailed {
            rollback_succeeded: true,
            ..
        })
    ));
    assert_eq!(
        fs::read(fixture.path("/etc/nginx/conf.d/vps-guard-ingress.conf"))?,
        b"nginx-bypass\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.state.join(format!("{EDGE_SERVICE}.active")))?,
        "inactive\n"
    );
    Ok(())
}

#[test]
fn staged_switch_failure_restores_config_and_both_candidates()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let backup_root = fixture._temporary.path().join("staged-switch-fault");
    let mut config = switch_fixture(&fixture, &backup_root)?;
    let stage = tempfile::Builder::new()
        .prefix("vpsguard-cutover.")
        .tempdir_in("/tmp")?;
    for (name, contents) in [
        ("g7devops-edge.conf", "staged-edge\n"),
        ("g7devops-bypass.conf", "staged-bypass\n"),
        ("vps-guard.ingress.toml", "staged-guard\n"),
    ] {
        fs::write(stage.path().join(name), contents)?;
    }
    config.stage_root = Some(stage.path().to_path_buf());
    config.fixture_probe_failure = true;
    let operation_id = "staged-switch-rollback";
    let plan = ingress_switch_plan(operation_id, IngressSwitchDirection::ToEdge, &config);
    let transaction = backup_root.join("transactions").join(operation_id);
    let mut driver = IngressSwitchDriver::new(
        config,
        IngressSwitchDirection::ToEdge,
        transaction.join("rollback.json"),
    )?;
    let result = execute_operation(
        &plan,
        transaction.join("state.json"),
        backup_root.join("operation.lock"),
        &mut driver,
    );
    assert!(matches!(
        result,
        Err(OperationEngineError::OperationFailed {
            rollback_succeeded: true,
            ..
        })
    ));
    assert_eq!(fs::read(fixture.path(ACTIVE_CONFIG))?, b"config-before\n");
    assert_eq!(
        fs::read(fixture.path("/etc/vps-guard/nginx/edge-origin.conf"))?,
        b"edge-candidate\n"
    );
    assert_eq!(
        fs::read(fixture.path("/etc/vps-guard/nginx/public-bypass.conf"))?,
        b"nginx-bypass\n"
    );
    Ok(())
}

#[test]
fn staged_direct_candidate_is_applied_by_typed_driver() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    fs::write(
        fixture.state.join(format!("{EDGE_SERVICE}.active")),
        b"inactive\n",
    )?;
    let stage = tempfile::Builder::new()
        .prefix("vpsguard-direct.")
        .tempdir_in("/tmp")?;
    for (name, contents) in [
        ("origin-only.conf", "nginx-direct\n"),
        ("direct.toml", "config-direct\n"),
        ("edge-tls.conf", "dropin-direct\n"),
        ("certbot-deploy-hook", "generic-hook\n"),
        ("g7-certbot-deploy-hook", "site-hook\n"),
    ] {
        fs::write(stage.path().join(name), contents)?;
    }
    let mut store = IngressStateStore::new(fixture.config());
    let candidate = store.create_direct_candidate_snapshot(stage.path())?;
    let operation_id = "direct-candidate-apply";
    let plan = ingress_apply_plan(
        operation_id,
        candidate
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("candidate"),
    );
    let transaction = fixture.snapshots.join("transactions").join(operation_id);
    let mut driver =
        IngressApplyDriver::with_checkpoint(store, &candidate, transaction.join("rollback.json"))?;
    let state_path = transaction.join("state.json");
    let result = execute_operation(
        &plan,
        &state_path,
        fixture.snapshots.join("operation.lock"),
        &mut driver,
    );
    assert!(
        result.is_ok(),
        "unexpected apply result: {result:?}, state={}",
        fs::read_to_string(&state_path).unwrap_or_default()
    );

    assert_eq!(fs::read(fixture.path(ACTIVE_NGINX))?, b"nginx-direct\n");
    assert_eq!(fs::read(fixture.path(ACTIVE_CONFIG))?, b"config-direct\n");
    assert!(!fixture.path(DEFAULT_DENY).exists());
    assert_eq!(
        fs::read_to_string(fixture.state.join("edge-public"))?,
        "true\n"
    );
    assert!(driver.rollback_snapshot().is_some());
    Ok(())
}

fn switch_fixture(
    fixture: &Fixture,
    backup_root: &Path,
) -> Result<IngressSwitchConfig, Box<dyn std::error::Error>> {
    fs::create_dir_all(fixture.path("/etc/nginx/conf.d"))?;
    fs::create_dir_all(fixture.path("/etc/vps-guard/nginx"))?;
    fs::write(
        fixture.path("/etc/nginx/conf.d/vps-guard-ingress.conf"),
        b"nginx-bypass\n",
    )?;
    fs::write(
        fixture.path("/etc/vps-guard/nginx/edge-origin.conf"),
        b"edge-candidate\n",
    )?;
    fs::write(
        fixture.path("/etc/vps-guard/nginx/public-bypass.conf"),
        b"nginx-bypass\n",
    )?;
    fs::write(
        fixture.state.join(format!("{EDGE_SERVICE}.active")),
        b"inactive\n",
    )?;
    Ok(IngressSwitchConfig::fixture(
        &fixture.root,
        &fixture.state,
        backup_root,
    ))
}

fn run_switch(
    config: &IngressSwitchConfig,
    direction: IngressSwitchDirection,
    operation_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let plan = ingress_switch_plan(operation_id, direction, config);
    let transaction = config.backup_root.join("transactions").join(operation_id);
    let mut driver =
        IngressSwitchDriver::new(config.clone(), direction, transaction.join("rollback.json"))?;
    execute_operation(
        &plan,
        transaction.join("state.json"),
        config.backup_root.join("operation.lock"),
        &mut driver,
    )?;
    Ok(())
}

fn logical(root: &Path, path: &str) -> PathBuf {
    root.join(path.trim_start_matches('/'))
}
