//! OPS-011 Apache public TLS 유지형 loopback 전환 회귀 테스트입니다.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::{
    ApacheIngressConfig, ApacheIngressDirection, ApacheIngressDriver, apache_ingress_plan,
};
use crate::{OperationEngineError, execute_operation};

const ACTIVE: &str = "/etc/apache2/sites-available/gnuboard5.conf";
const PUBLIC_LINK: &str = "/etc/apache2/sites-enabled/gnuboard5.conf";
const ORIGIN: &str = "/etc/apache2/sites-available/vpsguard-origin.conf";
const ORIGIN_LINK: &str = "/etc/apache2/sites-enabled/vpsguard-origin.conf";
const PORTS: &str = "/etc/apache2/conf-available/vpsguard-origin-ports.conf";
const PORTS_LINK: &str = "/etc/apache2/conf-enabled/vpsguard-origin-ports.conf";

struct Fixture {
    _temporary: TempDir,
    root: PathBuf,
    state: PathBuf,
    backup: PathBuf,
    stage: TempDir,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("root");
        let state = temporary.path().join("state");
        let backup = temporary.path().join("backups");
        for directory in [
            "/etc/apache2/sites-available",
            "/etc/apache2/sites-enabled",
            "/etc/apache2/conf-available",
            "/etc/apache2/conf-enabled",
            "/etc/apache2/mods-available",
            "/etc/apache2/mods-enabled",
            "/etc/vps-guard/apache",
            "/etc/vps-guard",
            "/etc/ssl/gnuboard5",
        ] {
            fs::create_dir_all(logical(&root, directory))?;
        }
        fs::create_dir_all(&state)?;
        fs::write(logical(&root, ACTIVE), b"apache-before\n")?;
        for module in [
            "proxy.load",
            "proxy.conf",
            "proxy_http.load",
            "remoteip.load",
        ] {
            fs::write(
                logical(&root, &format!("/etc/apache2/mods-available/{module}")),
                b"module\n",
            )?;
        }
        symlink(
            "../sites-available/gnuboard5.conf",
            logical(&root, PUBLIC_LINK),
        )?;
        fs::write(
            logical(&root, "/etc/vps-guard/config.toml"),
            b"config-before\n",
        )?;
        fs::write(
            logical(&root, "/etc/ssl/gnuboard5/gnuboard5.local.pem"),
            b"public-certificate\n",
        )?;
        for (unit, active) in [
            ("apache2.service", "active\n"),
            ("vps-guard-edge.service", "inactive\n"),
        ] {
            fs::write(state.join(format!("{unit}.enabled")), b"enabled\n")?;
            fs::write(state.join(format!("{unit}.active")), active)?;
        }
        fs::write(state.join("edge-public"), b"false\n")?;
        fs::write(state.join("public-edge-header"), b"absent\n")?;
        fs::write(
            state.join("protected-listeners"),
            b"LISTEN 0 128 0.0.0.0:22 users:sshd\n",
        )?;
        let stage = tempfile::Builder::new()
            .prefix("vpsguard-apache.")
            .tempdir_in("/tmp")?;
        for (name, content) in [
            ("gnuboard5-guarded.conf", "apache-guarded\n"),
            ("gnuboard5-bypass.conf", "apache-bypass\n"),
            ("vpsguard-origin.conf", "apache-origin\n"),
            ("vpsguard-origin-ports.conf", "Listen 127.0.0.1:18081\n"),
            ("vps-guard.ingress.toml", "config-guarded\n"),
        ] {
            fs::write(stage.path().join(name), content)?;
        }
        Ok(Self {
            _temporary: temporary,
            root,
            state,
            backup,
            stage,
        })
    }

    fn config(&self) -> ApacheIngressConfig {
        let mut config = ApacheIngressConfig::fixture(&self.root, &self.state, &self.backup);
        config.stage_root = Some(self.stage.path().to_path_buf());
        config
    }

    fn path(&self, path: &str) -> PathBuf {
        logical(&self.root, path)
    }
}

#[test]
fn apache_round_trip_preserves_public_link_and_origin_boundary()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let config = fixture.config();
    run(&config, ApacheIngressDirection::ToEdge, "apache-to-edge")?;
    assert_eq!(fs::read(fixture.path(ACTIVE))?, b"apache-guarded\n");
    assert_eq!(fs::read(fixture.path(ORIGIN))?, b"apache-origin\n");
    assert_eq!(fs::read(fixture.path(PORTS))?, b"Listen 127.0.0.1:18081\n");
    assert_eq!(
        fs::read_link(fixture.path(PUBLIC_LINK))?,
        Path::new("../sites-available/gnuboard5.conf")
    );
    assert_eq!(
        fs::read_link(fixture.path(ORIGIN_LINK))?,
        Path::new("../sites-available/vpsguard-origin.conf")
    );
    assert_eq!(
        fs::read_link(fixture.path(PORTS_LINK))?,
        Path::new("../conf-available/vpsguard-origin-ports.conf")
    );
    assert_eq!(
        fs::read_link(fixture.path("/etc/apache2/mods-enabled/proxy_http.load"))?,
        Path::new("../mods-available/proxy_http.load")
    );
    assert_eq!(
        fs::read_link(fixture.path("/etc/apache2/mods-enabled/remoteip.load"))?,
        Path::new("../mods-available/remoteip.load")
    );

    let mut bypass = config.clone();
    bypass.stage_root = None;
    run(
        &bypass,
        ApacheIngressDirection::ToApache,
        "apache-to-apache",
    )?;
    assert_eq!(fs::read(fixture.path(ACTIVE))?, b"apache-bypass\n");
    assert_eq!(
        fs::read_to_string(fixture.state.join("vps-guard-edge.service.active"))?,
        "inactive\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.state.join("apache2.service.active"))?,
        "active\n"
    );
    Ok(())
}

#[test]
fn apache_probe_failure_restores_every_staged_node_and_service()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut config = fixture.config();
    config.fixture_probe_failure = true;
    let operation_id = "apache-probe-rollback";
    let plan = apache_ingress_plan(operation_id, ApacheIngressDirection::ToEdge, &config);
    let transaction = config.backup_root.join("transactions").join(operation_id);
    let mut driver = ApacheIngressDriver::new(
        config,
        ApacheIngressDirection::ToEdge,
        transaction.join("rollback.json"),
    )?;
    let result = execute_operation(
        &plan,
        transaction.join("state.json"),
        fixture.backup.join("operation.lock"),
        &mut driver,
    );
    assert!(matches!(
        result,
        Err(OperationEngineError::OperationFailed {
            rollback_succeeded: true,
            ..
        })
    ));
    assert_eq!(fs::read(fixture.path(ACTIVE))?, b"apache-before\n");
    assert!(!fixture.path(ORIGIN).exists());
    assert!(!fixture.path(ORIGIN_LINK).exists());
    assert!(!fixture.path(PORTS).exists());
    assert!(!fixture.path(PORTS_LINK).exists());
    assert!(
        !fixture
            .path("/etc/apache2/mods-enabled/proxy.load")
            .exists()
    );
    assert!(
        !fixture
            .path("/etc/apache2/mods-enabled/proxy.conf")
            .exists()
    );
    assert!(
        !fixture
            .path("/etc/apache2/mods-enabled/proxy_http.load")
            .exists()
    );
    assert!(
        !fixture
            .path("/etc/apache2/mods-enabled/remoteip.load")
            .exists()
    );
    assert_eq!(
        fs::read(fixture.path("/etc/vps-guard/config.toml"))?,
        b"config-before\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.state.join("vps-guard-edge.service.active"))?,
        "inactive\n"
    );
    Ok(())
}

#[test]
fn apache_config_rejects_site_data_as_an_ingress_path() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut config = fixture.config();
    config.origin_vhost = PathBuf::from("/home/gnuboard5/public_html/index.php");
    let result = ApacheIngressDriver::new(
        config,
        ApacheIngressDirection::ToEdge,
        fixture.backup.join("rollback.json"),
    );
    assert!(result.is_err());
    Ok(())
}

fn run(
    config: &ApacheIngressConfig,
    direction: ApacheIngressDirection,
    operation_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let plan = apache_ingress_plan(operation_id, direction, config);
    let transaction = config.backup_root.join("transactions").join(operation_id);
    let mut driver =
        ApacheIngressDriver::new(config.clone(), direction, transaction.join("rollback.json"))?;
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
