//! Public ingress CLI가 실제 typed driver를 끝까지 호출하는 격리 회귀 테스트입니다.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const ACTIVE_NGINX: &str = "/etc/nginx/sites-available/g7.conf";
const ACTIVE_GUARD: &str = "/etc/vps-guard/config.toml";
const EDGE_SERVICE: &str = "vps-guard-edge.service";
const NGINX_SERVICE: &str = "nginx.service";

#[test]
fn ingress_cli_round_trip_uses_one_typed_transaction_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let common = fixture.common_env();
    let snapshot_output = run(
        ["ops", "ingress-state", "snapshot", "--label", "direct"],
        &common,
    )?;
    let snapshot = stdout(&snapshot_output)?
        .lines()
        .find_map(|line| line.strip_prefix("snapshot="))
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("snapshot path output is missing"))?;
    run(
        [
            "ops",
            "ingress-state",
            "verify",
            snapshot.to_str().ok_or("snapshot is not UTF-8")?,
        ],
        &common,
    )?;

    fs::write(fixture.logical(ACTIVE_NGINX), b"mutated\n")?;
    let mut restore_env = common.clone();
    restore_env.push((
        "VPS_GUARD_DIRECT_RESTORE_CONFIRM".into(),
        "restore-direct-snapshot".into(),
    ));
    run(
        [
            "ops",
            "ingress-state",
            "restore",
            snapshot.to_str().ok_or("snapshot is not UTF-8")?,
        ],
        &restore_env,
    )?;
    assert_eq!(fs::read(fixture.logical(ACTIVE_NGINX))?, b"nginx-before\n");

    fixture.apply_direct(&common)?;
    fixture.switch(&common, "to-edge")?;
    fixture.switch(&common, "to-nginx")?;
    Ok(())
}

struct Fixture {
    root: PathBuf,
    state: PathBuf,
    snapshots: PathBuf,
    stage: PathBuf,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let suffix = format!(
            "{}{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        );
        let root = std::env::temp_dir().join(format!("vpsguard-cli-{suffix}"));
        let state = root.join("state");
        let snapshots = root.join("snapshots");
        let stage = PathBuf::from(format!("/tmp/vpsguard-direct.{suffix}"));
        for directory in [
            "/etc/nginx/sites-available",
            "/etc/nginx/sites-enabled",
            "/etc/nginx/conf.d",
            "/etc/vps-guard/nginx",
            "/etc/systemd/system/vps-guard-edge.service.d",
            "/etc/letsencrypt/renewal-hooks/deploy",
            "/usr/local/libexec/vps-guard",
        ] {
            fs::create_dir_all(logical(&root, directory))?;
        }
        fs::create_dir_all(&state)?;
        fs::create_dir_all(&snapshots)?;
        fs::create_dir(&stage)?;
        fs::write(logical(&root, ACTIVE_NGINX), b"nginx-before\n")?;
        fs::write(logical(&root, ACTIVE_GUARD), b"config-before\n")?;
        fs::write(
            logical(&root, "/etc/nginx/conf.d/vps-guard-ingress.conf"),
            b"nginx-bypass\n",
        )?;
        fs::write(
            logical(&root, "/etc/vps-guard/nginx/edge-origin.conf"),
            b"edge-candidate\n",
        )?;
        fs::write(
            logical(&root, "/etc/vps-guard/nginx/public-bypass.conf"),
            b"nginx-bypass\n",
        )?;
        for unit in [EDGE_SERVICE, NGINX_SERVICE] {
            fs::write(state.join(format!("{unit}.enabled")), b"enabled\n")?;
            let activity: &[u8] = if unit == NGINX_SERVICE {
                b"active\n"
            } else {
                b"inactive\n"
            };
            fs::write(state.join(format!("{unit}.active")), activity)?;
        }
        fs::write(state.join("edge-public"), b"false\n")?;
        fs::write(state.join("public-edge-header"), b"absent\n")?;
        fs::write(
            state.join("protected-listeners"),
            b"LISTEN 0 128 0.0.0.0:22 users:sshd\n",
        )?;
        for (name, contents) in [
            ("origin-only.conf", "nginx-direct\n"),
            ("direct.toml", "config-direct\n"),
            ("edge-tls.conf", "dropin-direct\n"),
            ("certbot-deploy-hook", "generic-hook\n"),
            ("g7-certbot-deploy-hook", "site-hook\n"),
        ] {
            fs::write(stage.join(name), contents)?;
        }
        Ok(Self {
            root,
            state,
            snapshots,
            stage,
        })
    }

    fn common_env(&self) -> Vec<(String, String)> {
        vec![
            (
                "VPS_GUARD_TEST_ROOT".into(),
                self.root.display().to_string(),
            ),
            (
                "VPS_GUARD_FAKE_STATE_DIR".into(),
                self.state.display().to_string(),
            ),
            (
                "VPS_GUARD_DIRECT_SNAPSHOT_ROOT".into(),
                self.snapshots.display().to_string(),
            ),
            (
                "VPS_GUARD_BACKUP_ROOT".into(),
                self.root.join("switch-backups").display().to_string(),
            ),
        ]
    }

    fn logical(&self, path: &str) -> PathBuf {
        logical(&self.root, path)
    }

    fn apply_direct(&self, common: &[(String, String)]) -> Result<(), Box<dyn std::error::Error>> {
        let mut environment = common.to_vec();
        environment.push((
            "VPS_GUARD_DIRECT_CONFIRM".into(),
            "g7devops:direct-tls".into(),
        ));
        run(
            [
                "ops",
                "ingress-state",
                "apply-direct",
                "--stage",
                self.stage.to_str().ok_or("stage is not UTF-8")?,
            ],
            &environment,
        )?;
        Ok(())
    }

    fn switch(
        &self,
        common: &[(String, String)],
        direction: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut environment = common.to_vec();
        environment.extend([
            (
                "VPS_GUARD_NGINX_ACTIVE".into(),
                "/etc/nginx/conf.d/vps-guard-ingress.conf".into(),
            ),
            (
                "VPS_GUARD_NGINX_EDGE_CANDIDATE".into(),
                "/etc/vps-guard/nginx/edge-origin.conf".into(),
            ),
            (
                "VPS_GUARD_NGINX_BYPASS_CANDIDATE".into(),
                "/etc/vps-guard/nginx/public-bypass.conf".into(),
            ),
            ("VPS_GUARD_INGRESS_CONFIRM".into(), direction.into()),
        ]);
        run(
            ["ops", "ingress-switch", "apply", "--direction", direction],
            &environment,
        )?;
        Ok(())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.root);
        let _ignored = fs::remove_dir_all(&self.stage);
    }
}

fn run<I, S>(args: I, environment: &[(String, String)]) -> Result<Output, io::Error>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(env!("CARGO_BIN_EXE_vps-guard"))
        .args(args)
        .envs(environment.iter().map(|(key, value)| (key, value)))
        .output()?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(io::Error::other(format!(
            "CLI failed: status={}, stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

fn stdout(output: &Output) -> Result<&str, std::str::Utf8Error> {
    std::str::from_utf8(&output.stdout)
}

fn logical(root: &Path, path: &str) -> PathBuf {
    root.join(path.trim_start_matches('/'))
}
