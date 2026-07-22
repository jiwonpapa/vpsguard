//! OPS-011 Apache ingress CLI가 typed driver와 확인값을 강제하는 회귀 테스트입니다.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn apache_cli_round_trip_uses_typed_transaction_and_exact_symlink()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let common = fixture.common_env();
    let plan = run(
        ["ops", "apache-ingress", "plan", "--direction", "to-edge"],
        &common,
    )?;
    assert!(stdout(&plan)?.contains("preserve: SSH, certificate, site data"));

    fixture.apply(&common, "to-edge", Some(&fixture.stage))?;
    assert_eq!(
        fs::read(fixture.logical("/etc/apache2/sites-available/gnuboard5.conf"))?,
        b"guarded\n"
    );
    assert_eq!(
        fs::read_link(fixture.logical("/etc/apache2/sites-enabled/gnuboard5.conf"))?,
        Path::new("../sites-available/gnuboard5.conf")
    );
    fixture.apply(&common, "to-apache", None)?;
    assert_eq!(
        fs::read(fixture.logical("/etc/apache2/sites-available/gnuboard5.conf"))?,
        b"bypass\n"
    );
    Ok(())
}

struct Fixture {
    root: PathBuf,
    state: PathBuf,
    backup: PathBuf,
    stage: PathBuf,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let suffix = format!(
            "{}{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        );
        let root = std::env::temp_dir().join(format!("vpsguard-apache-cli-{suffix}"));
        let state = root.join("state");
        let backup = root.join("backups");
        let stage = PathBuf::from(format!("/tmp/vpsguard-apache.{suffix}"));
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
        fs::create_dir_all(&stage)?;
        fs::write(
            logical(&root, "/etc/apache2/sites-available/gnuboard5.conf"),
            b"before\n",
        )?;
        for module in ["proxy.load", "proxy.conf", "proxy_http.load"] {
            fs::write(
                logical(&root, &format!("/etc/apache2/mods-available/{module}")),
                b"module\n",
            )?;
        }
        symlink(
            "../sites-available/gnuboard5.conf",
            logical(&root, "/etc/apache2/sites-enabled/gnuboard5.conf"),
        )?;
        fs::write(logical(&root, "/etc/vps-guard/config.toml"), b"before\n")?;
        fs::write(
            logical(&root, "/etc/ssl/gnuboard5/gnuboard5.local.pem"),
            b"certificate\n",
        )?;
        for (unit, activity) in [
            ("apache2.service", "active\n"),
            ("vps-guard-edge.service", "inactive\n"),
        ] {
            fs::write(state.join(format!("{unit}.enabled")), b"enabled\n")?;
            fs::write(state.join(format!("{unit}.active")), activity)?;
        }
        fs::write(state.join("edge-public"), b"false\n")?;
        fs::write(state.join("public-edge-header"), b"absent\n")?;
        fs::write(
            state.join("protected-listeners"),
            b"LISTEN 0 128 0.0.0.0:22 users:sshd\n",
        )?;
        for (name, content) in [
            ("gnuboard5-guarded.conf", "guarded\n"),
            ("gnuboard5-bypass.conf", "bypass\n"),
            ("vpsguard-origin.conf", "origin\n"),
            ("vpsguard-origin-ports.conf", "Listen 127.0.0.1:18081\n"),
            ("vps-guard.ingress.toml", "guard-config\n"),
        ] {
            fs::write(stage.join(name), content)?;
        }
        Ok(Self {
            root,
            state,
            backup,
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
                "VPS_GUARD_APACHE_BACKUP_ROOT".into(),
                self.backup.display().to_string(),
            ),
        ]
    }

    fn apply(
        &self,
        common: &[(String, String)],
        direction: &str,
        stage: Option<&Path>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut args = vec!["ops", "apache-ingress", "apply", "--direction", direction];
        if let Some(stage) = stage {
            args.extend(["--stage", stage.to_str().ok_or("stage is not UTF-8")?]);
        }
        let mut environment = common.to_vec();
        environment.push(("VPS_GUARD_APACHE_INGRESS_CONFIRM".into(), direction.into()));
        run(args, &environment)?;
        Ok(())
    }

    fn logical(&self, path: &str) -> PathBuf {
        logical(&self.root, path)
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
