//! OPS-012 `vps-guard setup`의 무변경 Nginx·Apache 탐지 CLI 회귀입니다.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use guard_system::{SetupCompatibility, SiteSetupReport, WebServerKind};
use tempfile::TempDir;

struct Fixture {
    _temporary: TempDir,
    root: PathBuf,
}

impl Fixture {
    fn apache() -> Result<Self, Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("root");
        for directory in [
            "/etc/apache2/sites-available",
            "/etc/apache2/sites-enabled",
            "/etc/apache2/conf-available",
            "/etc/apache2/mods-enabled",
            "/etc/apache2/mods-available",
            "/etc/apache2/conf-enabled",
            "/etc/vps-guard/apache",
            "/etc/vps-guard",
            "/etc/letsencrypt/live/example.com",
            "/run/vps-guard/setup-fixture",
            "/run/vps-guard/setup-state",
        ] {
            fs::create_dir_all(logical(&root, directory))?;
        }
        fs::write(
            logical(&root, "/etc/os-release"),
            "ID=ubuntu\nVERSION_ID=24.04\n",
        )?;
        fs::write(
            logical(&root, "/run/vps-guard/setup-fixture/apache2.service.active"),
            "active\n",
        )?;
        fs::write(
            logical(&root, "/etc/apache2/mods-enabled/php8.3.load"),
            "module\n",
        )?;
        fs::write(
            logical(&root, "/etc/vps-guard/config.toml"),
            "installed-placeholder\n",
        )?;
        fs::write(
            logical(&root, "/etc/letsencrypt/live/example.com/fullchain.pem"),
            "certificate\n",
        )?;
        for (unit, active) in [
            ("apache2.service", "active\n"),
            ("vps-guard-edge.service", "inactive\n"),
        ] {
            fs::write(
                logical(&root, &format!("/run/vps-guard/setup-state/{unit}.enabled")),
                "enabled\n",
            )?;
            fs::write(
                logical(&root, &format!("/run/vps-guard/setup-state/{unit}.active")),
                active,
            )?;
        }
        fs::write(
            logical(&root, "/run/vps-guard/setup-state/edge-public"),
            "false\n",
        )?;
        fs::write(
            logical(&root, "/run/vps-guard/setup-state/public-edge-header"),
            "absent\n",
        )?;
        fs::write(
            logical(&root, "/run/vps-guard/setup-state/protected-listeners"),
            "LISTEN 0 128 0.0.0.0:22 users:sshd\n",
        )?;
        fs::write(
            logical(&root, "/etc/apache2/sites-available/example.conf"),
            r#"
<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/example
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem
</VirtualHost>
"#,
        )?;
        symlink(
            "../sites-available/example.conf",
            logical(&root, "/etc/apache2/sites-enabled/example.conf"),
        )?;
        Ok(Self {
            _temporary: temporary,
            root,
        })
    }

    fn nginx() -> Result<Self, Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("root");
        for directory in [
            "/etc/nginx/sites-available",
            "/etc/nginx/sites-enabled",
            "/etc/vps-guard/nginx",
            "/etc/vps-guard",
            "/etc/letsencrypt/live/blog.example.com",
            "/run/vps-guard/setup-fixture",
            "/run/vps-guard/setup-state",
        ] {
            fs::create_dir_all(logical(&root, directory))?;
        }
        fs::write(
            logical(&root, "/etc/os-release"),
            "ID=ubuntu\nVERSION_ID=24.04\n",
        )?;
        fs::write(
            logical(&root, "/run/vps-guard/setup-fixture/nginx.service.active"),
            "active\n",
        )?;
        fs::write(
            logical(&root, "/etc/vps-guard/config.toml"),
            "installed-placeholder\n",
        )?;
        fs::write(
            logical(
                &root,
                "/etc/letsencrypt/live/blog.example.com/fullchain.pem",
            ),
            "certificate\n",
        )?;
        fs::write(
            logical(
                &root,
                "/run/vps-guard/setup-state/vps-guard-edge.service.enabled",
            ),
            "enabled\n",
        )?;
        fs::write(
            logical(
                &root,
                "/run/vps-guard/setup-state/vps-guard-edge.service.active",
            ),
            "inactive\n",
        )?;
        fs::write(
            logical(&root, "/run/vps-guard/setup-state/edge-public"),
            "false\n",
        )?;
        fs::write(
            logical(&root, "/run/vps-guard/setup-state/public-edge-header"),
            "absent\n",
        )?;
        fs::write(
            logical(&root, "/run/vps-guard/setup-state/protected-listeners"),
            "LISTEN 0 128 0.0.0.0:22 users:sshd\n",
        )?;
        fs::write(
            logical(&root, "/etc/nginx/sites-available/blog.conf"),
            r#"
server {
    listen 80;
    server_name blog.example.com;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl http2;
    server_name blog.example.com;
    root /var/www/blog;
    ssl_certificate /etc/letsencrypt/live/blog.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/blog.example.com/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }
}
"#,
        )?;
        symlink(
            "../sites-available/blog.conf",
            logical(&root, "/etc/nginx/sites-enabled/blog.conf"),
        )?;
        Ok(Self {
            _temporary: temporary,
            root,
        })
    }
}

#[test]
fn setup_apply_uses_nginx_typed_transaction_and_keeps_rollback()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::nginx()?;

    let output = run(&fixture.root, &["setup", "--apply"])?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("설치 적용: 성공"));
    assert!(stdout.contains("웹서버: Nginx"));
    assert!(stdout.contains("rollback:"));
    let active = fs::read_to_string(logical(
        &fixture.root,
        "/etc/nginx/sites-available/blog.conf",
    ))?;
    assert!(active.contains("proxy_pass http://127.0.0.1:18080;"));
    assert!(active.contains("listen 127.0.0.1:18081 ssl;"));
    Ok(())
}

#[test]
fn setup_apply_uses_apache_typed_transaction_and_keeps_rollback()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::apache()?;

    let output = run(&fixture.root, &["setup", "--apply"])?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("설치 적용: 성공"));
    assert!(stdout.contains("rollback:"));
    let active = fs::read_to_string(logical(
        &fixture.root,
        "/etc/apache2/sites-available/example.conf",
    ))?;
    assert!(active.contains("ProxyPass / http://127.0.0.1:18080/"));
    assert!(
        logical(
            &fixture.root,
            "/etc/apache2/sites-available/vpsguard-example-com-origin.conf"
        )
        .is_file()
    );
    assert!(
        logical(
            &fixture.root,
            "/etc/apache2/sites-enabled/vpsguard-example-com-origin.conf"
        )
        .is_symlink()
    );
    Ok(())
}

#[test]
fn setup_default_is_read_only_and_human_readable() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::apache()?;
    let before = count_entries(&fixture.root)?;

    let output = run(&fixture.root, &["setup"])?;

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("자동 준비 가능"));
    assert!(stdout.contains("웹서버: Apache"));
    assert!(stdout.contains("변경 수행: 0건"));
    assert_eq!(count_entries(&fixture.root)?, before);
    Ok(())
}

#[test]
fn setup_json_exposes_typed_manifest_without_secret_content()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::apache()?;

    let output = run(&fixture.root, &["setup", "--json"])?;

    assert!(output.status.success());
    let report: SiteSetupReport = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report.compatibility, SetupCompatibility::Supported);
    let site = report.site.ok_or("site manifest missing")?;
    assert_eq!(site.web_server, WebServerKind::Apache);
    assert_eq!(site.server_name, "example.com");
    assert_eq!(report.mutations_performed, 0);
    assert!(!output.stdout.windows(6).any(|window| window == b"secret"));
    Ok(())
}

fn run(root: &Path, arguments: &[&str]) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(Command::new(env!("CARGO_BIN_EXE_vps-guard"))
        .args(arguments)
        .env("VPS_GUARD_TEST_ROOT", root)
        .output()?)
}

fn logical(root: &Path, path: &str) -> PathBuf {
    root.join(path.trim_start_matches('/'))
}

fn count_entries(root: &Path) -> Result<usize, Box<dyn std::error::Error>> {
    fn count(path: &Path) -> Result<usize, Box<dyn std::error::Error>> {
        let mut total = 0_usize;
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            total = total.saturating_add(1);
            if entry.file_type()?.is_dir() {
                total = total.saturating_add(count(&entry.path())?);
            }
        }
        Ok(total)
    }
    count(root)
}
