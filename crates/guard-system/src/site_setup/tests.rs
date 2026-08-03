//! OPS-012 Nginx·Apache 설치 탐지와 fail-closed 판정 회귀입니다.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::{PhpRuntime, SetupCompatibility, SetupIssueCode, WebServerKind, inspect_site_setup};

struct Fixture {
    _temporary: TempDir,
    root: PathBuf,
}

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;
type TreeEntry = (PathBuf, Vec<u8>);

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("root");
        for directory in [
            "/etc",
            "/etc/nginx/sites-available",
            "/etc/nginx/sites-enabled",
            "/etc/apache2/sites-available",
            "/etc/apache2/sites-enabled",
            "/etc/apache2/mods-enabled",
            "/etc/apache2/conf-enabled",
            "/run/vps-guard/setup-fixture",
        ] {
            fs::create_dir_all(logical(&root, directory))?;
        }
        fs::write(
            logical(&root, "/etc/os-release"),
            "ID=ubuntu\nVERSION_ID=\"24.04\"\n",
        )?;
        Ok(Self {
            _temporary: temporary,
            root,
        })
    }

    fn activate(&self, service: &str) -> Result<(), Box<dyn std::error::Error>> {
        fs::write(
            logical(
                &self.root,
                &format!("/run/vps-guard/setup-fixture/{service}.active"),
            ),
            "active\n",
        )?;
        Ok(())
    }

    fn add_apache(&self, name: &str, source: &str) -> Result<(), Box<dyn std::error::Error>> {
        let available = logical(
            &self.root,
            &format!("/etc/apache2/sites-available/{name}.conf"),
        );
        fs::write(&available, source)?;
        symlink(
            format!("../sites-available/{name}.conf"),
            logical(
                &self.root,
                &format!("/etc/apache2/sites-enabled/{name}.conf"),
            ),
        )?;
        Ok(())
    }

    fn add_nginx(&self, name: &str, source: &str) -> Result<(), Box<dyn std::error::Error>> {
        let available = logical(
            &self.root,
            &format!("/etc/nginx/sites-available/{name}.conf"),
        );
        fs::write(&available, source)?;
        symlink(
            format!("../sites-available/{name}.conf"),
            logical(&self.root, &format!("/etc/nginx/sites-enabled/{name}.conf")),
        )?;
        Ok(())
    }
}

#[test]
fn detects_standard_apache_php_fpm_site_without_mutation() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = Fixture::new()?;
    fixture.activate("apache2.service")?;
    fs::write(
        logical(&fixture.root, "/etc/apache2/conf-enabled/php8.3-fpm.conf"),
        "enabled\n",
    )?;
    fixture.add_apache(
        "community",
        r#"
<VirtualHost *:80>
    ServerName community.example.com
    Redirect permanent / https://community.example.com/
</VirtualHost>
<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerName community.example.com
    ServerAlias www.community.example.com
    DocumentRoot /var/www/community/public
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/community.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/community.example.com/privkey.pem
    Include /etc/letsencrypt/options-ssl-apache.conf
</VirtualHost>
</IfModule>
"#,
    )?;
    let before = tree(&fixture.root)?;

    let report = inspect_site_setup(&fixture.root)?;

    assert_eq!(report.compatibility, SetupCompatibility::Supported);
    assert_eq!(report.mutations_performed, 0);
    let site = report.supported_site()?;
    assert_eq!(site.web_server, WebServerKind::Apache);
    assert_eq!(site.server_name, "community.example.com");
    assert_eq!(site.php_runtime, PhpRuntime::PhpFpm);
    assert_eq!(
        site.active_config,
        Path::new("/etc/apache2/sites-available/community.conf")
    );
    assert_eq!(tree(&fixture.root)?, before);
    let json = serde_json::to_string(&report)?;
    assert!(!json.contains("gnuboard5"));
    Ok(())
}

#[test]
fn detects_standard_nginx_php_fpm_site() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    fixture.activate("nginx.service")?;
    fixture.add_nginx(
        "wordpress",
        r#"
server {
    listen 80;
    server_name blog.example.com;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl http2;
    server_name blog.example.com www.blog.example.com;
    root /var/www/blog/public;
    ssl_certificate /etc/letsencrypt/live/blog.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/blog.example.com/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }
}
"#,
    )?;

    let report = inspect_site_setup(&fixture.root)?;

    assert_eq!(report.compatibility, SetupCompatibility::Supported);
    let site = report.supported_site()?;
    assert_eq!(site.web_server, WebServerKind::Nginx);
    assert_eq!(site.server_name, "blog.example.com");
    assert_eq!(site.php_runtime, PhpRuntime::PhpFpm);
    Ok(())
}

#[test]
fn rejects_two_active_web_servers_without_selecting_a_site()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    fixture.activate("nginx.service")?;
    fixture.activate("apache2.service")?;

    let report = inspect_site_setup(&fixture.root)?;

    assert_eq!(report.compatibility, SetupCompatibility::Rejected);
    assert!(report.site.is_none());
    assert_eq!(
        report.issues[0].code,
        SetupIssueCode::MultipleActiveWebServers
    );
    assert_eq!(report.mutations_performed, 0);
    Ok(())
}

#[test]
fn requires_manual_review_for_existing_apache_reverse_proxy()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    fixture.activate("apache2.service")?;
    fs::write(
        logical(&fixture.root, "/etc/apache2/mods-enabled/php8.3.load"),
        "enabled\n",
    )?;
    fixture.add_apache(
        "proxy",
        r#"
<VirtualHost *:443>
    ServerName proxy.example.com
    DocumentRoot /var/www/proxy
    SSLEngine on
    SSLCertificateFile /etc/ssl/proxy/fullchain.pem
    SSLCertificateKeyFile /etc/ssl/proxy/privkey.pem
    ProxyPass /api http://127.0.0.1:9000/
</VirtualHost>
"#,
    )?;

    let report = inspect_site_setup(&fixture.root)?;

    assert_eq!(report.compatibility, SetupCompatibility::ManualReview);
    assert_eq!(report.issues[0].code, SetupIssueCode::ExistingReverseProxy);
    Ok(())
}

#[test]
fn requires_manual_review_for_multiple_https_sites() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    fixture.activate("apache2.service")?;
    fs::write(
        logical(&fixture.root, "/etc/apache2/mods-enabled/php8.3.load"),
        "enabled\n",
    )?;
    for name in ["one", "two"] {
        fixture.add_apache(
            name,
            &format!(
                r#"
<VirtualHost *:443>
    ServerName {name}.example.com
    DocumentRoot /var/www/{name}
    SSLEngine on
    SSLCertificateFile /etc/ssl/{name}/fullchain.pem
    SSLCertificateKeyFile /etc/ssl/{name}/privkey.pem
</VirtualHost>
"#
            ),
        )?;
    }

    let report = inspect_site_setup(&fixture.root)?;

    assert_eq!(report.compatibility, SetupCompatibility::ManualReview);
    assert_eq!(report.issues[0].code, SetupIssueCode::MultipleHttpsSites);
    Ok(())
}

#[test]
fn rejects_enabled_symlink_outside_available_root() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    fixture.activate("nginx.service")?;
    fs::write(logical(&fixture.root, "/etc/foreign.conf"), "server {}\n")?;
    symlink(
        "../../foreign.conf",
        logical(&fixture.root, "/etc/nginx/sites-enabled/escape.conf"),
    )?;

    let result = inspect_site_setup(&fixture.root);

    assert!(result.is_err());
    Ok(())
}

fn logical(root: &Path, path: &str) -> PathBuf {
    root.join(path.trim_start_matches('/'))
}

fn tree(root: &Path) -> TestResult<Vec<TreeEntry>> {
    fn visit(root: &Path, current: &Path, output: &mut Vec<TreeEntry>) -> TestResult<()> {
        let mut entries = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let relative = path.strip_prefix(root)?.to_path_buf();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.is_dir() {
                visit(root, &path, output)?;
            } else if metadata.file_type().is_symlink() {
                output.push((
                    relative,
                    fs::read_link(&path)?
                        .as_os_str()
                        .as_encoded_bytes()
                        .to_vec(),
                ));
            } else {
                output.push((relative, fs::read(&path)?));
            }
        }
        Ok(())
    }
    let mut output = Vec::new();
    visit(root, root, &mut output)?;
    Ok(output)
}
