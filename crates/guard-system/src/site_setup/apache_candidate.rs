//! OPS-012 표준 Apache TLS site를 public wrapper와 loopback HTTPS origin으로 준비합니다.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use guard_core::GuardConfig;
use guard_core::config::{AdminAuthProvider, DetectionProfile, OriginProtocol, UiTlsTermination};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use super::{
    MAX_CONFIG_BYTES, SITE_SETUP_SCHEMA_VERSION, SiteSetupError, SiteSetupManifest, WebServerKind,
    io_error,
};

const DEFAULT_CONFIG: &str = include_str!("../../../../configs/vps-guard.example.toml");
const STAGE_PREFIX: &str = "vpsguard-apache.";
const STAGE_FILE_NAMES: [&str; 5] = [
    "public-guarded.conf",
    "public-bypass.conf",
    "origin.conf",
    "origin-ports.conf",
    "vps-guard.toml",
];
static STAGE_SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// Apache ingress transaction staging 파일 본문입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApacheSiteCandidates {
    /// 기존 public site에 loopback Edge proxy를 삽입한 후보입니다.
    pub public_guarded: String,
    /// 설치 전 Apache site와 byte-equivalent한 bypass 후보입니다.
    pub public_bypass: String,
    /// 선택 TLS vhost를 loopback HTTPS listener로 옮긴 origin 후보입니다.
    pub origin: String,
    /// loopback HTTPS listener include입니다.
    pub origin_ports: String,
    /// observe-only VPSGuard 설정입니다.
    pub guard_config: String,
}

/// 표준 Apache 단일 TLS site의 transaction 후보를 생성합니다.
///
/// 기존 source는 읽기만 하며 public 설정, 인증서와 site data를 변경하지 않습니다.
///
/// # Errors
///
/// manifest drift, 과대 설정, 선택 vhost 부재·중복 또는 생성 설정 검증 실패를 반환합니다.
pub fn build_apache_site_candidates(
    root: &Path,
    site: &SiteSetupManifest,
) -> Result<ApacheSiteCandidates, SiteSetupError> {
    if site.schema_version != SITE_SETUP_SCHEMA_VERSION || site.web_server != WebServerKind::Apache
    {
        return Err(SiteSetupError::Contract(
            "Apache candidate manifest schema 또는 웹서버가 다릅니다".to_owned(),
        ));
    }
    validate_root(root)?;
    let source_path = logical(root, &site.active_config);
    let size = fs::metadata(&source_path)
        .map_err(|source| io_error("apache_candidate_size", &source_path, source))?
        .len();
    if size > MAX_CONFIG_BYTES {
        return Err(SiteSetupError::Contract(format!(
            "Apache site 설정이 candidate 상한을 넘습니다: bytes={size}"
        )));
    }
    let source = fs::read_to_string(&source_path)
        .map_err(|error| io_error("read_apache_candidate_source", &source_path, error))?;
    build_from_source(&source, site)
}

/// root-only Apache candidate staging directory를 원자 생성합니다.
///
/// # Errors
///
/// parent 경계, 안전한 새 directory 생성 또는 bounded 파일 write 실패를 반환합니다.
pub fn write_apache_candidate_stage(
    parent: &Path,
    candidates: &ApacheSiteCandidates,
) -> Result<PathBuf, SiteSetupError> {
    validate_root(parent)?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|source| io_error("apache_stage_parent_metadata", parent, source))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(SiteSetupError::Contract(
            "Apache stage parent가 실제 directory가 아닙니다".to_owned(),
        ));
    }
    let mut selected = None;
    for _ in 0..64 {
        let sequence = STAGE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            "{STAGE_PREFIX}{}{:06}",
            std::process::id(),
            sequence % 1_000_000
        ));
        match DirBuilder::new().mode(0o700).create(&candidate) {
            Ok(()) => {
                selected = Some(candidate);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(io_error("create_apache_stage", &candidate, source));
            }
        }
    }
    let stage = selected.ok_or_else(|| {
        SiteSetupError::Contract("Apache stage 이름을 안전하게 할당하지 못했습니다".to_owned())
    })?;
    let write_result = (|| {
        for (name, content) in [
            ("public-guarded.conf", candidates.public_guarded.as_str()),
            ("public-bypass.conf", candidates.public_bypass.as_str()),
            ("origin.conf", candidates.origin.as_str()),
            ("origin-ports.conf", candidates.origin_ports.as_str()),
            ("vps-guard.toml", candidates.guard_config.as_str()),
        ] {
            write_new(&stage.join(name), content.as_bytes(), 0o600)?;
        }
        sync_directory(&stage)?;
        sync_directory(parent)
    })();
    if let Err(error) = write_result {
        let _ = remove_apache_candidate_stage(&stage);
        return Err(error);
    }
    Ok(stage)
}

/// VPSGuard가 생성한 Apache staging 파일만 제거합니다.
///
/// # Errors
///
/// 경계 밖 경로, 예상 밖 node 또는 파일 제거 실패를 반환합니다.
pub fn remove_apache_candidate_stage(stage: &Path) -> Result<(), SiteSetupError> {
    validate_stage_path(stage)?;
    for name in STAGE_FILE_NAMES {
        let path = stage.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                fs::remove_file(&path)
                    .map_err(|source| io_error("remove_apache_stage_file", &path, source))?;
            }
            Ok(_) => {
                return Err(SiteSetupError::Contract(format!(
                    "Apache stage node가 regular file이 아닙니다: {}",
                    path.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(io_error("inspect_apache_stage_file", &path, source));
            }
        }
    }
    fs::remove_dir(stage).map_err(|source| io_error("remove_apache_stage", stage, source))?;
    if let Some(parent) = stage.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn build_from_source(
    source: &str,
    site: &SiteSetupManifest,
) -> Result<ApacheSiteCandidates, SiteSetupError> {
    let lines: Vec<_> = source.lines().map(str::to_owned).collect();
    let (start, end) = select_https_vhost(&lines, &site.server_name)?;
    let indent = lines
        .get(start)
        .map(|line| {
            line.chars()
                .take_while(|character| character.is_whitespace())
                .count()
        })
        .unwrap_or(0);
    let child_indent = " ".repeat(indent.saturating_add(4));
    let guarded = [
        format!("{child_indent}# VPSGuard OPS-012 managed public request path"),
        format!("{child_indent}ProxyRequests Off"),
        format!("{child_indent}ProxyPreserveHost On"),
        format!("{child_indent}ProxyAddHeaders On"),
        format!("{child_indent}RequestHeader unset X-Forwarded-For early"),
        format!("{child_indent}RequestHeader unset X-Forwarded-Proto early"),
        format!("{child_indent}RequestHeader unset X-Forwarded-Host early"),
        format!("{child_indent}RequestHeader set X-Forwarded-Proto \"https\""),
        format!(
            "{child_indent}RequestHeader set X-Forwarded-Host \"{}\"",
            site.server_name
        ),
        format!(
            "{child_indent}ProxyPass / http://127.0.0.1:18080/ connectiontimeout=3 timeout=65 retry=0"
        ),
        format!("{child_indent}ProxyPassReverse / http://127.0.0.1:18080/"),
    ];
    let mut public_lines = lines.clone();
    public_lines.splice(start.saturating_add(1)..start.saturating_add(1), guarded);

    let mut origin_lines = lines[start..=end].to_vec();
    origin_lines[0] = format!("{}<VirtualHost 127.0.0.1:18081>", " ".repeat(indent));
    let origin_directives = [
        format!("{child_indent}# VPSGuard OPS-012 trusted loopback Edge only"),
        format!("{child_indent}RemoteIPHeader X-Forwarded-For"),
        format!("{child_indent}RemoteIPInternalProxy 127.0.0.1"),
    ];
    origin_lines.splice(1..1, origin_directives);

    let mut config = GuardConfig::from_toml(DEFAULT_CONFIG)
        .map_err(|error| SiteSetupError::Contract(format!("기본 설정 parse 실패: {error}")))?;
    config.edge.allowed_hosts = std::iter::once(site.server_name.clone())
        .chain(site.server_aliases.iter().cloned())
        .collect();
    config.edge.canonical_host = Some(site.server_name.clone());
    config.edge.trusted_proxy_cidrs = vec![parse_ipnet("127.0.0.1/32")?, parse_ipnet("::1/128")?];
    config.origin.address = parse_address("127.0.0.1:18081")?;
    config.origin.protocol = OriginProtocol::Https;
    config.origin.sni = Some(site.server_name.clone());
    config.tls.certificates.clear();
    config.ui.public_host = None;
    config.ui.tls_termination = UiTlsTermination::Edge;
    config.ui.auth_provider = AdminAuthProvider::Pam;
    config.detection.profile = DetectionProfile::Php;
    config
        .validate()
        .map_err(|error| SiteSetupError::Contract(format!("생성 설정 검증 실패: {error}")))?;
    let guard_config = toml::to_string_pretty(&config)
        .map_err(|error| SiteSetupError::Contract(format!("생성 설정 TOML 실패: {error}")))?;

    Ok(ApacheSiteCandidates {
        public_guarded: with_original_ending(source, public_lines),
        public_bypass: source.to_owned(),
        origin: format!("{}\n", origin_lines.join("\n")),
        origin_ports: "Listen 127.0.0.1:18081 https\n".to_owned(),
        guard_config,
    })
}

fn select_https_vhost(
    lines: &[String],
    server_name: &str,
) -> Result<(usize, usize), SiteSetupError> {
    let mut matches = Vec::new();
    let mut current = None;
    for (index, line) in lines.iter().enumerate() {
        let trimmed = strip_comment(line).trim().to_owned();
        if current.is_none() && trimmed.to_ascii_lowercase().starts_with("<virtualhost ") {
            current = Some(index);
            continue;
        }
        if let Some(start) = current
            && trimmed.eq_ignore_ascii_case("</virtualhost>")
        {
            let block = &lines[start..=index];
            if opening_is_https(&lines[start])
                && block_server_name(block).as_deref() == Some(server_name)
            {
                matches.push((start, index));
            }
            current = None;
        }
    }
    match matches.as_slice() {
        [selected] => Ok(*selected),
        [] => Err(SiteSetupError::Contract(format!(
            "선택한 Apache HTTPS vhost를 찾지 못했습니다: server_name={server_name}"
        ))),
        _ => Err(SiteSetupError::Contract(format!(
            "선택한 Apache HTTPS vhost가 중복입니다: server_name={server_name}"
        ))),
    }
}

fn opening_is_https(line: &str) -> bool {
    line.trim()
        .trim_matches(|character| character == '<' || character == '>')
        .split_whitespace()
        .skip(1)
        .any(|address| address == "443" || address.ends_with(":443"))
}

fn block_server_name(lines: &[String]) -> Option<String> {
    lines.iter().find_map(|line| {
        let trimmed = strip_comment(line);
        let mut words = trimmed.split_whitespace();
        let name = words.next()?;
        name.eq_ignore_ascii_case("ServerName")
            .then(|| words.next())
            .flatten()
            .map(|value| value.trim_matches('"').to_owned())
    })
}

fn strip_comment(line: &str) -> String {
    let mut quoted = false;
    let mut output = String::new();
    for character in line.chars() {
        if character == '"' {
            quoted = !quoted;
        }
        if character == '#' && !quoted {
            break;
        }
        output.push(character);
    }
    output
}

fn with_original_ending(source: &str, lines: Vec<String>) -> String {
    let mut output = lines.join("\n");
    if source.ends_with('\n') {
        output.push('\n');
    }
    output
}

fn parse_address(value: &str) -> Result<SocketAddr, SiteSetupError> {
    value
        .parse()
        .map_err(|error| SiteSetupError::Contract(format!("고정 origin 주소 실패: {error}")))
}

fn parse_ipnet(value: &str) -> Result<IpNet, SiteSetupError> {
    value
        .parse()
        .map_err(|error| SiteSetupError::Contract(format!("고정 trusted CIDR 실패: {error}")))
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), SiteSetupError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|source| io_error("create_apache_stage_file", path, source))?;
    file.write_all(bytes)
        .map_err(|source| io_error("write_apache_stage_file", path, source))?;
    file.sync_all()
        .map_err(|source| io_error("sync_apache_stage_file", path, source))
}

fn sync_directory(path: &Path) -> Result<(), SiteSetupError> {
    let directory =
        fs::File::open(path).map_err(|source| io_error("open_apache_stage_dir", path, source))?;
    directory
        .sync_all()
        .map_err(|source| io_error("sync_apache_stage_dir", path, source))
}

fn validate_stage_path(stage: &Path) -> Result<(), SiteSetupError> {
    let name = stage.file_name().and_then(|value| value.to_str());
    let suffix = name.and_then(|value| value.strip_prefix(STAGE_PREFIX));
    if stage.is_absolute()
        && stage.parent().is_some()
        && suffix.is_some_and(|value| {
            !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
    {
        Ok(())
    } else {
        Err(SiteSetupError::Contract(format!(
            "Apache stage path가 owned direct child가 아닙니다: {}",
            stage.display()
        )))
    }
}

fn validate_root(root: &Path) -> Result<(), SiteSetupError> {
    if root.is_absolute()
        && !root
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        Ok(())
    } else {
        Err(SiteSetupError::Contract(format!(
            "Apache candidate root가 절대 정규 경로가 아닙니다: {}",
            root.display()
        )))
    }
}

fn logical(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.to_path_buf()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::PhpRuntime;

    #[test]
    fn builds_guarded_bypass_origin_and_valid_observe_config()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let root = temporary.path().join("root");
        fs::create_dir_all(root.join("etc/apache2/sites-available"))?;
        let manifest = manifest();
        let source = r#"<VirtualHost *:80>
    ServerName community.example.com
</VirtualHost>
<VirtualHost *:443>
    ServerName community.example.com
    DocumentRoot /var/www/community/public
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/community.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/community.example.com/privkey.pem
    <FilesMatch "\.php$">
        SetHandler "proxy:unix:/run/php/php8.3-fpm.sock|fcgi://localhost"
    </FilesMatch>
</VirtualHost>
"#;
        fs::write(
            root.join("etc/apache2/sites-available/community.conf"),
            source,
        )?;

        let candidates = build_apache_site_candidates(&root, &manifest)?;

        assert_eq!(candidates.public_bypass, source);
        assert!(candidates.public_guarded.contains(
            "ProxyPass / http://127.0.0.1:18080/ connectiontimeout=3 timeout=65 retry=0"
        ));
        assert!(
            candidates
                .origin
                .starts_with("<VirtualHost 127.0.0.1:18081>")
        );
        assert!(!candidates.origin.contains("<VirtualHost *:80>"));
        assert!(
            candidates
                .origin
                .contains("RemoteIPInternalProxy 127.0.0.1")
        );
        assert_eq!(candidates.origin_ports, "Listen 127.0.0.1:18081 https\n");
        let config = GuardConfig::from_toml(&candidates.guard_config)?;
        assert_eq!(config.origin.protocol, OriginProtocol::Https);
        assert_eq!(config.origin.sni.as_deref(), Some("community.example.com"));
        assert_eq!(config.detection.profile, DetectionProfile::Php);
        assert_eq!(config.ui.auth_provider, AdminAuthProvider::Pam);
        assert!(config.tls.certificates.is_empty());
        Ok(())
    }

    #[test]
    fn rejects_manifest_when_selected_https_vhost_is_missing()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let root = temporary.path().join("root");
        fs::create_dir_all(root.join("etc/apache2/sites-available"))?;
        fs::write(
            root.join("etc/apache2/sites-available/community.conf"),
            "<VirtualHost *:443>\nServerName other.example.com\n</VirtualHost>\n",
        )?;

        let result = build_apache_site_candidates(&root, &manifest());

        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn stage_writer_uses_fixed_files_and_removes_only_owned_nodes()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let candidates = ApacheSiteCandidates {
            public_guarded: "guarded\n".to_owned(),
            public_bypass: "bypass\n".to_owned(),
            origin: "origin\n".to_owned(),
            origin_ports: "ports\n".to_owned(),
            guard_config: "config\n".to_owned(),
        };

        let stage = write_apache_candidate_stage(temporary.path(), &candidates)?;

        assert_eq!(
            fs::read_to_string(stage.join("public-guarded.conf"))?,
            "guarded\n"
        );
        assert_eq!(fs::read_dir(&stage)?.count(), 5);
        remove_apache_candidate_stage(&stage)?;
        assert!(!stage.exists());
        Ok(())
    }

    fn manifest() -> SiteSetupManifest {
        SiteSetupManifest {
            schema_version: SITE_SETUP_SCHEMA_VERSION,
            web_server: WebServerKind::Apache,
            server_name: "community.example.com".to_owned(),
            server_aliases: vec!["www.community.example.com".to_owned()],
            active_config: PathBuf::from("/etc/apache2/sites-available/community.conf"),
            enabled_link: PathBuf::from("/etc/apache2/sites-enabled/community.conf"),
            document_root: PathBuf::from("/var/www/community/public"),
            certificate: PathBuf::from("/etc/letsencrypt/live/community.example.com/fullchain.pem"),
            certificate_key: PathBuf::from(
                "/etc/letsencrypt/live/community.example.com/privkey.pem",
            ),
            php_runtime: PhpRuntime::PhpFpm,
        }
    }
}
