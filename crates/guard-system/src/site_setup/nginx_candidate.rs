//! OPS-012 표준 Nginx TLS site를 public wrapper와 loopback HTTPS origin으로 준비합니다.

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
const STAGE_PREFIX: &str = "vpsguard-cutover.";
const STAGE_FILE_NAMES: [&str; 3] = [
    "public-guarded.conf",
    "public-bypass.conf",
    "vps-guard.toml",
];
static STAGE_SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// Nginx ingress transaction staging 파일 본문입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NginxSiteCandidates {
    /// 기존 public TLS site와 loopback Edge proxy를 합성한 후보입니다.
    pub public_guarded: String,
    /// 설치 전 Nginx site와 byte-equivalent한 bypass 후보입니다.
    pub public_bypass: String,
    /// observe-only VPSGuard 설정입니다.
    pub guard_config: String,
}

/// 표준 Nginx 단일 TLS site의 transaction 후보를 생성합니다.
///
/// 기존 source는 읽기만 하며 public 설정, 인증서와 site data를 변경하지 않습니다.
///
/// # Errors
///
/// manifest drift, 과대 설정, 선택 server 부재·중복 또는 생성 설정 검증 실패를 반환합니다.
pub fn build_nginx_site_candidates(
    root: &Path,
    site: &SiteSetupManifest,
) -> Result<NginxSiteCandidates, SiteSetupError> {
    if site.schema_version != SITE_SETUP_SCHEMA_VERSION || site.web_server != WebServerKind::Nginx {
        return Err(SiteSetupError::Contract(
            "Nginx candidate manifest schema 또는 웹서버가 다릅니다".to_owned(),
        ));
    }
    validate_root(root)?;
    let source_path = logical(root, &site.active_config);
    let size = fs::metadata(&source_path)
        .map_err(|source| io_error("nginx_candidate_size", &source_path, source))?
        .len();
    if size > MAX_CONFIG_BYTES {
        return Err(SiteSetupError::Contract(format!(
            "Nginx site 설정이 candidate 상한을 넘습니다: bytes={size}"
        )));
    }
    let source = fs::read_to_string(&source_path)
        .map_err(|error| io_error("read_nginx_candidate_source", &source_path, error))?;
    build_from_source(&source, site)
}

/// root-only Nginx candidate staging directory를 원자 생성합니다.
///
/// # Errors
///
/// parent 경계, 안전한 새 directory 생성 또는 bounded 파일 write 실패를 반환합니다.
pub fn write_nginx_candidate_stage(
    parent: &Path,
    candidates: &NginxSiteCandidates,
) -> Result<PathBuf, SiteSetupError> {
    validate_root(parent)?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|source| io_error("nginx_stage_parent_metadata", parent, source))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(SiteSetupError::Contract(
            "Nginx stage parent가 실제 directory가 아닙니다".to_owned(),
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
            Err(source) => return Err(io_error("create_nginx_stage", &candidate, source)),
        }
    }
    let stage = selected.ok_or_else(|| {
        SiteSetupError::Contract("Nginx stage 이름을 안전하게 할당하지 못했습니다".to_owned())
    })?;
    let write_result = (|| {
        for (name, content) in [
            ("public-guarded.conf", candidates.public_guarded.as_str()),
            ("public-bypass.conf", candidates.public_bypass.as_str()),
            ("vps-guard.toml", candidates.guard_config.as_str()),
        ] {
            write_new(&stage.join(name), content.as_bytes(), 0o600)?;
        }
        sync_directory(&stage)?;
        sync_directory(parent)
    })();
    if let Err(error) = write_result {
        let _ = remove_nginx_candidate_stage(&stage);
        return Err(error);
    }
    Ok(stage)
}

/// VPSGuard가 생성한 Nginx staging 파일만 제거합니다.
///
/// # Errors
///
/// 경계 밖 경로, 예상 밖 node 또는 파일 제거 실패를 반환합니다.
pub fn remove_nginx_candidate_stage(stage: &Path) -> Result<(), SiteSetupError> {
    validate_stage_path(stage)?;
    for name in STAGE_FILE_NAMES {
        let path = stage.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                fs::remove_file(&path)
                    .map_err(|source| io_error("remove_nginx_stage_file", &path, source))?;
            }
            Ok(_) => {
                return Err(SiteSetupError::Contract(format!(
                    "Nginx stage node가 regular file이 아닙니다: {}",
                    path.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error("inspect_nginx_stage_file", &path, source)),
        }
    }
    fs::remove_dir(stage).map_err(|source| io_error("remove_nginx_stage", stage, source))?;
    if let Some(parent) = stage.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn build_from_source(
    source: &str,
    site: &SiteSetupManifest,
) -> Result<NginxSiteCandidates, SiteSetupError> {
    let lines: Vec<_> = source.lines().map(str::to_owned).collect();
    let blocks = server_blocks(&lines)?;
    let selected: Vec<_> = blocks
        .into_iter()
        .filter(|&(start, end)| {
            let block = &lines[start..=end];
            block_is_https(block)
                && block_server_names(block)
                    .first()
                    .is_some_and(|name| name == &site.server_name)
        })
        .collect();
    let (start, end) = match selected.as_slice() {
        [selected] => *selected,
        [] => {
            return Err(SiteSetupError::Contract(format!(
                "선택한 Nginx HTTPS server를 찾지 못했습니다: server_name={}",
                site.server_name
            )));
        }
        _ => {
            return Err(SiteSetupError::Contract(format!(
                "선택한 Nginx HTTPS server가 중복입니다: server_name={}",
                site.server_name
            )));
        }
    };
    let block = &lines[start..=end];
    let wrapper = public_wrapper(block)?;
    let origin = loopback_origin(block)?;
    let mut guarded = Vec::with_capacity(lines.len().saturating_add(origin.len()));
    guarded.extend_from_slice(&lines[..start]);
    guarded.extend(wrapper);
    guarded.extend(origin);
    guarded.extend_from_slice(&lines[end.saturating_add(1)..]);

    Ok(NginxSiteCandidates {
        public_guarded: with_original_ending(source, guarded),
        public_bypass: source.to_owned(),
        guard_config: guard_config(site)?,
    })
}

fn public_wrapper(block: &[String]) -> Result<Vec<String>, SiteSetupError> {
    let top_level = top_level_directives(block);
    let mut kept = Vec::new();
    for line in top_level {
        let name = directive_name(line)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let value = directive_value(line);
        let allowed = match name.as_str() {
            "listen" => value.is_some_and(listen_is_https),
            "server_name"
            | "ssl_certificate"
            | "ssl_certificate_key"
            | "http2"
            | "access_log"
            | "error_log"
            | "client_max_body_size"
            | "add_header" => true,
            "include" => value.is_some_and(|item| item.starts_with("/etc/letsencrypt/")),
            _ => name.starts_with("ssl_"),
        };
        if allowed {
            kept.push(format!("    {}", line.trim()));
        }
    }
    for required in [
        "listen",
        "server_name",
        "ssl_certificate",
        "ssl_certificate_key",
    ] {
        if !kept.iter().any(|line| {
            directive_name(line).is_some_and(|name| name.eq_ignore_ascii_case(required))
        }) {
            return Err(SiteSetupError::Contract(format!(
                "Nginx public wrapper 필수 directive가 없습니다: {required}"
            )));
        }
    }
    kept.extend([
        "    # VPSGuard OPS-012 managed public request path".to_owned(),
        "    location / {".to_owned(),
        "        proxy_http_version 1.1;".to_owned(),
        "        proxy_set_header Host $host;".to_owned(),
        "        proxy_set_header X-Forwarded-For $remote_addr;".to_owned(),
        "        proxy_set_header X-Forwarded-Proto https;".to_owned(),
        "        proxy_set_header X-Forwarded-Host $host;".to_owned(),
        "        proxy_set_header Upgrade $http_upgrade;".to_owned(),
        "        proxy_set_header Connection \"upgrade\";".to_owned(),
        "        proxy_pass http://127.0.0.1:18080;".to_owned(),
        "    }".to_owned(),
    ]);
    let mut wrapper = vec!["server {".to_owned()];
    wrapper.extend(kept);
    wrapper.push("}".to_owned());
    Ok(wrapper)
}

fn loopback_origin(block: &[String]) -> Result<Vec<String>, SiteSetupError> {
    let mut origin = Vec::with_capacity(block.len());
    let mut depth = 0_i32;
    let mut inserted_listener = false;
    for (index, line) in block.iter().enumerate() {
        let before = depth;
        depth += brace_delta(&strip_comment(line));
        if index == 0 {
            origin.push("server {".to_owned());
            continue;
        }
        if before == 1
            && directive_name(line).is_some_and(|name| name.eq_ignore_ascii_case("listen"))
        {
            if !inserted_listener {
                origin.push("    listen 127.0.0.1:18081 ssl;".to_owned());
                inserted_listener = true;
            }
            continue;
        }
        if index == block.len().saturating_sub(1) {
            continue;
        }
        origin.push(line.clone());
    }
    if !inserted_listener {
        return Err(SiteSetupError::Contract(
            "Nginx origin으로 옮길 listen directive가 없습니다".to_owned(),
        ));
    }
    origin.push("}".to_owned());
    Ok(origin)
}

fn guard_config(site: &SiteSetupManifest) -> Result<String, SiteSetupError> {
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
    toml::to_string_pretty(&config)
        .map_err(|error| SiteSetupError::Contract(format!("생성 설정 TOML 실패: {error}")))
}

fn server_blocks(lines: &[String]) -> Result<Vec<(usize, usize)>, SiteSetupError> {
    let mut blocks = Vec::new();
    let mut start = None;
    let mut depth = 0_i32;
    for (index, line) in lines.iter().enumerate() {
        let clean = strip_comment(line);
        if start.is_none()
            && clean
                .trim()
                .strip_prefix("server")
                .is_some_and(|rest| rest.trim_start().starts_with('{'))
        {
            start = Some(index);
            depth = 0;
        }
        if let Some(begin) = start {
            depth += brace_delta(&clean);
            if depth == 0 {
                blocks.push((begin, index));
                start = None;
            } else if depth < 0 {
                return Err(SiteSetupError::Contract(
                    "Nginx server brace가 잘못됐습니다".to_owned(),
                ));
            }
        }
    }
    if start.is_some() {
        return Err(SiteSetupError::Contract(
            "Nginx server block이 닫히지 않았습니다".to_owned(),
        ));
    }
    Ok(blocks)
}

fn top_level_directives(block: &[String]) -> Vec<&str> {
    let mut output = Vec::new();
    let mut depth = 0_i32;
    for line in block {
        let before = depth;
        depth += brace_delta(&strip_comment(line));
        if before == 1 && !line.trim_start().starts_with('}') {
            output.push(line.as_str());
        }
    }
    output
}

fn block_is_https(block: &[String]) -> bool {
    top_level_directives(block).iter().any(|line| {
        directive_name(line).is_some_and(|name| name.eq_ignore_ascii_case("listen"))
            && directive_value(line).is_some_and(listen_is_https)
    })
}

fn block_server_names(block: &[String]) -> Vec<String> {
    top_level_directives(block)
        .into_iter()
        .find_map(|line| {
            directive_name(line)
                .is_some_and(|name| name.eq_ignore_ascii_case("server_name"))
                .then(|| directive_value(line))
                .flatten()
        })
        .map(|value| {
            value
                .split_whitespace()
                .map(|item| item.trim_end_matches(';').to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn directive_name(line: &str) -> Option<&str> {
    line.split('#')
        .next()?
        .split_whitespace()
        .next()
        .map(|name| name.trim())
}

fn directive_value(line: &str) -> Option<&str> {
    let clean = line.split('#').next()?.trim();
    let (_, value) = clean.split_once(char::is_whitespace)?;
    Some(value.trim().trim_end_matches(';').trim())
}

fn listen_is_https(value: &str) -> bool {
    value
        .split_whitespace()
        .any(|item| item == "443" || item.ends_with(":443"))
}

fn strip_comment(line: &str) -> String {
    let mut quoted = false;
    let mut output = String::new();
    for character in line.chars() {
        if character == '"' || character == '\'' {
            quoted = !quoted;
        }
        if character == '#' && !quoted {
            break;
        }
        output.push(character);
    }
    output
}

fn brace_delta(line: &str) -> i32 {
    let mut quoted = false;
    line.chars().fold(0_i32, |mut depth, character| {
        if character == '"' || character == '\'' {
            quoted = !quoted;
        } else if !quoted {
            if character == '{' {
                depth += 1;
            } else if character == '}' {
                depth -= 1;
            }
        }
        depth
    })
}

fn with_original_ending(source: &str, lines: Vec<String>) -> String {
    let mut output = lines.join("\n");
    if source.ends_with('\n') {
        output.push('\n');
    }
    output
}

fn parse_ipnet(value: &str) -> Result<IpNet, SiteSetupError> {
    value
        .parse()
        .map_err(|error| SiteSetupError::Contract(format!("CIDR parse 실패: {error}")))
}

fn parse_address(value: &str) -> Result<SocketAddr, SiteSetupError> {
    value
        .parse()
        .map_err(|error| SiteSetupError::Contract(format!("origin address parse 실패: {error}")))
}

fn validate_root(path: &Path) -> Result<(), SiteSetupError> {
    if path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        Ok(())
    } else {
        Err(SiteSetupError::Contract(format!(
            "Nginx candidate root가 절대 정규 경로가 아닙니다: {}",
            path.display()
        )))
    }
}

fn validate_stage_path(stage: &Path) -> Result<(), SiteSetupError> {
    validate_root(stage)?;
    let name = stage
        .file_name()
        .and_then(|value| value.to_str())
        .and_then(|value| value.strip_prefix(STAGE_PREFIX))
        .ok_or_else(|| SiteSetupError::Contract("Nginx stage 이름이 잘못됐습니다".to_owned()))?;
    if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(SiteSetupError::Contract(
            "Nginx stage suffix가 잘못됐습니다".to_owned(),
        ));
    }
    Ok(())
}

fn logical(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.to_path_buf()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
}

fn write_new(path: &Path, content: &[u8], mode: u32) -> Result<(), SiteSetupError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|source| io_error("create_nginx_stage_file", path, source))?;
    file.write_all(content)
        .map_err(|source| io_error("write_nginx_stage_file", path, source))?;
    file.sync_all()
        .map_err(|source| io_error("sync_nginx_stage_file", path, source))
}

fn sync_directory(path: &Path) -> Result<(), SiteSetupError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("sync_nginx_stage_directory", path, source))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use super::*;
    use crate::PhpRuntime;

    fn manifest() -> SiteSetupManifest {
        SiteSetupManifest {
            schema_version: SITE_SETUP_SCHEMA_VERSION,
            web_server: WebServerKind::Nginx,
            server_name: "blog.example.com".to_owned(),
            server_aliases: vec!["www.blog.example.com".to_owned()],
            active_config: PathBuf::from("/etc/nginx/sites-available/blog.conf"),
            enabled_link: PathBuf::from("/etc/nginx/sites-enabled/blog.conf"),
            document_root: PathBuf::from("/var/www/blog"),
            certificate: PathBuf::from("/etc/letsencrypt/live/blog.example.com/fullchain.pem"),
            certificate_key: PathBuf::from("/etc/letsencrypt/live/blog.example.com/privkey.pem"),
            php_runtime: PhpRuntime::PhpFpm,
        }
    }

    #[test]
    fn builds_guarded_public_and_loopback_origin_without_touching_source()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = r#"server {
    listen 80;
    server_name blog.example.com;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl http2;
    server_name blog.example.com www.blog.example.com;
    root /var/www/blog;
    ssl_certificate /etc/letsencrypt/live/blog.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/blog.example.com/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }
}
"#;

        let candidates = build_from_source(source, &manifest())?;

        assert_eq!(candidates.public_bypass, source);
        assert!(
            candidates
                .public_guarded
                .contains("proxy_pass http://127.0.0.1:18080;")
        );
        assert!(
            candidates
                .public_guarded
                .contains("listen 127.0.0.1:18081 ssl;")
        );
        assert!(
            candidates
                .public_guarded
                .contains("fastcgi_pass unix:/run/php/php8.3-fpm.sock;")
        );
        assert!(!candidates.guard_config.contains("g7devops.com"));
        Ok(())
    }

    #[test]
    fn stage_is_private_and_removes_only_owned_files() -> Result<(), Box<dyn std::error::Error>> {
        let parent = TempDir::new()?;
        let candidates = build_from_source(
            r#"server {
    listen 443 ssl;
    server_name blog.example.com;
    root /var/www/blog;
    ssl_certificate /etc/ssl/blog/fullchain.pem;
    ssl_certificate_key /etc/ssl/blog/privkey.pem;
    location ~ \.php$ { fastcgi_pass unix:/run/php/php8.3-fpm.sock; }
}
"#,
            &manifest(),
        )?;

        let stage = write_nginx_candidate_stage(parent.path(), &candidates)?;

        assert_eq!(fs::metadata(&stage)?.permissions().mode() & 0o777, 0o700);
        assert_eq!(
            fs::metadata(stage.join("vps-guard.toml"))?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        remove_nginx_candidate_stage(&stage)?;
        assert!(!stage.exists());
        Ok(())
    }

    #[test]
    fn rejects_duplicate_selected_https_server() {
        let block = r#"server {
    listen 443 ssl;
    server_name blog.example.com;
    ssl_certificate /etc/ssl/a;
    ssl_certificate_key /etc/ssl/b;
}
"#;
        let source = format!("{block}{block}");

        let result = build_from_source(&source, &manifest());

        assert!(result.is_err());
    }

    #[test]
    fn public_wrapper_drops_application_locations() -> Result<(), SiteSetupError> {
        let source = r#"server {
    listen 443 ssl;
    server_name blog.example.com;
    root /var/www/blog;
    ssl_certificate /etc/ssl/a;
    ssl_certificate_key /etc/ssl/b;
    location /admin { deny all; }
}
"#;

        let candidate = build_from_source(source, &manifest())?;
        let public = candidate
            .public_guarded
            .split("listen 127.0.0.1:18081")
            .next()
            .unwrap_or_default();

        assert!(!public.contains("location /admin"));
        Ok(())
    }

    #[test]
    fn fixture_source_remains_byte_identical() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let root = temporary.path().join("root");
        let active = root.join("etc/nginx/sites-available/blog.conf");
        fs::create_dir_all(active.parent().ok_or("parent")?)?;
        fs::write(
            &active,
            r#"server {
    listen 443 ssl;
    server_name blog.example.com;
    root /var/www/blog;
    ssl_certificate /etc/ssl/a;
    ssl_certificate_key /etc/ssl/b;
    location ~ \.php$ { fastcgi_pass unix:/run/php/php8.3-fpm.sock; }
}
"#,
        )?;
        let before = fs::read(&active)?;

        let _candidates = build_nginx_site_candidates(&root, &manifest())?;

        assert_eq!(fs::read(&active)?, before);
        Ok(())
    }

    #[allow(dead_code)]
    fn _assert_path(_: &Path) {}
}
