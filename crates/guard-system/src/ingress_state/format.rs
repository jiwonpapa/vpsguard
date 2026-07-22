//! Versioned ingress manifest와 legacy v1 checksum 검증을 제공합니다.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    DEFAULT_DENY_TARGET, FILE_SPECS, INGRESS_SNAPSHOT_SCHEMA_VERSION, IngressStateConfig,
    IngressStateError, io_error,
};

const MAX_FILES: usize = 32;
const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 384 * 1024 * 1024;
const MAX_METADATA_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Presence {
    Present,
    Absent,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileRecord {
    pub(super) logical: String,
    pub(super) payload: String,
    pub(super) presence: Presence,
    pub(super) mode: u32,
    pub(super) uid: Option<u32>,
    pub(super) gid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServiceRecord {
    pub(super) unit: String,
    pub(super) enabled: String,
    pub(super) active: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IngressManifest {
    pub(super) schema_version: u32,
    pub(super) machine_id_sha256: String,
    pub(super) label: String,
    pub(super) files: Vec<FileRecord>,
    pub(super) default_deny: Presence,
    pub(super) default_deny_target: String,
    pub(super) services: Vec<ServiceRecord>,
    pub(super) edge_public: bool,
    pub(super) public_edge_header: bool,
    pub(super) certificate_fingerprint: String,
    pub(super) protected_listeners: Option<BTreeSet<String>>,
}

pub(super) fn load_manifest(
    config: &IngressStateConfig,
    snapshot: &Path,
) -> Result<IngressManifest, IngressStateError> {
    verify_checksums(snapshot)?;
    let json = snapshot.join("manifest.json");
    let manifest = if json.exists() {
        let bytes = read_bounded(&json, MAX_METADATA_BYTES)?;
        serde_json::from_slice::<IngressManifest>(&bytes)?
    } else {
        load_legacy_manifest(snapshot)?
    };
    validate_manifest(config, snapshot, &manifest)?;
    Ok(manifest)
}

pub(super) fn verify_checksums(snapshot: &Path) -> Result<(), IngressStateError> {
    let checksum = snapshot.join("SHA256SUMS");
    let source = String::from_utf8(read_bounded(&checksum, MAX_METADATA_BYTES)?)
        .map_err(|_| IngressStateError::Contract("SHA256SUMS가 UTF-8이 아닙니다".to_owned()))?;
    let mut expected = BTreeMap::new();
    for line in source.lines() {
        let (hash, relative) = line.split_once("  ").ok_or_else(|| {
            IngressStateError::Contract("SHA256SUMS row 형식이 잘못됐습니다".to_owned())
        })?;
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(IngressStateError::Contract(
                "SHA256SUMS hash가 잘못됐습니다".to_owned(),
            ));
        }
        let relative = relative.strip_prefix("./").ok_or_else(|| {
            IngressStateError::Contract("checksum path는 ./ 상대 경로여야 합니다".to_owned())
        })?;
        validate_relative(relative)?;
        if relative == "SHA256SUMS"
            || expected
                .insert(relative.to_owned(), hash.to_ascii_lowercase())
                .is_some()
        {
            return Err(IngressStateError::Contract(
                "checksum path가 중복되거나 self-reference입니다".to_owned(),
            ));
        }
    }
    let files = collect_regular_files(snapshot, false)?;
    let actual: BTreeSet<_> = files
        .iter()
        .filter_map(|path| path.strip_prefix(snapshot).ok())
        .map(|path| path.to_string_lossy().into_owned())
        .collect();
    if actual != expected.keys().cloned().collect() {
        return Err(IngressStateError::Contract(
            "checksum inventory와 snapshot file inventory가 다릅니다".to_owned(),
        ));
    }
    for file in files {
        let relative = file
            .strip_prefix(snapshot)
            .map_err(|_| IngressStateError::Contract("checksum path escape".to_owned()))?
            .to_string_lossy()
            .into_owned();
        if expected.get(&relative) != Some(&hash_file(&file)?) {
            return Err(IngressStateError::Contract(format!(
                "snapshot checksum이 맞지 않습니다: {relative}"
            )));
        }
    }
    Ok(())
}

pub(super) fn collect_regular_files(
    root: &Path,
    include_checksum: bool,
) -> Result<Vec<PathBuf>, IngressStateError> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    let mut total = 0_u64;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|source| io_error("read_snapshot_directory", &directory, source))?
        {
            let entry =
                entry.map_err(|source| io_error("read_snapshot_entry", &directory, source))?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|source| io_error("snapshot_entry_metadata", &path, source))?;
            if metadata.file_type().is_symlink() {
                return Err(IngressStateError::Contract(format!(
                    "snapshot 내부 symlink를 거부했습니다: {}",
                    path.display()
                )));
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                if metadata.len() > MAX_FILE_BYTES {
                    return Err(IngressStateError::Contract(format!(
                        "snapshot file 크기가 제한을 넘었습니다: {}",
                        path.display()
                    )));
                }
                total = total.saturating_add(metadata.len());
                if total > MAX_TOTAL_BYTES {
                    return Err(IngressStateError::Contract(
                        "snapshot 전체 크기가 제한을 넘었습니다".to_owned(),
                    ));
                }
                if include_checksum
                    || path.file_name().and_then(|name| name.to_str()) != Some("SHA256SUMS")
                {
                    files.push(path);
                }
                if files.len() > MAX_FILES {
                    return Err(IngressStateError::Contract(
                        "snapshot file 수가 제한을 넘었습니다".to_owned(),
                    ));
                }
            } else {
                return Err(IngressStateError::Contract(format!(
                    "snapshot special file을 거부했습니다: {}",
                    path.display()
                )));
            }
        }
    }
    files.sort();
    Ok(files)
}

pub(super) fn hash_file(path: &Path) -> Result<String, IngressStateError> {
    let bytes = read_bounded(path, MAX_FILE_BYTES)?;
    Ok(hex_digest(&bytes))
}

fn load_legacy_manifest(snapshot: &Path) -> Result<IngressManifest, IngressStateError> {
    let source = String::from_utf8(read_bounded(
        &snapshot.join("manifest.tsv"),
        MAX_METADATA_BYTES,
    )?)
    .map_err(|_| IngressStateError::Contract("legacy manifest가 UTF-8이 아닙니다".to_owned()))?;
    let mut values = BTreeMap::new();
    for line in source.lines() {
        let (key, value) = line.split_once('|').ok_or_else(|| {
            IngressStateError::Contract("legacy manifest row 형식이 잘못됐습니다".to_owned())
        })?;
        validate_field(key)?;
        if !value.is_empty() {
            validate_field(value)?;
        }
        if values.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(IngressStateError::Contract(format!(
                "legacy manifest key가 중복됐습니다: {key}"
            )));
        }
    }
    let required_keys: BTreeSet<_> = [
        "schema_version",
        "machine_id_sha256",
        "label",
        "dropin",
        "default_deny",
        "default_deny_target",
        "generic_certbot_hook",
        "site_certbot_hook",
        "edge_enabled",
        "edge_active",
        "nginx_enabled",
        "nginx_active",
        "edge_public",
        "public_edge_header",
        "certificate_fingerprint",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if values.keys().cloned().collect::<BTreeSet<_>>() != required_keys
        || values.get("schema_version").map(String::as_str) != Some("1")
    {
        return Err(IngressStateError::Contract(
            "legacy manifest field 또는 schema가 잘못됐습니다".to_owned(),
        ));
    }
    let optional_state = |key: &str| -> Result<Presence, IngressStateError> {
        parse_presence(values.get(key).map(String::as_str).unwrap_or(""))
    };
    let mut files = Vec::new();
    for (index, spec) in FILE_SPECS.iter().enumerate() {
        let presence = match index {
            0 | 1 => Presence::Present,
            2 => optional_state("dropin")?,
            3 => optional_state("generic_certbot_hook")?,
            4 => optional_state("site_certbot_hook")?,
            _ => return Err(IngressStateError::Contract("legacy file index".to_owned())),
        };
        let payload = snapshot.join(spec.payload);
        let metadata = if presence == Presence::Present {
            Some(
                fs::metadata(&payload)
                    .map_err(|source| io_error("legacy_payload", &payload, source))?,
            )
        } else {
            None
        };
        files.push(FileRecord {
            logical: spec.logical.to_owned(),
            payload: spec.payload.to_owned(),
            presence,
            mode: metadata.as_ref().map_or(0, |value| value.mode() & 0o7777),
            uid: None,
            gid: None,
        });
    }
    Ok(IngressManifest {
        schema_version: 1,
        machine_id_sha256: required(&values, "machine_id_sha256")?,
        label: required(&values, "label")?,
        files,
        default_deny: parse_presence(values.get("default_deny").map(String::as_str).unwrap_or(""))?,
        default_deny_target: values
            .get("default_deny_target")
            .cloned()
            .unwrap_or_default(),
        services: vec![
            ServiceRecord {
                unit: super::EDGE_SERVICE.to_owned(),
                enabled: required(&values, "edge_enabled")?,
                active: required(&values, "edge_active")?,
            },
            ServiceRecord {
                unit: super::NGINX_SERVICE.to_owned(),
                enabled: required(&values, "nginx_enabled")?,
                active: required(&values, "nginx_active")?,
            },
        ],
        edge_public: parse_bool(&required(&values, "edge_public")?)?,
        public_edge_header: match required(&values, "public_edge_header")?.as_str() {
            "present" => true,
            "absent" => false,
            other => {
                return Err(IngressStateError::Contract(format!(
                    "public edge header 상태가 잘못됐습니다: {other}"
                )));
            }
        },
        certificate_fingerprint: required(&values, "certificate_fingerprint")?,
        protected_listeners: None,
    })
}

fn validate_manifest(
    config: &IngressStateConfig,
    snapshot: &Path,
    manifest: &IngressManifest,
) -> Result<(), IngressStateError> {
    if !matches!(manifest.schema_version, 1 | INGRESS_SNAPSHOT_SCHEMA_VERSION) {
        return Err(IngressStateError::Contract(format!(
            "지원하지 않는 ingress snapshot schema입니다: {}",
            manifest.schema_version
        )));
    }
    if manifest.machine_id_sha256.len() != 64
        || !manifest
            .machine_id_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(IngressStateError::Contract(
            "machine identity hash가 잘못됐습니다".to_owned(),
        ));
    }
    if !matches!(manifest.label.as_str(), "direct" | "rollback") {
        return Err(IngressStateError::Contract(
            "snapshot label이 잘못됐습니다".to_owned(),
        ));
    }
    if manifest.files.len() != FILE_SPECS.len() {
        return Err(IngressStateError::Contract(
            "ingress file state가 완전하지 않습니다".to_owned(),
        ));
    }
    for (record, spec) in manifest.files.iter().zip(FILE_SPECS.iter()) {
        if record.logical != spec.logical || record.payload != spec.payload {
            return Err(IngressStateError::Contract(format!(
                "ingress file allowlist가 맞지 않습니다: {}",
                record.logical
            )));
        }
        if spec.required && record.presence != Presence::Present {
            return Err(IngressStateError::Contract(format!(
                "필수 ingress file이 없습니다: {}",
                spec.logical
            )));
        }
        let payload = snapshot.join(&record.payload);
        match record.presence {
            Presence::Present => {
                let metadata = fs::symlink_metadata(&payload)
                    .map_err(|source| io_error("payload_metadata", &payload, source))?;
                if !metadata.is_file() || metadata.file_type().is_symlink() || record.mode > 0o7777
                {
                    return Err(IngressStateError::Contract(format!(
                        "payload 또는 mode가 잘못됐습니다: {}",
                        record.payload
                    )));
                }
            }
            Presence::Absent if payload.exists() => {
                return Err(IngressStateError::Contract(format!(
                    "absent payload가 snapshot에 존재합니다: {}",
                    record.payload
                )));
            }
            Presence::Absent => {}
        }
    }
    if manifest.default_deny == Presence::Present
        && manifest.default_deny_target != DEFAULT_DENY_TARGET
    {
        return Err(IngressStateError::Contract(
            "default deny symlink target이 잘못됐습니다".to_owned(),
        ));
    }
    if manifest.default_deny == Presence::Absent && !manifest.default_deny_target.is_empty() {
        return Err(IngressStateError::Contract(
            "absent default deny에 target이 있습니다".to_owned(),
        ));
    }
    let units: Vec<_> = manifest
        .services
        .iter()
        .map(|state| state.unit.as_str())
        .collect();
    if units != [super::EDGE_SERVICE, super::NGINX_SERVICE] {
        return Err(IngressStateError::Contract(
            "service state allowlist가 맞지 않습니다".to_owned(),
        ));
    }
    for state in &manifest.services {
        validate_field(&state.enabled)?;
        validate_field(&state.active)?;
    }
    validate_field(&manifest.certificate_fingerprint)?;
    if config.server_name.is_empty() || !config.public_probe_url.starts_with("https://") {
        return Err(IngressStateError::Contract(
            "public probe URL 또는 server name이 잘못됐습니다".to_owned(),
        ));
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, IngressStateError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| io_error("metadata", path, source))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > maximum {
        return Err(IngressStateError::Contract(format!(
            "bounded regular file이 아닙니다: {}",
            path.display()
        )));
    }
    fs::read(path).map_err(|source| io_error("read", path, source))
}

fn validate_relative(value: &str) -> Result<(), IngressStateError> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir
                    | Component::CurDir
                    | Component::RootDir
                    | Component::Prefix(_)
            )
        })
    {
        return Err(IngressStateError::Contract(format!(
            "잘못된 snapshot 상대 경로입니다: {value}"
        )));
    }
    Ok(())
}

fn validate_field(value: &str) -> Result<(), IngressStateError> {
    if value.is_empty() || value.len() > 4096 || value.contains(['|', '\n', '\r', '\0']) {
        return Err(IngressStateError::Contract(
            "manifest field가 표현 범위를 벗어났습니다".to_owned(),
        ));
    }
    Ok(())
}

fn required(values: &BTreeMap<String, String>, key: &str) -> Result<String, IngressStateError> {
    values
        .get(key)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| {
            IngressStateError::Contract(format!("legacy manifest field가 없습니다: {key}"))
        })
}

fn parse_presence(value: &str) -> Result<Presence, IngressStateError> {
    match value {
        "present" => Ok(Presence::Present),
        "absent" => Ok(Presence::Absent),
        other => Err(IngressStateError::Contract(format!(
            "presence가 잘못됐습니다: {other}"
        ))),
    }
}

fn parse_bool(value: &str) -> Result<bool, IngressStateError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(IngressStateError::Contract(format!(
            "boolean이 잘못됐습니다: {other}"
        ))),
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ignored = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}
