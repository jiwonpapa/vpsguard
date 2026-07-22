//! Legacy v1 metadata parser와 checksum inventory 검증을 제공합니다.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use super::host::ServiceSnapshot;
use super::snapshot_files::hash_file;
use super::{
    DeploymentStateError, OWNED_DIRECTORIES, OWNED_FILES, OWNED_SERVICES, PROTECTED_PATHS,
    PROTECTED_SERVICES, io_error,
};

const MAX_SNAPSHOT_FILES: usize = 128;
const MAX_SNAPSHOT_FILE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_SNAPSHOT_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_METADATA_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
pub(super) struct LoadedSnapshot {
    pub(super) machine_id_sha256: String,
    pub(super) account_present: bool,
    pub(super) absent_paths: BTreeSet<String>,
    pub(super) symlinks: BTreeMap<String, PathBuf>,
    pub(super) payloads: BTreeMap<String, PathBuf>,
    pub(super) directories: BTreeMap<String, bool>,
    pub(super) services: Vec<ServiceSnapshot>,
    pub(super) protected: Vec<String>,
    pub(super) listeners: BTreeSet<String>,
}

pub(super) fn verify_checksums(snapshot: &Path) -> Result<(), DeploymentStateError> {
    let checksum_path = snapshot.join("SHA256SUMS");
    let lines = read_metadata_lines(&checksum_path)?;
    let mut expected = BTreeMap::new();
    for line in lines {
        let (hash, relative) = line.split_once("  ").ok_or_else(|| {
            DeploymentStateError::Contract("SHA256SUMS row 형식이 잘못됐습니다".to_owned())
        })?;
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(DeploymentStateError::Contract(
                "SHA256SUMS hash가 잘못됐습니다".to_owned(),
            ));
        }
        let relative = relative.strip_prefix("./").ok_or_else(|| {
            DeploymentStateError::Contract("checksum path는 ./ 상대 경로여야 합니다".to_owned())
        })?;
        validate_relative_snapshot_path(relative)?;
        if relative == "SHA256SUMS"
            || expected
                .insert(relative.to_owned(), hash.to_owned())
                .is_some()
        {
            return Err(DeploymentStateError::Contract(
                "checksum path가 중복되거나 self-reference입니다".to_owned(),
            ));
        }
    }
    let actual_files = collect_regular_files(snapshot, false)?;
    let actual: BTreeSet<_> = actual_files
        .iter()
        .filter_map(|path| path.strip_prefix(snapshot).ok())
        .map(|path| path.to_string_lossy().into_owned())
        .collect();
    let expected_paths: BTreeSet<_> = expected.keys().cloned().collect();
    if actual != expected_paths {
        return Err(DeploymentStateError::Contract(
            "checksum inventory와 snapshot file inventory가 다릅니다".to_owned(),
        ));
    }
    for file in actual_files {
        let relative = file
            .strip_prefix(snapshot)
            .map(|path| path.to_string_lossy().into_owned())
            .map_err(|_| DeploymentStateError::Contract("checksum path escape".to_owned()))?;
        if expected.get(&relative) != Some(&hash_file(&file)?) {
            return Err(DeploymentStateError::Contract(format!(
                "snapshot checksum이 맞지 않습니다: {relative}"
            )));
        }
    }
    Ok(())
}

pub(super) fn collect_regular_files(
    root: &Path,
    include_checksum: bool,
) -> Result<Vec<PathBuf>, DeploymentStateError> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    let mut directories = 0_usize;
    let mut total_bytes = 0_u64;
    while let Some(directory) = pending.pop() {
        directories += 1;
        if directories > MAX_SNAPSHOT_FILES {
            return Err(DeploymentStateError::Contract(
                "snapshot directory 수가 제한을 넘었습니다".to_owned(),
            ));
        }
        let entries = fs::read_dir(&directory)
            .map_err(|source| io_error("read_snapshot_directory", &directory, source))?;
        for entry in entries {
            let entry =
                entry.map_err(|source| io_error("read_snapshot_entry", &directory, source))?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|source| io_error("snapshot_entry_metadata", &path, source))?;
            if metadata.file_type().is_symlink() {
                return Err(DeploymentStateError::Contract(format!(
                    "snapshot 내부 symlink를 거부했습니다: {}",
                    path.display()
                )));
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                total_bytes = total_bytes.saturating_add(metadata.len());
                if metadata.len() > MAX_SNAPSHOT_FILE_BYTES {
                    return Err(DeploymentStateError::Contract(format!(
                        "snapshot file 크기가 제한을 넘었습니다: {}",
                        path.display()
                    )));
                }
                if total_bytes > MAX_SNAPSHOT_TOTAL_BYTES {
                    return Err(DeploymentStateError::Contract(
                        "snapshot 전체 크기가 제한을 넘었습니다".to_owned(),
                    ));
                }
                if include_checksum
                    || path.file_name().and_then(|name| name.to_str()) != Some("SHA256SUMS")
                {
                    files.push(path);
                }
                if files.len() > MAX_SNAPSHOT_FILES {
                    return Err(DeploymentStateError::Contract(
                        "snapshot file 수가 제한을 넘었습니다".to_owned(),
                    ));
                }
            } else {
                return Err(DeploymentStateError::Contract(format!(
                    "snapshot special file을 거부했습니다: {}",
                    path.display()
                )));
            }
        }
    }
    files.sort();
    Ok(files)
}

pub(super) fn collect_payloads(
    snapshot: &Path,
) -> Result<BTreeMap<String, PathBuf>, DeploymentStateError> {
    let payload_root = snapshot.join("payload");
    let mut payloads = BTreeMap::new();
    for file in collect_regular_files(&payload_root, true)? {
        let relative = file.strip_prefix(&payload_root).map_err(|_| {
            DeploymentStateError::Contract("payload path가 root를 벗어났습니다".to_owned())
        })?;
        let logical = format!("/{}", relative.to_string_lossy());
        if !OWNED_FILES.contains(&logical.as_str())
            || payloads.insert(logical.clone(), file).is_some()
        {
            return Err(DeploymentStateError::Contract(format!(
                "allowlist 밖 payload입니다: {logical}"
            )));
        }
    }
    Ok(payloads)
}

pub(super) fn parse_allowed_set(
    lines: &[String],
    allowed: &[&str],
    label: &str,
) -> Result<BTreeSet<String>, DeploymentStateError> {
    let mut values = BTreeSet::new();
    for value in lines.iter().filter(|line| !line.is_empty()) {
        if !allowed.contains(&value.as_str()) || !values.insert(value.clone()) {
            return Err(DeploymentStateError::Contract(format!(
                "잘못된 {label}입니다: {value}"
            )));
        }
    }
    Ok(values)
}

pub(super) fn parse_symlinks(
    lines: &[String],
) -> Result<BTreeMap<String, PathBuf>, DeploymentStateError> {
    let mut values = BTreeMap::new();
    for line in lines.iter().filter(|line| !line.is_empty()) {
        let (logical, target) = line.split_once('|').ok_or_else(|| {
            DeploymentStateError::Contract("symlink state 형식이 잘못됐습니다".to_owned())
        })?;
        let target = PathBuf::from(target);
        validate_symlink_target(&target)?;
        if !OWNED_FILES.contains(&logical) || values.insert(logical.to_owned(), target).is_some() {
            return Err(DeploymentStateError::Contract(format!(
                "잘못된 symlink state입니다: {logical}"
            )));
        }
    }
    Ok(values)
}

pub(super) fn validate_complete_file_state(
    absent: &BTreeSet<String>,
    symlinks: &BTreeMap<String, PathBuf>,
    payloads: &BTreeMap<String, PathBuf>,
) -> Result<(), DeploymentStateError> {
    for logical in OWNED_FILES {
        let count = usize::from(absent.contains(logical))
            + usize::from(symlinks.contains_key(logical))
            + usize::from(payloads.contains_key(logical));
        if count != 1 {
            return Err(DeploymentStateError::Contract(format!(
                "owned path state는 정확히 하나여야 합니다: {logical}"
            )));
        }
    }
    Ok(())
}

pub(super) fn parse_directory_state(
    lines: &[String],
) -> Result<BTreeMap<String, bool>, DeploymentStateError> {
    let mut values = BTreeMap::new();
    for line in lines.iter().filter(|line| !line.is_empty()) {
        let (logical, state) = line.split_once('|').ok_or_else(|| {
            DeploymentStateError::Contract("directory state 형식이 잘못됐습니다".to_owned())
        })?;
        let present = match state {
            "present" => true,
            "absent" => false,
            _ => {
                return Err(DeploymentStateError::Contract(format!(
                    "directory presence가 잘못됐습니다: {state}"
                )));
            }
        };
        if !OWNED_DIRECTORIES.contains(&logical)
            || values.insert(logical.to_owned(), present).is_some()
        {
            return Err(DeploymentStateError::Contract(format!(
                "잘못된 owned directory입니다: {logical}"
            )));
        }
    }
    if values.len() != OWNED_DIRECTORIES.len() {
        return Err(DeploymentStateError::Contract(
            "owned directory state가 완전하지 않습니다".to_owned(),
        ));
    }
    Ok(values)
}

pub(super) fn parse_service_state(
    lines: &[String],
) -> Result<Vec<ServiceSnapshot>, DeploymentStateError> {
    let mut states = BTreeMap::new();
    for line in lines.iter().filter(|line| !line.is_empty()) {
        let fields: Vec<_> = line.split('|').collect();
        if fields.len() != 3 || !OWNED_SERVICES.contains(&fields[0]) {
            return Err(DeploymentStateError::Contract(format!(
                "service state 형식 또는 unit이 잘못됐습니다: {line}"
            )));
        }
        validate_field(fields[1], "service enablement")?;
        validate_field(fields[2], "service activity")?;
        let state = ServiceSnapshot {
            unit: fields[0].to_owned(),
            enabled: fields[1].to_owned(),
            active: fields[2].to_owned(),
        };
        if states.insert(state.unit.clone(), state).is_some() {
            return Err(DeploymentStateError::Contract(
                "service state가 중복됐습니다".to_owned(),
            ));
        }
    }
    OWNED_SERVICES
        .iter()
        .map(|unit| {
            states.remove(*unit).ok_or_else(|| {
                DeploymentStateError::Contract(format!("service state가 없습니다: {unit}"))
            })
        })
        .collect()
}

pub(super) fn parse_key_values(
    lines: &[String],
    label: &str,
) -> Result<BTreeMap<String, String>, DeploymentStateError> {
    let mut values = BTreeMap::new();
    for line in lines.iter().filter(|line| !line.is_empty()) {
        let (key, value) = line.split_once('|').ok_or_else(|| {
            DeploymentStateError::Contract(format!("{label} row 형식이 잘못됐습니다"))
        })?;
        validate_field(key, label)?;
        validate_field(value, label)?;
        if values.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(DeploymentStateError::Contract(format!(
                "{label} key가 중복됐습니다: {key}"
            )));
        }
    }
    Ok(values)
}

pub(super) fn read_metadata_lines(path: &Path) -> Result<Vec<String>, DeploymentStateError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| io_error("metadata", path, source))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_METADATA_BYTES
    {
        return Err(DeploymentStateError::Contract(format!(
            "metadata file이 regular bounded file이 아닙니다: {}",
            path.display()
        )));
    }
    let value =
        fs::read_to_string(path).map_err(|source| io_error("read_metadata", path, source))?;
    if value.contains('\0') || value.contains('\r') {
        return Err(DeploymentStateError::Contract(format!(
            "metadata control character를 거부했습니다: {}",
            path.display()
        )));
    }
    Ok(value.lines().map(str::to_owned).collect())
}

pub(super) fn validate_field(value: &str, label: &str) -> Result<(), DeploymentStateError> {
    if value.is_empty() || value.len() > 4096 || value.contains(['|', '\n', '\r', '\0']) {
        return Err(DeploymentStateError::Contract(format!(
            "{label} field가 표현 범위를 벗어났습니다"
        )));
    }
    Ok(())
}

pub(super) fn validate_symlink_target(target: &Path) -> Result<(), DeploymentStateError> {
    let value = target.to_str().ok_or_else(|| {
        DeploymentStateError::Contract("symlink target이 UTF-8이 아닙니다".to_owned())
    })?;
    if value.is_empty() || value.len() > 4096 || value.contains(['|', '\n', '\r', '\0']) {
        return Err(DeploymentStateError::Contract(
            "symlink target이 표현 범위를 벗어났습니다".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_protected_state(lines: &[String]) -> Result<(), DeploymentStateError> {
    if lines.len() != PROTECTED_PATHS.len() + PROTECTED_SERVICES.len() {
        return Err(DeploymentStateError::Contract(
            "protected state row 수가 잘못됐습니다".to_owned(),
        ));
    }
    for ((name, path), line) in PROTECTED_PATHS.iter().zip(lines.iter()) {
        let prefix = format!("{name}|{path}|");
        if !line.starts_with(&prefix) || line.len() == prefix.len() {
            return Err(DeploymentStateError::Contract(format!(
                "protected path row가 잘못됐습니다: {name}"
            )));
        }
    }
    for (unit, line) in PROTECTED_SERVICES
        .iter()
        .zip(lines.iter().skip(PROTECTED_PATHS.len()))
    {
        let prefix = format!("service:{unit}|enabled=");
        let Some((enabled, activity)) = line
            .strip_prefix(&prefix)
            .and_then(|value| value.split_once("|activity="))
        else {
            return Err(DeploymentStateError::Contract(format!(
                "protected service row가 잘못됐습니다: {unit}"
            )));
        };
        validate_field(enabled, "protected service enablement")?;
        if !matches!(activity, "up" | "down" | "failed") {
            return Err(DeploymentStateError::Contract(format!(
                "protected service activity가 잘못됐습니다: {unit}"
            )));
        }
    }
    Ok(())
}

fn validate_relative_snapshot_path(value: &str) -> Result<(), DeploymentStateError> {
    let path = Path::new(value);
    if path.is_absolute()
        || value.is_empty()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::CurDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(DeploymentStateError::Contract(format!(
            "잘못된 snapshot 상대 경로입니다: {value}"
        )));
    }
    Ok(())
}
