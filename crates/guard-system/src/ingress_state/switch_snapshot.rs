//! Public ingress switch 전용 exact-file snapshot, staged release와 복원입니다.

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use serde::{Deserialize, Serialize};

use super::files::{
    copy_snapshot_file, create_private_dir, create_private_dir_all, remove_file_if_present,
    replace_file, sync_dir, timestamp, write_checksums, write_private,
};
use super::format::{FileRecord, Presence, ServiceRecord, verify_checksums};
use super::switch::{IngressSwitchConfig, IngressSwitchDirection};
use super::{EDGE_SERVICE, IngressStateError, IngressStateStore, io_error};

pub(super) const SWITCH_SCHEMA_VERSION: u32 = 2;
static SWITCH_SEQUENCE: AtomicU32 = AtomicU32::new(0);

const SNAPSHOT_FILES: [(&str, &str); 4] = [
    ("active-nginx.conf", "active_config"),
    ("active-guard.toml", "active_guard_config"),
    ("edge-candidate.conf", "edge_candidate"),
    ("nginx-candidate.conf", "nginx_candidate"),
];

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SwitchSnapshot {
    schema_version: u32,
    files: Vec<FileRecord>,
    edge_service: ServiceRecord,
}

pub(super) fn create(
    config: &IngressSwitchConfig,
    store: &mut IngressStateStore,
) -> Result<PathBuf, IngressStateError> {
    create_private_dir_all(&config.backup_root)?;
    let sequence = SWITCH_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let path = config.backup_root.join(format!(
        "ingress-{}-{}{:06}",
        timestamp(),
        std::process::id(),
        sequence % 1_000_000
    ));
    create_private_dir(&path)?;
    let mut files = Vec::with_capacity(SNAPSHOT_FILES.len());
    for (payload, field) in SNAPSHOT_FILES {
        let logical = config_path(config, field)?;
        let source = logical_path(store, logical)?;
        let metadata = fs::symlink_metadata(&source).ok();
        if let Some(metadata) = &metadata {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(IngressStateError::Contract(format!(
                    "switch snapshot 대상이 regular file이 아닙니다: {}",
                    source.display()
                )));
            }
            copy_snapshot_file(&source, &path.join(payload), metadata)?;
        }
        files.push(FileRecord {
            logical: logical.display().to_string(),
            payload: payload.to_owned(),
            presence: if metadata.is_some() {
                Presence::Present
            } else {
                Presence::Absent
            },
            mode: metadata.as_ref().map_or(0, |value| value.mode() & 0o7777),
            uid: metadata.as_ref().map(MetadataExt::uid),
            gid: metadata.as_ref().map(MetadataExt::gid),
        });
    }
    let record = SwitchSnapshot {
        schema_version: SWITCH_SCHEMA_VERSION,
        files,
        edge_service: store.service_state(EDGE_SERVICE)?,
    };
    write_private(
        &path.join("manifest.json"),
        &serde_json::to_vec_pretty(&record)?,
    )?;
    write_checksums(&path)?;
    sync_dir(&path)?;
    Ok(path)
}

pub(super) fn stage_release(
    config: &IngressSwitchConfig,
    store: &IngressStateStore,
    direction: IngressSwitchDirection,
) -> Result<(), IngressStateError> {
    let Some(stage) = &config.stage_root else {
        return Ok(());
    };
    let owner = if config.state.test_root.is_some() {
        (None, None)
    } else {
        let active = logical_path(store, &config.active_guard_config)?;
        let metadata = fs::metadata(&active)
            .map_err(|source| io_error("active_guard_metadata", &active, source))?;
        (Some(metadata.uid()), Some(metadata.gid()))
    };
    install(
        store,
        &stage.join("g7devops-edge.conf"),
        &config.edge_candidate,
        0o640,
        owner,
    )?;
    install(
        store,
        &stage.join("g7devops-bypass.conf"),
        &config.nginx_candidate,
        0o640,
        owner,
    )?;
    if direction == IngressSwitchDirection::ToEdge {
        install(
            store,
            &stage.join("vps-guard.ingress.toml"),
            &config.active_guard_config,
            0o640,
            owner,
        )?;
    }
    Ok(())
}

pub(super) fn restore(
    config: &IngressSwitchConfig,
    store: &IngressStateStore,
    snapshot: &Path,
) -> Result<ServiceRecord, IngressStateError> {
    validate_snapshot_path(config, snapshot)?;
    verify_checksums(snapshot)?;
    let record: SwitchSnapshot = serde_json::from_slice(
        &fs::read(snapshot.join("manifest.json"))
            .map_err(|source| io_error("read_switch_manifest", snapshot, source))?,
    )?;
    validate_manifest(config, &record)?;
    for file in &record.files {
        let destination = logical_path(store, Path::new(&file.logical))?;
        store.ensure_safe_parent(&destination)?;
        match file.presence {
            Presence::Present => replace_file(
                &snapshot.join(&file.payload),
                &destination,
                file,
                config.state.test_root.is_none(),
            )?,
            Presence::Absent => remove_file_if_present(&destination)?,
        }
    }
    Ok(record.edge_service)
}

fn install(
    store: &IngressStateStore,
    source: &Path,
    logical: &Path,
    mode: u32,
    owner: (Option<u32>, Option<u32>),
) -> Result<(), IngressStateError> {
    require_stage_file(source)?;
    let destination = logical_path(store, logical)?;
    store.ensure_safe_parent(&destination)?;
    replace_file(
        source,
        &destination,
        &FileRecord {
            logical: logical.display().to_string(),
            payload: String::new(),
            presence: Presence::Present,
            mode,
            uid: owner.0,
            gid: owner.1,
        },
        store.config.test_root.is_none(),
    )
}

fn validate_manifest(
    config: &IngressSwitchConfig,
    record: &SwitchSnapshot,
) -> Result<(), IngressStateError> {
    if record.schema_version != SWITCH_SCHEMA_VERSION || record.files.len() != SNAPSHOT_FILES.len()
    {
        return Err(IngressStateError::Contract(
            "switch snapshot schema 또는 file 수가 잘못됐습니다".to_owned(),
        ));
    }
    let mut seen = BTreeSet::new();
    for (payload, field) in SNAPSHOT_FILES {
        let logical = config_path(config, field)?.display().to_string();
        let file = record
            .files
            .iter()
            .find(|candidate| candidate.logical == logical)
            .ok_or_else(|| {
                IngressStateError::Contract(format!("switch snapshot file이 없습니다: {logical}"))
            })?;
        if file.payload != payload || !seen.insert(&file.logical) || file.mode > 0o7777 {
            return Err(IngressStateError::Contract(
                "switch snapshot file 계약이 잘못됐습니다".to_owned(),
            ));
        }
    }
    if record.edge_service.unit != EDGE_SERVICE {
        return Err(IngressStateError::Contract(
            "switch snapshot service가 잘못됐습니다".to_owned(),
        ));
    }
    Ok(())
}

fn validate_snapshot_path(
    config: &IngressSwitchConfig,
    snapshot: &Path,
) -> Result<(), IngressStateError> {
    let name = snapshot.file_name().and_then(|value| value.to_str());
    if snapshot.parent() != Some(config.backup_root.as_path())
        || name.is_none_or(|value| !value.starts_with("ingress-"))
    {
        return Err(IngressStateError::Contract(
            "switch snapshot이 bounded root의 direct child가 아닙니다".to_owned(),
        ));
    }
    Ok(())
}

fn logical_path(store: &IngressStateStore, logical: &Path) -> Result<PathBuf, IngressStateError> {
    store.logical_path(
        logical.to_str().ok_or_else(|| {
            IngressStateError::Contract("switch path가 UTF-8이 아닙니다".to_owned())
        })?,
    )
}

fn config_path<'a>(
    config: &'a IngressSwitchConfig,
    field: &str,
) -> Result<&'a Path, IngressStateError> {
    match field {
        "active_config" => Ok(&config.active_config),
        "active_guard_config" => Ok(&config.active_guard_config),
        "edge_candidate" => Ok(&config.edge_candidate),
        "nginx_candidate" => Ok(&config.nginx_candidate),
        _ => Err(IngressStateError::Contract(
            "switch snapshot 내부 field가 잘못됐습니다".to_owned(),
        )),
    }
}

fn require_stage_file(path: &Path) -> Result<(), IngressStateError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("staged_switch_metadata", path, source))?;
    if metadata.is_file() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(IngressStateError::Contract(format!(
            "staged switch file이 regular file이 아닙니다: {}",
            path.display()
        )))
    }
}
