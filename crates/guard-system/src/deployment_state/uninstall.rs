//! OPS-006 uninstall 전 versioned release의 bounded snapshot과 exact restore입니다.
//!
//! 운영 release root 전체를 일반 재귀 복사하지 않습니다. 최대 8개 40-hex
//! release와 각 release의 고정된 네 binary만 허용합니다.

#[cfg(test)]
mod tests;

use std::collections::BTreeSet;
use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use rustix::fs::{Gid, Uid};
use serde::{Deserialize, Serialize};

use super::snapshot_files::{
    copy_file, create_private_dir, create_private_dir_all, hash_file, snapshot_timestamp, sync_dir,
    write_private,
};
use super::snapshot_format::{collect_regular_files, verify_checksums};
use super::{DeploymentStateError, io_error};

const SCHEMA_VERSION: u32 = 1;
const MAX_RELEASES: usize = 8;
const MAX_BINARY_BYTES: u64 = 128 * 1024 * 1024;
const RELEASE_ROOT: &str = "/usr/local/lib/vps-guard/releases";
const SNAPSHOT_ROOT: &str = "/var/backups/vps-guard/uninstall";
const BINARIES: [&str; 4] = [
    "vps-guard",
    "vps-guard-control",
    "vps-guard-edge",
    "vps-guard-privileged",
];

/// 한 uninstall release snapshot의 검증된 경로와 개수입니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallReleaseSnapshot {
    /// snapshot의 exact direct-child 경로입니다.
    pub path: PathBuf,
    /// 보존한 versioned release 수입니다.
    pub release_count: usize,
    /// 보존한 binary 수입니다.
    pub binary_count: usize,
}

/// 실제 또는 fixture versioned release snapshot 저장소입니다.
#[derive(Debug, Clone)]
pub struct UninstallReleaseStore {
    test_root: Option<PathBuf>,
    release_root: PathBuf,
    snapshot_root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotManifest {
    schema_version: u32,
    release_root_mode: u32,
    release_root_uid: u32,
    release_root_gid: u32,
    releases: Vec<ReleaseRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseRecord {
    id: String,
    mode: u32,
    uid: u32,
    gid: u32,
    bin_mode: u32,
    bin_uid: u32,
    bin_gid: u32,
    binaries: Vec<BinaryRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BinaryRecord {
    name: String,
    mode: u32,
    uid: u32,
    gid: u32,
    bytes: u64,
    sha256: String,
}

impl UninstallReleaseStore {
    /// 실제 고정 release와 private backup 경계를 만듭니다.
    #[must_use]
    pub fn production() -> Self {
        Self {
            test_root: None,
            release_root: PathBuf::from(RELEASE_ROOT),
            snapshot_root: PathBuf::from(SNAPSHOT_ROOT),
        }
    }

    /// OS mutation 없는 fixture 경계를 만듭니다.
    #[must_use]
    pub fn fixture(root: impl Into<PathBuf>, snapshots: impl Into<PathBuf>) -> Self {
        Self {
            test_root: Some(root.into()),
            release_root: PathBuf::from(RELEASE_ROOT),
            snapshot_root: snapshots.into(),
        }
    }

    /// 현재 bounded release tree를 checksum snapshot으로 저장합니다.
    ///
    /// # Errors
    ///
    /// release 이름·구조·크기 또는 filesystem 경계 위반을 반환합니다.
    pub fn create_snapshot(&self) -> Result<UninstallReleaseSnapshot, DeploymentStateError> {
        self.validate_boundaries()?;
        let source_root = self.logical(&self.release_root)?;
        let root_metadata = regular_directory(&source_root, "release root")?;
        let releases = self.inspect_releases(&source_root)?;
        create_private_dir_all(&self.snapshot_root)?;
        let pending = self.snapshot_root.join(format!(
            ".pending-uninstall-{}-{}",
            snapshot_timestamp(),
            std::process::id()
        ));
        let final_path = self.snapshot_root.join(format!(
            "uninstall-{}-{}",
            snapshot_timestamp(),
            std::process::id()
        ));
        if pending.exists() || final_path.exists() {
            return Err(DeploymentStateError::Contract(
                "uninstall release snapshot 경로가 이미 존재합니다".to_owned(),
            ));
        }
        create_private_dir(&pending)?;
        let payload = pending.join("payload");
        create_private_dir(&payload)?;
        for release in &releases {
            let source_bin = source_root.join(&release.id).join("bin");
            let destination_bin = payload.join(&release.id).join("bin");
            create_private_dir_all(&destination_bin)?;
            for binary in &release.binaries {
                let source = source_bin.join(&binary.name);
                let metadata = fs::metadata(&source)
                    .map_err(|error| io_error("uninstall_binary_metadata", &source, error))?;
                copy_file(
                    &source,
                    &destination_bin.join(&binary.name),
                    &metadata,
                    self.test_root.is_none(),
                )?;
            }
            set_directory_metadata(
                &destination_bin,
                release.bin_mode,
                release.bin_uid,
                release.bin_gid,
                self.test_root.is_none(),
            )?;
            set_directory_metadata(
                &payload.join(&release.id),
                release.mode,
                release.uid,
                release.gid,
                self.test_root.is_none(),
            )?;
        }
        let manifest = SnapshotManifest {
            schema_version: SCHEMA_VERSION,
            release_root_mode: root_metadata.mode() & 0o7777,
            release_root_uid: root_metadata.uid(),
            release_root_gid: root_metadata.gid(),
            releases,
        };
        write_private(
            &pending.join("manifest.json"),
            &serde_json::to_vec_pretty(&manifest)?,
        )?;
        self.write_checksums(&pending)?;
        sync_dir(&pending)?;
        fs::rename(&pending, &final_path)
            .map_err(|error| io_error("activate_uninstall_snapshot", &final_path, error))?;
        sync_dir(&self.snapshot_root)?;
        Ok(UninstallReleaseSnapshot {
            path: final_path,
            release_count: manifest.releases.len(),
            binary_count: manifest
                .releases
                .iter()
                .map(|release| release.binaries.len())
                .sum(),
        })
    }

    /// checksum과 manifest만 검증하고 서버 release를 변경하지 않습니다.
    ///
    /// # Errors
    ///
    /// snapshot 경로·checksum·schema 또는 payload 오류를 반환합니다.
    pub fn verify_snapshot(
        &self,
        path: &Path,
    ) -> Result<UninstallReleaseSnapshot, DeploymentStateError> {
        let manifest = self.load_snapshot(path)?;
        Ok(UninstallReleaseSnapshot {
            path: path.to_path_buf(),
            release_count: manifest.releases.len(),
            binary_count: manifest
                .releases
                .iter()
                .map(|release| release.binaries.len())
                .sum(),
        })
    }

    /// uninstall로 release root가 사라진 경우에만 snapshot을 exact 복원합니다.
    ///
    /// # Errors
    ///
    /// 기존 destination, snapshot 또는 read-back 불일치를 반환합니다.
    pub fn restore_snapshot(
        &self,
        path: &Path,
    ) -> Result<UninstallReleaseSnapshot, DeploymentStateError> {
        let manifest = self.load_snapshot(path)?;
        let destination_root = self.logical(&self.release_root)?;
        if fs::symlink_metadata(&destination_root).is_ok() {
            return Err(DeploymentStateError::Contract(
                "release restore destination이 이미 존재합니다".to_owned(),
            ));
        }
        self.ensure_safe_parent(&destination_root)?;
        create_directory(
            &destination_root,
            manifest.release_root_mode,
            manifest.release_root_uid,
            manifest.release_root_gid,
            self.test_root.is_none(),
        )?;
        for release in &manifest.releases {
            let destination = destination_root.join(&release.id);
            create_directory(
                &destination,
                release.mode,
                release.uid,
                release.gid,
                self.test_root.is_none(),
            )?;
            let destination_bin = destination.join("bin");
            create_directory(
                &destination_bin,
                release.bin_mode,
                release.bin_uid,
                release.bin_gid,
                self.test_root.is_none(),
            )?;
            for binary in &release.binaries {
                let source = path
                    .join("payload")
                    .join(&release.id)
                    .join("bin")
                    .join(&binary.name);
                let destination = destination_bin.join(&binary.name);
                let metadata = fs::metadata(&source)
                    .map_err(|error| io_error("uninstall_payload_metadata", &source, error))?;
                copy_file(&source, &destination, &metadata, self.test_root.is_none())?;
            }
        }
        let observed = self.inspect_releases(&destination_root)?;
        if observed != manifest.releases {
            return Err(DeploymentStateError::Contract(
                "uninstall release restore read-back이 snapshot과 다릅니다".to_owned(),
            ));
        }
        Ok(UninstallReleaseSnapshot {
            path: path.to_path_buf(),
            release_count: manifest.releases.len(),
            binary_count: manifest
                .releases
                .iter()
                .map(|release| release.binaries.len())
                .sum(),
        })
    }

    /// 검증된 exact snapshot direct child만 제거합니다.
    ///
    /// # Errors
    ///
    /// snapshot 검증 또는 bounded directory 제거 오류를 반환합니다.
    pub fn remove_snapshot(&self, path: &Path) -> Result<(), DeploymentStateError> {
        self.load_snapshot(path)?;
        fs::remove_dir_all(path)
            .map_err(|error| io_error("remove_uninstall_snapshot", path, error))?;
        sync_dir(&self.snapshot_root)
    }

    fn inspect_releases(&self, root: &Path) -> Result<Vec<ReleaseRecord>, DeploymentStateError> {
        let entries =
            fs::read_dir(root).map_err(|error| io_error("read_release_root", root, error))?;
        let mut releases = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| io_error("read_release_entry", root, error))?;
            let path = entry.path();
            let metadata = regular_directory(&path, "versioned release")?;
            let id = entry.file_name().to_string_lossy().into_owned();
            if !valid_release_id(&id) {
                return Err(DeploymentStateError::Contract(format!(
                    "versioned release ID가 올바르지 않습니다: {id}"
                )));
            }
            let children = directory_names(&path)?;
            if children != BTreeSet::from(["bin".to_owned()]) {
                return Err(DeploymentStateError::Contract(format!(
                    "release에는 bin directory만 허용합니다: {id}"
                )));
            }
            let bin = path.join("bin");
            let bin_metadata = regular_directory(&bin, "release bin")?;
            let binary_names = directory_names(&bin)?;
            let expected: BTreeSet<_> = BINARIES.iter().map(ToString::to_string).collect();
            if binary_names != expected {
                return Err(DeploymentStateError::Contract(format!(
                    "release binary allowlist가 일치하지 않습니다: {id}"
                )));
            }
            let mut binaries = Vec::new();
            for name in BINARIES {
                let binary = bin.join(name);
                let binary_metadata = regular_file(&binary, "release binary")?;
                if binary_metadata.len() > MAX_BINARY_BYTES {
                    return Err(DeploymentStateError::Contract(format!(
                        "release binary가 크기 제한을 넘었습니다: {id}/{name}"
                    )));
                }
                binaries.push(BinaryRecord {
                    name: name.to_owned(),
                    mode: binary_metadata.mode() & 0o7777,
                    uid: binary_metadata.uid(),
                    gid: binary_metadata.gid(),
                    bytes: binary_metadata.len(),
                    sha256: hash_file(&binary)?,
                });
            }
            releases.push(ReleaseRecord {
                id,
                mode: metadata.mode() & 0o7777,
                uid: metadata.uid(),
                gid: metadata.gid(),
                bin_mode: bin_metadata.mode() & 0o7777,
                bin_uid: bin_metadata.uid(),
                bin_gid: bin_metadata.gid(),
                binaries,
            });
        }
        releases.sort_by(|left, right| left.id.cmp(&right.id));
        if releases.is_empty() || releases.len() > MAX_RELEASES {
            return Err(DeploymentStateError::Contract(format!(
                "versioned release 수가 제한 밖입니다: {}",
                releases.len()
            )));
        }
        Ok(releases)
    }

    fn load_snapshot(&self, path: &Path) -> Result<SnapshotManifest, DeploymentStateError> {
        self.validate_snapshot_path(path)?;
        verify_checksums(path)?;
        let manifest: SnapshotManifest =
            serde_json::from_slice(&fs::read(path.join("manifest.json")).map_err(|error| {
                io_error(
                    "read_uninstall_manifest",
                    &path.join("manifest.json"),
                    error,
                )
            })?)?;
        if manifest.schema_version != SCHEMA_VERSION
            || manifest.releases.is_empty()
            || manifest.releases.len() > MAX_RELEASES
        {
            return Err(DeploymentStateError::Contract(
                "uninstall release snapshot schema 또는 개수가 올바르지 않습니다".to_owned(),
            ));
        }
        let payload = path.join("payload");
        let observed = self.inspect_releases(&payload)?;
        if observed != manifest.releases {
            return Err(DeploymentStateError::Contract(
                "uninstall release payload가 manifest와 다릅니다".to_owned(),
            ));
        }
        Ok(manifest)
    }

    fn write_checksums(&self, snapshot: &Path) -> Result<(), DeploymentStateError> {
        let mut lines = String::new();
        for file in collect_regular_files(snapshot, false)? {
            let relative = file.strip_prefix(snapshot).map_err(|_| {
                DeploymentStateError::Contract("uninstall checksum path escape".to_owned())
            })?;
            lines.push_str(&format!(
                "{}  ./{}\n",
                hash_file(&file)?,
                relative.display()
            ));
        }
        write_private(&snapshot.join("SHA256SUMS"), lines.as_bytes())
    }

    fn validate_snapshot_path(&self, path: &Path) -> Result<(), DeploymentStateError> {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        if path.parent() != Some(self.snapshot_root.as_path())
            || !name.starts_with("uninstall-")
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(DeploymentStateError::Contract(format!(
                "snapshot은 {}의 uninstall-* direct child여야 합니다",
                self.snapshot_root.display()
            )));
        }
        regular_directory(path, "uninstall snapshot")?;
        Ok(())
    }

    fn validate_boundaries(&self) -> Result<(), DeploymentStateError> {
        if !self.snapshot_root.is_absolute() || self.release_root != Path::new(RELEASE_ROOT) {
            return Err(DeploymentStateError::Contract(
                "uninstall release 경계가 절대 고정 경로가 아닙니다".to_owned(),
            ));
        }
        if let Some(root) = &self.test_root
            && (!root.is_absolute() || root == Path::new("/"))
        {
            return Err(DeploymentStateError::Contract(
                "uninstall fixture root가 올바르지 않습니다".to_owned(),
            ));
        }
        Ok(())
    }

    fn logical(&self, path: &Path) -> Result<PathBuf, DeploymentStateError> {
        if !path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        {
            return Err(DeploymentStateError::Contract(
                "uninstall release path가 정규 절대 경로가 아닙니다".to_owned(),
            ));
        }
        Ok(self.test_root.as_ref().map_or_else(
            || path.to_path_buf(),
            |root| root.join(path.strip_prefix("/").unwrap_or(path)),
        ))
    }

    fn ensure_safe_parent(&self, path: &Path) -> Result<(), DeploymentStateError> {
        let parent = path.parent().ok_or_else(|| {
            DeploymentStateError::Contract("release root parent가 없습니다".to_owned())
        })?;
        let (mut current, relative) = self.test_root.as_ref().map_or_else(
            || {
                (
                    PathBuf::from("/"),
                    parent.strip_prefix("/").unwrap_or(parent),
                )
            },
            |root| {
                (
                    root.clone(),
                    parent.strip_prefix(root).unwrap_or_else(|_| Path::new("")),
                )
            },
        );
        for component in relative.components() {
            current.push(component);
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
                Ok(_) => {
                    return Err(DeploymentStateError::Contract(format!(
                        "release restore parent가 실제 directory가 아닙니다: {}",
                        current.display()
                    )));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&current)
                        .map_err(|source| io_error("create_release_parent", &current, source))?;
                }
                Err(source) => return Err(io_error("release_parent_metadata", &current, source)),
            }
        }
        Ok(())
    }
}

fn valid_release_id(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn directory_names(path: &Path) -> Result<BTreeSet<String>, DeploymentStateError> {
    fs::read_dir(path)
        .map_err(|error| io_error("read_release_directory", path, error))?
        .map(|entry| {
            entry
                .map(|value| value.file_name().to_string_lossy().into_owned())
                .map_err(|error| io_error("read_release_child", path, error))
        })
        .collect()
}

fn regular_directory(path: &Path, label: &str) -> Result<fs::Metadata, DeploymentStateError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| io_error("directory_metadata", path, error))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(DeploymentStateError::Contract(format!(
            "{label}가 실제 directory가 아닙니다: {}",
            path.display()
        )));
    }
    Ok(metadata)
}

fn regular_file(path: &Path, label: &str) -> Result<fs::Metadata, DeploymentStateError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| io_error("file_metadata", path, error))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(DeploymentStateError::Contract(format!(
            "{label}가 regular file이 아닙니다: {}",
            path.display()
        )));
    }
    Ok(metadata)
}

fn create_directory(
    path: &Path,
    mode: u32,
    uid: u32,
    gid: u32,
    preserve_owner: bool,
) -> Result<(), DeploymentStateError> {
    let mut builder = DirBuilder::new();
    builder
        .mode(mode)
        .create(path)
        .map_err(|error| io_error("create_release_restore_directory", path, error))?;
    set_directory_metadata(path, mode, uid, gid, preserve_owner)
}

fn set_directory_metadata(
    path: &Path,
    mode: u32,
    uid: u32,
    gid: u32,
    preserve_owner: bool,
) -> Result<(), DeploymentStateError> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| io_error("chmod_release_restore_directory", path, error))?;
    if preserve_owner {
        rustix::fs::chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid))).map_err(
            |error| {
                io_error(
                    "chown_release_restore_directory",
                    path,
                    std::io::Error::from(error),
                )
            },
        )?;
    }
    Ok(())
}
