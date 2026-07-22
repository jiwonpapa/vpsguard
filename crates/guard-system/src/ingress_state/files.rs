//! Ingress snapshot의 private file 생성과 atomic replacement helper입니다.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::Path;

use rustix::fs::{Gid, Uid};
use time::OffsetDateTime;

use super::format::{FileRecord, collect_regular_files, hash_file};
use super::{IngressStateError, io_error};

pub(super) fn create_private_dir(path: &Path) -> Result<(), IngressStateError> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|source| io_error("create_private_directory", path, source))
}

pub(super) fn create_private_dir_all(path: &Path) -> Result<(), IngressStateError> {
    let mut builder = DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(path)
        .map_err(|source| io_error("create_snapshot_root", path, source))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("snapshot_root_metadata", path, source))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(IngressStateError::Contract(
            "snapshot root가 실제 directory가 아닙니다".to_owned(),
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error("chmod_snapshot_root", path, source))
}

pub(super) fn copy_snapshot_file(
    source: &Path,
    destination: &Path,
    metadata: &fs::Metadata,
) -> Result<(), IngressStateError> {
    let mut input = File::open(source).map_err(|error| io_error("open_source", source, error))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut output = options
        .open(destination)
        .map_err(|error| io_error("create_payload", destination, error))?;
    std::io::copy(&mut input, &mut output)
        .map_err(|error| io_error("copy_payload", destination, error))?;
    fs::set_permissions(
        destination,
        fs::Permissions::from_mode(metadata.mode() & 0o7777),
    )
    .map_err(|error| io_error("chmod_payload", destination, error))?;
    output
        .sync_all()
        .map_err(|error| io_error("sync_payload", destination, error))
}

pub(super) fn replace_file(
    source: &Path,
    destination: &Path,
    record: &FileRecord,
    preserve_owner: bool,
) -> Result<(), IngressStateError> {
    if fs::symlink_metadata(destination)
        .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
    {
        return Err(IngressStateError::Contract(format!(
            "ingress file destination이 directory입니다: {}",
            destination.display()
        )));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| IngressStateError::Contract("restore parent가 없습니다".to_owned()))?;
    let temp = parent.join(format!(".vpsguard-ingress-restore-{}", std::process::id()));
    if temp.exists() {
        return Err(IngressStateError::Contract(format!(
            "restore temp가 존재합니다: {}",
            temp.display()
        )));
    }
    let mut input = File::open(source).map_err(|error| io_error("open_payload", source, error))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(record.mode);
    let mut output = options
        .open(&temp)
        .map_err(|error| io_error("create_restore_temp", &temp, error))?;
    std::io::copy(&mut input, &mut output)
        .map_err(|error| io_error("copy_restore", &temp, error))?;
    fs::set_permissions(&temp, fs::Permissions::from_mode(record.mode))
        .map_err(|error| io_error("chmod_restore", &temp, error))?;
    if preserve_owner {
        let current = fs::metadata(destination).ok();
        let uid = record
            .uid
            .or_else(|| current.as_ref().map(MetadataExt::uid));
        let gid = record
            .gid
            .or_else(|| current.as_ref().map(MetadataExt::gid));
        rustix::fs::chown(&temp, uid.map(Uid::from_raw), gid.map(Gid::from_raw))
            .map_err(|error| io_error("chown_restore", &temp, std::io::Error::from(error)))?;
    }
    output
        .sync_all()
        .map_err(|error| io_error("sync_restore", &temp, error))?;
    if let Err(error) = fs::rename(&temp, destination) {
        let _ignored = fs::remove_file(&temp);
        return Err(io_error("activate_restore", destination, error));
    }
    sync_dir(parent)
}

pub(super) fn replace_symlink(destination: &Path, target: &Path) -> Result<(), IngressStateError> {
    remove_file_if_present(destination)?;
    symlink(target, destination)
        .map_err(|source| io_error("restore_symlink", destination, source))?;
    sync_dir(destination.parent().unwrap_or_else(|| Path::new("/")))
}

pub(super) fn remove_file_if_present(path: &Path) -> Result<(), IngressStateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Err(
            IngressStateError::Contract(format!("file 경로가 directory입니다: {}", path.display())),
        ),
        Ok(_) => fs::remove_file(path).map_err(|source| io_error("remove_file", path, source)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("remove_metadata", path, source)),
    }
}

pub(super) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), IngressStateError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|source| io_error("create_snapshot_file", path, source))?;
    file.write_all(bytes)
        .map_err(|source| io_error("write_snapshot_file", path, source))?;
    file.sync_all()
        .map_err(|source| io_error("sync_snapshot_file", path, source))
}

pub(super) fn write_checksums(snapshot: &Path) -> Result<(), IngressStateError> {
    let mut sums = String::new();
    for file in collect_regular_files(snapshot, false)? {
        let relative = file
            .strip_prefix(snapshot)
            .map_err(|_| IngressStateError::Contract("checksum path escape".to_owned()))?;
        sums.push_str(&format!(
            "{}  ./{}\n",
            hash_file(&file)?,
            relative.display()
        ));
    }
    write_private(&snapshot.join("SHA256SUMS"), sums.as_bytes())
}

pub(super) fn sync_dir(path: &Path) -> Result<(), IngressStateError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("sync_directory", path, source))
}

pub(super) fn timestamp() -> String {
    let now = OffsetDateTime::now_utc();
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}
