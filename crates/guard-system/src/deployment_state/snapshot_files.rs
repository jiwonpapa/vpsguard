//! Snapshot payload의 private 생성, atomic 교체와 bounded 삭제 helper입니다.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::Path;

use rustix::fs::{Gid, Uid};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use super::{DeploymentStateError, io_error};

pub(super) fn create_private_dir(path: &Path) -> Result<(), DeploymentStateError> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|source| io_error("create_private_directory", path, source))
}

pub(super) fn create_private_dir_all(path: &Path) -> Result<(), DeploymentStateError> {
    let mut builder = DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(path)
        .map_err(|source| io_error("create_snapshot_root", path, source))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error("chmod_snapshot_root", path, source))
}

pub(super) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), DeploymentStateError> {
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

pub(super) fn copy_file(
    source: &Path,
    destination: &Path,
    metadata: &fs::Metadata,
    preserve_owner: bool,
) -> Result<(), DeploymentStateError> {
    let parent = destination.parent().ok_or_else(|| {
        DeploymentStateError::Contract("snapshot payload parent가 없습니다".to_owned())
    })?;
    ensure_copy_parent(parent)?;
    let mut input = File::open(source).map_err(|error| io_error("open_source", source, error))?;
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(metadata.mode() & 0o7777);
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
    if preserve_owner {
        rustix::fs::chown(
            destination,
            Some(Uid::from_raw(metadata.uid())),
            Some(Gid::from_raw(metadata.gid())),
        )
        .map_err(|error| io_error("chown_payload", destination, std::io::Error::from(error)))?;
    }
    output
        .sync_all()
        .map_err(|error| io_error("sync_payload", destination, error))
}

pub(super) fn replace_file(
    source: &Path,
    destination: &Path,
    preserve_owner: bool,
) -> Result<(), DeploymentStateError> {
    reject_directory_destination(destination)?;
    let metadata =
        fs::metadata(source).map_err(|error| io_error("payload_metadata", source, error))?;
    let parent = destination.parent().ok_or_else(|| {
        DeploymentStateError::Contract("restore destination parent가 없습니다".to_owned())
    })?;
    let temp = parent.join(format!(".vpsguard-restore-{}", std::process::id()));
    if temp.exists() {
        return Err(DeploymentStateError::Contract(format!(
            "restore 임시 경로가 이미 존재합니다: {}",
            temp.display()
        )));
    }
    copy_file(source, &temp, &metadata, preserve_owner)?;
    let result = fs::rename(&temp, destination)
        .map_err(|error| io_error("activate_restored_file", destination, error));
    if result.is_err() {
        let _ignored = fs::remove_file(&temp);
    }
    result?;
    sync_dir(parent)
}

pub(super) fn replace_symlink(
    destination: &Path,
    target: &Path,
) -> Result<(), DeploymentStateError> {
    reject_directory_destination(destination)?;
    let parent = destination.parent().ok_or_else(|| {
        DeploymentStateError::Contract("symlink destination parent가 없습니다".to_owned())
    })?;
    let temp = parent.join(format!(".vpsguard-restore-link-{}", std::process::id()));
    if temp.exists() {
        return Err(DeploymentStateError::Contract(format!(
            "symlink 임시 경로가 이미 존재합니다: {}",
            temp.display()
        )));
    }
    symlink(target, &temp).map_err(|error| io_error("create_restored_symlink", &temp, error))?;
    let result = fs::rename(&temp, destination)
        .map_err(|error| io_error("activate_restored_symlink", destination, error));
    if result.is_err() {
        let _ignored = fs::remove_file(&temp);
    }
    result?;
    sync_dir(parent)
}

pub(super) fn remove_owned_file_if_present(path: &Path) -> Result<(), DeploymentStateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            Err(DeploymentStateError::Contract(format!(
                "owned file path의 directory를 제거하지 않습니다: {}",
                path.display()
            )))
        }
        Ok(_) => {
            fs::remove_file(path).map_err(|source| io_error("remove_owned_file", path, source))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("owned_file_metadata", path, source)),
    }
}

pub(super) fn remove_owned_directory_if_present(path: &Path) -> Result<(), DeploymentStateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(DeploymentStateError::Contract(format!(
                "owned directory 제거 대상이 실제 directory가 아닙니다: {}",
                path.display()
            )))
        }
        Ok(_) => fs::remove_dir_all(path)
            .map_err(|source| io_error("remove_owned_directory", path, source)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("owned_directory_metadata", path, source)),
    }
}

pub(super) fn hash_file(path: &Path) -> Result<String, DeploymentStateError> {
    let mut input = File::open(path).map_err(|error| io_error("hash_open", path, error))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|error| io_error("hash_read", path, error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ignored = write!(&mut encoded, "{byte:02x}");
    }
    Ok(encoded)
}

pub(super) fn lines_to_bytes(lines: &[String]) -> Vec<u8> {
    if lines.is_empty() {
        return Vec::new();
    }
    let mut output = lines.join("\n").into_bytes();
    output.push(b'\n');
    output
}

pub(super) fn sync_dir(path: &Path) -> Result<(), DeploymentStateError> {
    File::open(path)
        .map_err(|source| io_error("open_directory_for_sync", path, source))?
        .sync_all()
        .map_err(|source| io_error("sync_directory", path, source))
}

pub(super) fn snapshot_timestamp() -> String {
    let now = OffsetDateTime::now_utc();
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

fn reject_directory_destination(path: &Path) -> Result<(), DeploymentStateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            Err(DeploymentStateError::Contract(format!(
                "owned file destination이 directory입니다: {}",
                path.display()
            )))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("destination_metadata", path, source)),
    }
}

fn ensure_copy_parent(path: &Path) -> Result<(), DeploymentStateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(DeploymentStateError::Contract(format!(
            "copy parent가 실제 directory가 아닙니다: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_private_dir_all(path),
        Err(source) => Err(io_error("copy_parent_metadata", path, source)),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    use tempfile::tempdir;

    use super::ensure_copy_parent;

    #[test]
    fn existing_copy_parent_keeps_its_mode() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let parent = temp.path().join("existing");
        fs::create_dir(&parent)?;
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755))?;

        ensure_copy_parent(&parent)?;

        assert_eq!(fs::metadata(&parent)?.permissions().mode() & 0o777, 0o755);
        Ok(())
    }

    #[test]
    fn missing_copy_parent_is_created_private() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let parent = temp.path().join("payload/nested");

        ensure_copy_parent(&parent)?;

        assert!(parent.is_dir());
        assert_eq!(fs::metadata(&parent)?.permissions().mode() & 0o777, 0o700);
        Ok(())
    }

    #[test]
    fn non_directory_copy_parents_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let file = temp.path().join("file");
        let link = temp.path().join("link");
        fs::write(&file, b"sentinel")?;
        symlink(temp.path(), &link)?;

        for path in [&file, &link] {
            let error =
                ensure_copy_parent(path).map_or_else(|error| error.to_string(), |()| String::new());
            assert!(error.contains("실제 directory가 아닙니다"));
        }
        assert_eq!(fs::read(&file)?, b"sentinel");
        Ok(())
    }
}
