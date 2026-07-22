//! 복구된 owned file·symlink·directory·service·account의 exact read-back입니다.

use std::fs;
use std::os::unix::fs::MetadataExt;

use super::snapshot_files::hash_file;
use super::snapshot_format::LoadedSnapshot;
use super::{DeploymentStateError, DeploymentStateStore, io_error};

impl DeploymentStateStore {
    pub(super) fn verify_owned_state(
        &mut self,
        snapshot: &LoadedSnapshot,
    ) -> Result<(), DeploymentStateError> {
        for logical in &snapshot.absent_paths {
            let path = self.logical_path(logical)?;
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => {
                    return Err(DeploymentStateError::Contract(format!(
                        "복구 후에도 absent path가 존재합니다: {logical}"
                    )));
                }
                Err(source) => return Err(io_error("verify_absent_path", &path, source)),
            }
        }
        for (logical, expected) in &snapshot.symlinks {
            let path = self.logical_path(logical)?;
            let metadata = fs::symlink_metadata(&path)
                .map_err(|source| io_error("verify_symlink_metadata", &path, source))?;
            let actual = fs::read_link(&path)
                .map_err(|source| io_error("verify_symlink_target", &path, source))?;
            if !metadata.file_type().is_symlink() || actual != *expected {
                return Err(DeploymentStateError::Contract(format!(
                    "복구 symlink read-back이 다릅니다: {logical}"
                )));
            }
        }
        for (logical, expected) in &snapshot.payloads {
            let path = self.logical_path(logical)?;
            let expected_metadata = fs::metadata(expected)
                .map_err(|source| io_error("verify_payload_metadata", expected, source))?;
            let actual_metadata = fs::symlink_metadata(&path)
                .map_err(|source| io_error("verify_owned_metadata", &path, source))?;
            let same_metadata = actual_metadata.is_file()
                && !actual_metadata.file_type().is_symlink()
                && actual_metadata.mode() & 0o7777 == expected_metadata.mode() & 0o7777
                && actual_metadata.uid() == expected_metadata.uid()
                && actual_metadata.gid() == expected_metadata.gid();
            if !same_metadata || hash_file(&path)? != hash_file(expected)? {
                return Err(DeploymentStateError::Contract(format!(
                    "복구 file read-back이 다릅니다: {logical}"
                )));
            }
        }
        for (logical, expected_present) in &snapshot.directories {
            let path = self.logical_path(logical)?;
            let actual_present = match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Ok(_) => {
                    return Err(DeploymentStateError::Contract(format!(
                        "owned directory read-back type이 다릅니다: {logical}"
                    )));
                }
                Err(source) => return Err(io_error("verify_owned_directory", &path, source)),
            };
            if actual_present != *expected_present {
                return Err(DeploymentStateError::Contract(format!(
                    "owned directory presence가 다릅니다: {logical}"
                )));
            }
        }
        for expected in &snapshot.services {
            if self.service_state(&expected.unit)? != *expected {
                return Err(DeploymentStateError::Contract(format!(
                    "service state read-back이 다릅니다: {}",
                    expected.unit
                )));
            }
        }
        if self.account_exists()? != snapshot.account_present {
            return Err(DeploymentStateError::Contract(
                "vps-guard account presence read-back이 다릅니다".to_owned(),
            ));
        }
        Ok(())
    }
}
