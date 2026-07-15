//! systemd credential 또는 절대 root-only 파일에서 비밀값을 읽습니다.

use std::env;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{Mode, OFlags, open};
use rustix::io::Errno;
use secrecy::SecretString;
use secrecy::zeroize::Zeroize;
use thiserror::Error;

/// 허용할 secret 문자열 길이 정책입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretFilePolicy {
    /// trim 뒤 최소 byte 길이입니다.
    pub min_bytes: usize,
    /// trim 뒤 최대 byte 길이입니다.
    pub max_bytes: usize,
}

/// 비밀 credential 파일 검증 실패입니다.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SecretFileError {
    /// 상대 이름인데 systemd credential directory가 없습니다.
    #[error("systemd credential directory unavailable")]
    CredentialDirectoryUnavailable,
    /// 상대 credential 이름이 단일 안전 이름이 아닙니다.
    #[error("credential name invalid")]
    CredentialNameInvalid,
    /// 파일 metadata 또는 내용을 읽지 못했습니다.
    #[error("secret file read failed")]
    ReadFailed,
    /// regular file이 아니거나 symlink입니다.
    #[error("secret must be a regular non-symlink file")]
    NotRegularFile,
    /// group 또는 other 권한이 열려 있습니다.
    #[error("secret file permissions must be 0600 or stricter")]
    PermissionsTooOpen,
    /// secret 길이 또는 문자가 정책과 다릅니다.
    #[error("secret file format invalid")]
    FormatInvalid,
}

impl SecretFileError {
    /// 비밀값과 파일 경로를 포함하지 않는 안정 오류 코드입니다.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::CredentialDirectoryUnavailable => "SYSTEMD_CREDENTIAL_DIRECTORY_UNAVAILABLE",
            Self::CredentialNameInvalid => "CREDENTIAL_NAME_INVALID",
            Self::ReadFailed => "SECRET_READ_FAILED",
            Self::NotRegularFile => "SECRET_MUST_BE_REGULAR_FILE",
            Self::PermissionsTooOpen => "SECRET_FILE_PERMISSIONS_MUST_BE_0600_OR_STRICTER",
            Self::FormatInvalid => "SECRET_FORMAT_INVALID",
        }
    }
}

/// 비밀값을 root-only 파일에서 읽고 임시 평문 buffer를 zeroize합니다.
///
/// 상대 경로는 현재 service의 `$CREDENTIALS_DIRECTORY` 아래 단일 credential
/// 이름으로만 해석합니다.
///
/// # Errors
///
/// path, file type, mode 또는 문자열 정책이 안전하지 않으면 거부합니다.
pub fn load_secret_file(
    configured: &Path,
    policy: SecretFilePolicy,
) -> Result<SecretString, SecretFileError> {
    if policy.min_bytes == 0 || policy.min_bytes > policy.max_bytes {
        return Err(SecretFileError::FormatInvalid);
    }
    let credential_directory = env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from);
    let path = resolve_credential_path(configured, credential_directory.as_deref())?;
    let descriptor = open(
        &path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == Errno::LOOP {
            SecretFileError::NotRegularFile
        } else {
            SecretFileError::ReadFailed
        }
    })?;
    let mut file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| SecretFileError::ReadFailed)?;
    if !metadata.file_type().is_file() {
        return Err(SecretFileError::NotRegularFile);
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(SecretFileError::PermissionsTooOpen);
    }
    let mut source = String::new();
    if file
        .by_ref()
        .take(policy.max_bytes.saturating_add(2) as u64)
        .read_to_string(&mut source)
        .is_err()
    {
        source.zeroize();
        return Err(SecretFileError::ReadFailed);
    }
    let value = source.trim().to_owned();
    source.zeroize();
    if !(policy.min_bytes..=policy.max_bytes).contains(&value.len())
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(SecretFileError::FormatInvalid);
    }
    Ok(value.into())
}

/// 절대 path를 유지하고 상대값은 명시된 systemd credential directory 아래에서 해석합니다.
///
/// # Errors
///
/// 상대값에 directory가 없거나 단일 안전 이름이 아니면 거부합니다.
pub fn resolve_credential_path(
    configured: &Path,
    credential_directory: Option<&Path>,
) -> Result<PathBuf, SecretFileError> {
    if configured.is_absolute() {
        return Ok(configured.to_path_buf());
    }
    let mut components = configured.components();
    let Some(Component::Normal(name)) = components.next() else {
        return Err(SecretFileError::CredentialNameInvalid);
    };
    if components.next().is_some() || name.is_empty() {
        return Err(SecretFileError::CredentialNameInvalid);
    }
    let directory = credential_directory.ok_or(SecretFileError::CredentialDirectoryUnavailable)?;
    Ok(directory.join(name))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;

    use secrecy::ExposeSecret;

    use super::{SecretFileError, SecretFilePolicy, load_secret_file, resolve_credential_path};

    #[test]
    fn loads_root_only_secret_and_rejects_open_mode() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("credential");
        fs::write(&path, "mysql://monitor:secret@127.0.0.1/db\n")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let secret = load_secret_file(
            &path,
            SecretFilePolicy {
                min_bytes: 8,
                max_bytes: 512,
            },
        )?;
        assert_eq!(
            secret.expose_secret(),
            "mysql://monitor:secret@127.0.0.1/db"
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
        assert!(matches!(
            load_secret_file(
                &path,
                SecretFilePolicy {
                    min_bytes: 8,
                    max_bytes: 512,
                }
            ),
            Err(SecretFileError::PermissionsTooOpen)
        ));
        Ok(())
    }

    #[test]
    fn resolves_only_single_relative_credential_names() {
        let directory = std::path::Path::new("/run/credentials/vps-guard-control.service");
        assert_eq!(
            resolve_credential_path(std::path::Path::new("mysql-url"), Some(directory)),
            Ok(directory.join("mysql-url"))
        );
        assert!(resolve_credential_path(std::path::Path::new("mysql-url"), None).is_err());
        assert!(
            resolve_credential_path(std::path::Path::new("../mysql-url"), Some(directory)).is_err()
        );
    }

    #[test]
    fn refuses_symlink_and_oversized_secret_files() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let target = directory.path().join("target");
        let link = directory.path().join("credential");
        fs::write(&target, "root-only-value")?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
        symlink(&target, &link)?;
        assert!(
            load_secret_file(
                &link,
                SecretFilePolicy {
                    min_bytes: 4,
                    max_bytes: 64,
                }
            )
            .is_err()
        );

        let oversized = directory.path().join("oversized");
        fs::write(&oversized, "0123456789abcdef")?;
        fs::set_permissions(&oversized, fs::Permissions::from_mode(0o600))?;
        assert!(matches!(
            load_secret_file(
                &oversized,
                SecretFilePolicy {
                    min_bytes: 4,
                    max_bytes: 8,
                }
            ),
            Err(SecretFileError::FormatInvalid)
        ));
        Ok(())
    }
}
