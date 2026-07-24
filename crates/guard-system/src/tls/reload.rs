//! 갱신된 TLS PEM을 런타임 전용 디렉터리에 원자적으로 준비합니다.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use guard_core::config::CertificateConfig;
use rustix::fs::{Gid, Uid};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{CertificateInspection, CertificateValidationError, validate_certificate};

/// systemd `RuntimeDirectory` 아래 TLS reload bundle 디렉터리입니다.
pub const VPS_GUARD_TLS_RELOAD_DIRECTORY: &str = "/run/vps-guard-tls/tls-reload";
/// 새 worker가 읽는 갱신 certificate chain 경로입니다.
pub const VPS_GUARD_TLS_RELOAD_CERTIFICATE: &str = "/run/vps-guard-tls/tls-reload/fullchain.pem";
/// 새 worker가 읽는 갱신 private key 경로입니다.
pub const VPS_GUARD_TLS_RELOAD_KEY: &str = "/run/vps-guard-tls/tls-reload/privkey.pem";

const CERTIFICATE_FILE_NAME: &str = "fullchain.pem";
const PRIVATE_KEY_FILE_NAME: &str = "privkey.pem";

/// 원자 준비가 끝난 TLS reload bundle의 비밀값 없는 결과입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsReloadBundle {
    /// 검증된 인증서 상태입니다.
    pub inspection: CertificateInspection,
    /// 준비된 certificate chain 경로입니다.
    pub certificate_file: PathBuf,
    /// 준비된 private key 경로입니다.
    pub key_file: PathBuf,
}

/// TLS reload bundle 준비 실패입니다.
#[derive(Debug, Error)]
pub enum TlsReloadStageError {
    /// 원본 certificate·key·SAN·유효기간 검증 실패입니다.
    #[error(transparent)]
    Certificate(#[from] CertificateValidationError),
    /// runtime root가 실제 디렉터리가 아니거나 symlink입니다.
    #[error("TLS reload runtime root가 안전한 디렉터리가 아닙니다")]
    UnsafeRuntimeRoot,
    /// reload 디렉터리를 준비하지 못했습니다.
    #[error("TLS reload 디렉터리 준비 실패: {0}")]
    PrepareDirectory(#[source] std::io::Error),
    /// 원본 PEM을 읽지 못했습니다.
    #[error("TLS reload 원본 읽기 실패: kind={kind}, cause={source}")]
    ReadSource {
        /// certificate 또는 private-key입니다.
        kind: &'static str,
        /// I/O 오류입니다.
        source: std::io::Error,
    },
    /// 임시 PEM을 쓰거나 원자 교체하지 못했습니다.
    #[error("TLS reload 파일 준비 실패: kind={kind}, cause={source}")]
    WriteBundle {
        /// certificate 또는 private-key입니다.
        kind: &'static str,
        /// I/O 오류입니다.
        source: std::io::Error,
    },
    /// staged file 소유자를 runtime service 계정으로 맞추지 못했습니다.
    #[error("TLS reload 파일 소유권 설정 실패: kind={kind}, cause={source}")]
    Ownership {
        /// certificate 또는 private-key입니다.
        kind: &'static str,
        /// OS 오류입니다.
        source: rustix::io::Errno,
    },
}

/// 갱신된 certificate와 key를 검증한 뒤 runtime 전용 경로에 원자 준비합니다.
///
/// `runtime_root`의 root·service group 경계를 그대로 사용하고 결과 파일은
/// mode `0440`으로 제한합니다. 호출자는 준비가 성공한 뒤에만 edge reload를
/// 요청해야 합니다.
///
/// # Errors
///
/// PEM 검증, runtime root 안전성, 파일 I/O 또는 소유권 설정 실패를 반환합니다.
pub fn stage_tls_reload_bundle(
    certificate: &CertificateConfig,
    runtime_root: &Path,
) -> Result<TlsReloadBundle, TlsReloadStageError> {
    let inspection = validate_certificate(certificate)?;
    let root_metadata =
        fs::symlink_metadata(runtime_root).map_err(TlsReloadStageError::PrepareDirectory)?;
    if !root_metadata.file_type().is_dir() || root_metadata.file_type().is_symlink() {
        return Err(TlsReloadStageError::UnsafeRuntimeRoot);
    }
    let owner = Uid::from_raw(root_metadata.uid());
    let group = Gid::from_raw(root_metadata.gid());
    let destination = runtime_root.join("tls-reload");
    let directory_owner = if rustix::process::geteuid() == Uid::ROOT {
        Uid::ROOT
    } else {
        owner
    };
    prepare_directory(&destination, directory_owner, group)?;

    let certificate_bytes =
        fs::read(&certificate.cert_file).map_err(|source| TlsReloadStageError::ReadSource {
            kind: "certificate",
            source,
        })?;
    let key_bytes =
        fs::read(&certificate.key_file).map_err(|source| TlsReloadStageError::ReadSource {
            kind: "private-key",
            source,
        })?;
    let certificate_file = destination.join(CERTIFICATE_FILE_NAME);
    let key_file = destination.join(PRIVATE_KEY_FILE_NAME);
    atomic_write(
        &destination,
        &certificate_file,
        &certificate_bytes,
        "certificate",
        owner,
        group,
    )?;
    atomic_write(
        &destination,
        &key_file,
        &key_bytes,
        "private-key",
        owner,
        group,
    )?;
    File::open(&destination)
        .and_then(|directory| directory.sync_all())
        .map_err(TlsReloadStageError::PrepareDirectory)?;

    Ok(TlsReloadBundle {
        inspection,
        certificate_file,
        key_file,
    })
}

fn prepare_directory(
    destination: &Path,
    owner: Uid,
    group: Gid,
) -> Result<(), TlsReloadStageError> {
    match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(TlsReloadStageError::UnsafeRuntimeRoot);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(destination)
                .map_err(TlsReloadStageError::PrepareDirectory)?;
        }
        Err(error) => return Err(TlsReloadStageError::PrepareDirectory(error)),
    }
    fs::set_permissions(destination, fs::Permissions::from_mode(0o750))
        .map_err(TlsReloadStageError::PrepareDirectory)?;
    rustix::fs::chown(destination, Some(owner), Some(group)).map_err(|source| {
        TlsReloadStageError::Ownership {
            kind: "directory",
            source,
        }
    })
}

fn atomic_write(
    directory: &Path,
    target: &Path,
    contents: &[u8],
    kind: &'static str,
    owner: Uid,
    group: Gid,
) -> Result<(), TlsReloadStageError> {
    let temporary = directory.join(format!(".{kind}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o440)
            .open(&temporary)
            .map_err(|source| TlsReloadStageError::WriteBundle { kind, source })?;
        file.write_all(contents)
            .and_then(|()| file.sync_all())
            .map_err(|source| TlsReloadStageError::WriteBundle { kind, source })?;
        rustix::fs::chown(&temporary, Some(owner), Some(group))
            .map_err(|source| TlsReloadStageError::Ownership { kind, source })?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o440))
            .map_err(|source| TlsReloadStageError::WriteBundle { kind, source })?;
        fs::rename(&temporary, target)
            .map_err(|source| TlsReloadStageError::WriteBundle { kind, source })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
#[path = "reload/tests.rs"]
mod tests;
