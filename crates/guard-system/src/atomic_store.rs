//! 같은 파일시스템 내 fsync와 rename을 사용하는 원자 JSON 저장소입니다.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// 원자 JSON 저장·복구 실패입니다.
#[derive(Debug, Error)]
pub enum StoreError {
    /// JSON encode 실패입니다.
    #[error("JSON encode 실패: {0}")]
    Encode(#[from] serde_json::Error),
    /// 파일 작업 실패입니다.
    #[error("원자 파일 작업 실패: operation={operation}, path={path}, cause={source}")]
    Io {
        /// 실패한 작업입니다.
        operation: &'static str,
        /// 대상 경로입니다.
        path: String,
        /// 원본 오류입니다.
        source: std::io::Error,
    },
    /// 대상 파일에 parent directory가 없습니다.
    #[error("저장 경로에 parent directory가 없습니다: {0}")]
    MissingParent(String),
}

/// typed JSON을 last-known-good 파일로 원자 저장합니다.
#[derive(Debug, Clone)]
pub struct AtomicJsonStore<T> {
    path: PathBuf,
    marker: PhantomData<T>,
}

impl<T> AtomicJsonStore<T> {
    /// 최종 JSON 경로를 고정합니다.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            marker: PhantomData,
        }
    }

    /// 최종 파일 경로입니다.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl<T> AtomicJsonStore<T>
where
    T: Serialize + DeserializeOwned,
{
    /// JSON을 같은 directory 임시 파일에 fsync한 뒤 rename합니다.
    ///
    /// # Errors
    ///
    /// encode, directory, 파일 쓰기, fsync 또는 rename 실패를 반환합니다.
    pub fn write(&self, value: &T) -> Result<(), StoreError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| StoreError::MissingParent(self.path.display().to_string()))?;
        fs::create_dir_all(parent).map_err(|source| io_error("create_dir_all", parent, source))?;
        let bytes = serde_json::to_vec_pretty(value)?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp = parent.join(format!(".vps-guard-{}-{sequence}.tmp", std::process::id()));
        let write_result = write_temp(&temp, &bytes).and_then(|()| {
            fs::rename(&temp, &self.path)
                .map_err(|source| io_error("rename", &self.path, source))?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|source| io_error("sync_parent", parent, source))
        });
        if write_result.is_err() {
            let _ignored = fs::remove_file(&temp);
        }
        write_result
    }

    /// 마지막 정상 JSON을 읽습니다.
    ///
    /// # Errors
    ///
    /// 파일 읽기 또는 JSON decode 실패를 반환합니다.
    pub fn read(&self) -> Result<T, StoreError> {
        let bytes = fs::read(&self.path).map_err(|source| io_error("read", &self.path, source))?;
        serde_json::from_slice(&bytes).map_err(StoreError::Encode)
    }
}

fn write_temp(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|source| io_error("create_temp", path, source))?;
    file.write_all(bytes)
        .map_err(|source| io_error("write_temp", path, source))?;
    file.sync_all()
        .map_err(|source| io_error("sync_temp", path, source))
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> StoreError {
    StoreError::Io {
        operation,
        path: path.display().to_string(),
        source,
    }
}

#[cfg(test)]
#[path = "atomic_store/tests.rs"]
mod tests;
