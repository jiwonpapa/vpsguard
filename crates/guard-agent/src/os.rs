//! Linux `/proc` 기반 읽기 전용 OS collector입니다.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// `/proc`에서 수집한 bounded OS snapshot입니다.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsSnapshot {
    /// 1분 load average입니다.
    pub load_1m: f64,
    /// 전체 memory bytes입니다.
    pub memory_total_bytes: u64,
    /// 즉시 사용 가능한 memory bytes입니다.
    pub memory_available_bytes: u64,
    /// 전체 swap bytes입니다.
    pub swap_total_bytes: u64,
    /// 남은 swap bytes입니다.
    pub swap_free_bytes: u64,
    /// system uptime 초입니다.
    pub uptime_seconds: u64,
}

/// OS collector 실패입니다.
#[derive(Debug, Error)]
pub enum OsCollectorError {
    /// `/proc` 파일을 읽지 못했습니다.
    #[error("OS collector 파일 읽기 실패: path={path}, cause={source}")]
    Read {
        /// 읽은 경로입니다.
        path: String,
        /// 원본 I/O 오류입니다.
        source: std::io::Error,
    },
    /// kernel 값을 해석하지 못했습니다.
    #[error("OS collector 값 해석 실패: field={field}")]
    Parse {
        /// 실패한 필드입니다.
        field: &'static str,
    },
}

/// 지정한 proc root에서 OS snapshot을 수집합니다.
///
/// 실제 Linux에서는 `/proc`를 전달하고 테스트에서는 fixture directory를 전달합니다.
///
/// # Errors
///
/// 파일 읽기 또는 숫자 해석 실패를 반환합니다.
pub fn collect(proc_root: &Path) -> Result<OsSnapshot, OsCollectorError> {
    let load = read(proc_root, "loadavg")?;
    let memory = read(proc_root, "meminfo")?;
    let uptime = read(proc_root, "uptime")?;
    Ok(OsSnapshot {
        load_1m: first_number(&load, "load_1m")?,
        memory_total_bytes: kib_value(&memory, "MemTotal")?,
        memory_available_bytes: kib_value(&memory, "MemAvailable")?,
        swap_total_bytes: kib_value(&memory, "SwapTotal")?,
        swap_free_bytes: kib_value(&memory, "SwapFree")?,
        uptime_seconds: first_number::<f64>(&uptime, "uptime")? as u64,
    })
}

fn read(root: &Path, name: &str) -> Result<String, OsCollectorError> {
    let path = root.join(name);
    fs::read_to_string(&path).map_err(|source| OsCollectorError::Read {
        path: path.display().to_string(),
        source,
    })
}

fn first_number<T>(raw: &str, field: &'static str) -> Result<T, OsCollectorError>
where
    T: std::str::FromStr,
{
    raw.split_whitespace()
        .next()
        .and_then(|value| value.parse::<T>().ok())
        .ok_or(OsCollectorError::Parse { field })
}

fn kib_value(raw: &str, key: &'static str) -> Result<u64, OsCollectorError> {
    raw.lines()
        .find_map(|line| {
            let (candidate, value) = line.split_once(':')?;
            (candidate == key).then_some(value)
        })
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
        .map(|kib| kib.saturating_mul(1024))
        .ok_or(OsCollectorError::Parse { field: key })
}

#[cfg(test)]
#[path = "os/tests.rs"]
mod tests;
