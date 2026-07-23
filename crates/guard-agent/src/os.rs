//! Linux `/proc` 기반 읽기 전용 OS collector입니다.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// `/proc`에서 수집한 bounded OS snapshot입니다.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsSnapshot {
    /// 직전 `/proc/stat` 표본과 비교한 host CPU 사용률입니다.
    ///
    /// 첫 표본이거나 kernel counter가 역행하면 `None`입니다.
    pub cpu_usage_percent: Option<u8>,
    /// kernel이 보고한 logical CPU 수입니다.
    pub logical_cpu_count: u16,
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

/// 연속 CPU 사용률 계산에 필요한 누적 kernel counter입니다.
///
/// 값 자체는 외부 계약이 아니며 다음 수집 호출에만 전달합니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuTimes {
    total: u64,
    idle: u64,
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
    collect_with_previous(proc_root, None).map(|(snapshot, _)| snapshot)
}

/// 직전 CPU counter와 비교해 OS snapshot과 다음 counter를 함께 수집합니다.
///
/// 실제 Linux에서는 `/proc`를 전달하고 첫 호출에는 `None`, 이후 호출에는 반환된
/// [`CpuTimes`]를 전달합니다.
///
/// # Errors
///
/// 파일 읽기 또는 숫자 해석 실패를 반환합니다.
pub fn collect_with_previous(
    proc_root: &Path,
    previous_cpu: Option<CpuTimes>,
) -> Result<(OsSnapshot, CpuTimes), OsCollectorError> {
    let load = read(proc_root, "loadavg")?;
    let memory = read(proc_root, "meminfo")?;
    let uptime = read(proc_root, "uptime")?;
    let stat = read(proc_root, "stat")?;
    let current_cpu = parse_cpu_times(&stat)?;
    Ok((
        OsSnapshot {
            cpu_usage_percent: previous_cpu
                .and_then(|previous| cpu_usage_percent(previous, current_cpu)),
            logical_cpu_count: logical_cpu_count(&stat)?,
            load_1m: first_number(&load, "load_1m")?,
            memory_total_bytes: kib_value(&memory, "MemTotal")?,
            memory_available_bytes: kib_value(&memory, "MemAvailable")?,
            swap_total_bytes: kib_value(&memory, "SwapTotal")?,
            swap_free_bytes: kib_value(&memory, "SwapFree")?,
            uptime_seconds: first_number::<f64>(&uptime, "uptime")? as u64,
        },
        current_cpu,
    ))
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

fn parse_cpu_times(raw: &str) -> Result<CpuTimes, OsCollectorError> {
    let line = raw
        .lines()
        .find(|line| line.starts_with("cpu "))
        .ok_or(OsCollectorError::Parse { field: "cpu" })?;
    let values = line
        .split_whitespace()
        .skip(1)
        .take(8)
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| OsCollectorError::Parse { field: "cpu" })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if values.len() < 4 {
        return Err(OsCollectorError::Parse { field: "cpu" });
    }
    let total = values.iter().copied().fold(0_u64, u64::saturating_add);
    let idle = values[3].saturating_add(values.get(4).copied().unwrap_or_default());
    Ok(CpuTimes { total, idle })
}

fn logical_cpu_count(raw: &str) -> Result<u16, OsCollectorError> {
    let count = raw
        .lines()
        .filter(|line| {
            line.strip_prefix("cpu")
                .and_then(|suffix| suffix.chars().next())
                .is_some_and(|character| character.is_ascii_digit())
        })
        .count();
    if count == 0 {
        return Err(OsCollectorError::Parse {
            field: "logical_cpu_count",
        });
    }
    u16::try_from(count).map_err(|_| OsCollectorError::Parse {
        field: "logical_cpu_count",
    })
}

fn cpu_usage_percent(previous: CpuTimes, current: CpuTimes) -> Option<u8> {
    let total_delta = current.total.checked_sub(previous.total)?;
    let idle_delta = current.idle.checked_sub(previous.idle)?;
    if total_delta == 0 {
        return None;
    }
    let busy_delta = total_delta.saturating_sub(idle_delta);
    u8::try_from(busy_delta.saturating_mul(100) / total_delta)
        .ok()
        .map(|percent| percent.min(100))
}

#[cfg(test)]
#[path = "os/tests.rs"]
mod tests;
