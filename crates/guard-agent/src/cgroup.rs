//! allowlist된 systemd unit의 cgroup v2 resource 파일만 bounded read합니다.

use std::fs::File;
use std::io::Read;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_CGROUP_FILE_BYTES: u64 = 64 * 1_024;

/// 한 핵심 service의 cgroup v2 누적·현재 자원값입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CgroupSnapshot {
    /// 수집 시각 Unix milliseconds입니다.
    pub collected_at_unix_ms: u64,
    /// 누적 CPU 사용 microseconds입니다.
    pub cpu_usage_usec: u64,
    /// 누적 user CPU microseconds입니다.
    pub cpu_user_usec: u64,
    /// 누적 system CPU microseconds입니다.
    pub cpu_system_usec: u64,
    /// CPU throttle 발생 횟수입니다.
    pub cpu_nr_throttled: u64,
    /// 누적 throttle microseconds입니다.
    pub cpu_throttled_usec: u64,
    /// 직전 sample 대비 milli-percent입니다. 100,000은 한 core 100%입니다.
    pub cpu_usage_milli_percent: Option<u64>,
    /// 현재 memory bytes입니다.
    pub memory_current_bytes: u64,
    /// kernel이 제공하면 관측한 peak memory bytes입니다.
    pub memory_peak_bytes: Option<u64>,
    /// memory.high event 누계입니다.
    pub memory_high_events: u64,
    /// memory.max event 누계입니다.
    pub memory_max_events: u64,
    /// OOM event 누계입니다.
    pub oom_events: u64,
    /// OOM kill 누계입니다.
    pub oom_kill_events: u64,
    /// 누적 block I/O read bytes입니다.
    pub io_read_bytes: u64,
    /// 누적 block I/O write bytes입니다.
    pub io_write_bytes: u64,
    /// `cgroup.procs`의 process 수입니다.
    pub process_count: u64,
    /// pids controller가 집계한 task 수입니다.
    pub task_count: u64,
}

/// cgroup v2 파일 검증·읽기·parse 실패입니다.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CgroupError {
    /// root 밖으로 나갈 수 있는 경로입니다.
    #[error("cgroup relative path invalid")]
    InvalidPath,
    /// 필수 cgroup v2 파일을 읽지 못했습니다.
    #[error("cgroup file unavailable")]
    Unavailable,
    /// file size 또는 숫자 형식이 bounded 계약과 다릅니다.
    #[error("cgroup value invalid")]
    InvalidValue,
}

impl CgroupError {
    /// 경로를 포함하지 않는 안정 오류 코드입니다.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidPath => "CGROUP_PATH_INVALID",
            Self::Unavailable => "CGROUP_UNAVAILABLE",
            Self::InvalidValue => "CGROUP_VALUE_INVALID",
        }
    }
}

/// 명시된 cgroup root와 상대 경로에서 resource snapshot을 수집합니다.
///
/// # Errors
///
/// 상대 경로가 root를 벗어나거나 필수 cgroup v2 숫자를 읽지 못하면 거부합니다.
pub fn collect(
    root: &Path,
    relative_path: &Path,
    collected_at_unix_ms: u64,
) -> Result<CgroupSnapshot, CgroupError> {
    if !safe_relative_path(relative_path) {
        return Err(CgroupError::InvalidPath);
    }
    let canonical_root = root.canonicalize().map_err(|_| CgroupError::Unavailable)?;
    let directory = root
        .join(relative_path)
        .canonicalize()
        .map_err(|_| CgroupError::Unavailable)?;
    if !directory.starts_with(&canonical_root) {
        return Err(CgroupError::InvalidPath);
    }
    let cpu = read_bounded(&directory.join("cpu.stat"))?;
    let memory_events = read_bounded(&directory.join("memory.events"))?;
    let io = read_bounded(&directory.join("io.stat"))?;
    let processes = read_bounded(&directory.join("cgroup.procs"))?;
    Ok(CgroupSnapshot {
        collected_at_unix_ms,
        cpu_usage_usec: keyed_u64(&cpu, "usage_usec")?,
        cpu_user_usec: keyed_u64(&cpu, "user_usec")?,
        cpu_system_usec: keyed_u64(&cpu, "system_usec")?,
        cpu_nr_throttled: keyed_u64(&cpu, "nr_throttled")?,
        cpu_throttled_usec: keyed_u64(&cpu, "throttled_usec")?,
        cpu_usage_milli_percent: None,
        memory_current_bytes: single_u64(&read_bounded(&directory.join("memory.current"))?)?,
        memory_peak_bytes: optional_single_u64(&directory.join("memory.peak"))?,
        memory_high_events: keyed_u64(&memory_events, "high")?,
        memory_max_events: keyed_u64(&memory_events, "max")?,
        oom_events: keyed_u64(&memory_events, "oom")?,
        oom_kill_events: keyed_u64(&memory_events, "oom_kill")?,
        io_read_bytes: io_total(&io, "rbytes")?,
        io_write_bytes: io_total(&io, "wbytes")?,
        process_count: bounded_line_count(&processes)?,
        task_count: single_u64(&read_bounded(&directory.join("pids.current"))?)?,
    })
}

fn read_bounded(path: &Path) -> Result<String, CgroupError> {
    let file = File::open(path).map_err(|_| CgroupError::Unavailable)?;
    let mut bytes = Vec::with_capacity(1_024);
    file.take(MAX_CGROUP_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| CgroupError::Unavailable)?;
    if bytes.len() as u64 > MAX_CGROUP_FILE_BYTES {
        return Err(CgroupError::InvalidValue);
    }
    String::from_utf8(bytes).map_err(|_| CgroupError::InvalidValue)
}

fn optional_single_u64(path: &Path) -> Result<Option<u64>, CgroupError> {
    match read_bounded(path) {
        Ok(value) => single_u64(&value).map(Some),
        Err(CgroupError::Unavailable) => Ok(None),
        Err(error) => Err(error),
    }
}

fn single_u64(value: &str) -> Result<u64, CgroupError> {
    value
        .trim()
        .parse::<u64>()
        .map_err(|_| CgroupError::InvalidValue)
}

fn keyed_u64(value: &str, key: &str) -> Result<u64, CgroupError> {
    value
        .lines()
        .find_map(|line| {
            let (candidate, value) = line.split_once(' ')?;
            (candidate == key).then(|| value.trim().parse::<u64>().ok())?
        })
        .ok_or(CgroupError::InvalidValue)
}

fn io_total(value: &str, key: &str) -> Result<u64, CgroupError> {
    let mut found = false;
    let mut total = 0_u64;
    for line in value.lines() {
        for field in line.split_whitespace().skip(1) {
            let Some((candidate, raw)) = field.split_once('=') else {
                continue;
            };
            if candidate == key {
                total = total
                    .saturating_add(raw.parse::<u64>().map_err(|_| CgroupError::InvalidValue)?);
                found = true;
            }
        }
    }
    found.then_some(total).ok_or(CgroupError::InvalidValue)
}

fn bounded_line_count(value: &str) -> Result<u64, CgroupError> {
    let count = value.lines().filter(|line| !line.trim().is_empty()).count();
    (count <= 65_536)
        .then_some(count as u64)
        .ok_or(CgroupError::InvalidValue)
}

fn safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path.components().count() <= 8
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::collect;

    #[test]
    fn collects_only_the_allowlisted_cgroup_files() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let unit = root.path().join("system.slice/php8.3-fpm.service");
        fs::create_dir_all(&unit)?;
        fs::write(
            unit.join("cpu.stat"),
            "usage_usec 1000\nuser_usec 700\nsystem_usec 300\nnr_periods 9\nnr_throttled 2\nthrottled_usec 50\n",
        )?;
        fs::write(unit.join("memory.current"), "4096\n")?;
        fs::write(unit.join("memory.peak"), "8192\n")?;
        fs::write(
            unit.join("memory.events"),
            "low 0\nhigh 3\nmax 1\noom 1\noom_kill 0\n",
        )?;
        fs::write(
            unit.join("io.stat"),
            "8:0 rbytes=100 wbytes=200 rios=1 wios=2\n8:1 rbytes=30 wbytes=40 rios=1 wios=1\n",
        )?;
        fs::write(unit.join("cgroup.procs"), "100\n101\n")?;
        fs::write(unit.join("pids.current"), "5\n")?;

        let snapshot = collect(
            root.path(),
            Path::new("system.slice/php8.3-fpm.service"),
            1_000,
        )?;
        assert_eq!(snapshot.cpu_usage_usec, 1_000);
        assert_eq!(snapshot.memory_current_bytes, 4_096);
        assert_eq!(snapshot.io_read_bytes, 130);
        assert_eq!(snapshot.io_write_bytes, 240);
        assert_eq!(snapshot.process_count, 2);
        assert_eq!(snapshot.task_count, 5);
        assert!(collect(root.path(), Path::new("../other.service"), 1_000).is_err());
        Ok(())
    }
}
