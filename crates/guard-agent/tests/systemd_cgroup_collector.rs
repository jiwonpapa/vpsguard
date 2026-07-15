//! allowlist된 systemd unit cgroup만 읽는 경계를 검증합니다.

use std::fs;
use std::path::Path;

use guard_agent::cgroup;

#[test]
fn rejects_cgroup_escape_and_collects_the_named_unit() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let unit = root.path().join("system.slice/nginx.service");
    fs::create_dir_all(&unit)?;
    fs::write(
        unit.join("cpu.stat"),
        "usage_usec 1000\nuser_usec 700\nsystem_usec 300\nnr_throttled 0\nthrottled_usec 0\n",
    )?;
    fs::write(unit.join("memory.current"), "8192\n")?;
    fs::write(
        unit.join("memory.events"),
        "high 0\nmax 0\noom 0\noom_kill 0\n",
    )?;
    fs::write(unit.join("io.stat"), "8:0 rbytes=10 wbytes=20\n")?;
    fs::write(unit.join("cgroup.procs"), "100\n")?;
    fs::write(unit.join("pids.current"), "2\n")?;

    let snapshot = cgroup::collect(root.path(), Path::new("system.slice/nginx.service"), 1_000)?;
    assert_eq!(snapshot.memory_current_bytes, 8_192);
    assert!(cgroup::collect(root.path(), Path::new("../ssh.service"), 1_000).is_err());
    Ok(())
}
