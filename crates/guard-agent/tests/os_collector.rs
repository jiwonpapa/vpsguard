//! `/proc` fixture 기반 OS collector 통합 회귀 테스트입니다.

use std::fs;

use guard_agent::os::collect_with_previous;

#[test]
fn collects_cpu_load_memory_swap_and_uptime() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    fs::write(root.path().join("loadavg"), "1.50 0.50 0.25 1/100 1\n")?;
    fs::write(
        root.path().join("meminfo"),
        "\
MemTotal:       2048000 kB
MemAvailable:   1024000 kB
SwapTotal:       512000 kB
SwapFree:        256000 kB
",
    )?;
    fs::write(root.path().join("uptime"), "7200.00 1000.00\n")?;
    fs::write(
        root.path().join("stat"),
        "\
cpu  100 0 50 850 0 0 0 0 0 0
cpu0 50 0 25 425 0 0 0 0 0 0
cpu1 50 0 25 425 0 0 0 0 0 0
",
    )?;

    let (first, previous) = collect_with_previous(root.path(), None)?;
    assert_eq!(first.cpu_usage_percent, None);
    assert_eq!(first.logical_cpu_count, 2);
    assert_eq!(first.load_1m, 1.5);
    assert_eq!(first.memory_total_bytes, 2_097_152_000);
    assert_eq!(first.swap_free_bytes, 262_144_000);
    assert_eq!(first.uptime_seconds, 7_200);

    fs::write(
        root.path().join("stat"),
        "\
cpu  150 0 70 880 0 0 0 0 0 0
cpu0 75 0 35 440 0 0 0 0 0 0
cpu1 75 0 35 440 0 0 0 0 0 0
",
    )?;
    let (second, _) = collect_with_previous(root.path(), Some(previous))?;
    assert_eq!(second.cpu_usage_percent, Some(70));
    Ok(())
}
