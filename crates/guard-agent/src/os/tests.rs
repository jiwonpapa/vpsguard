//! OS collector parser와 CPU delta 회귀 테스트입니다.

use super::{cpu_usage_percent, first_number, kib_value, logical_cpu_count, parse_cpu_times};

#[test]
fn parses_meminfo_kib_as_bytes() {
    let fixture = "MemTotal:       2048000 kB\nMemAvailable:   1024000 kB\n";
    assert_eq!(kib_value(fixture, "MemTotal").ok(), Some(2_097_152_000));
}

#[test]
fn parses_load_average() {
    assert_eq!(
        first_number::<f64>("0.25 0.20 0.10 1/100 1", "load").ok(),
        Some(0.25)
    );
}

#[test]
fn derives_cpu_usage_from_proc_stat_delta() -> Result<(), Box<dyn std::error::Error>> {
    let previous = parse_cpu_times("cpu 100 0 50 850 0 0 0 0 0 0\n")?;
    let current = parse_cpu_times("cpu 150 0 70 880 0 0 0 0 0 0\n")?;

    assert_eq!(cpu_usage_percent(previous, current), Some(70));
    Ok(())
}

#[test]
fn counts_only_logical_cpu_rows() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = "\
cpu  100 0 50 850 0 0 0 0 0 0
cpu0 50 0 25 425 0 0 0 0 0 0
cpu1 50 0 25 425 0 0 0 0 0 0
intr 123
";

    assert_eq!(logical_cpu_count(fixture)?, 2);
    Ok(())
}
