//! OS collector parser 회귀 테스트입니다.

use super::{first_number, kib_value};

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
