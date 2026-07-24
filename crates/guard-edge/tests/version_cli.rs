//! OPS-007 release artifact용 Edge binary metadata 실행 회귀입니다.

use std::process::Command;

#[test]
fn edge_binary_exposes_the_package_version() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_vps-guard-edge"))
        .arg("--version")
        .output()?;
    assert!(
        output.status.success(),
        "vps-guard-edge --version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("vps-guard-edge"));
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
    Ok(())
}
