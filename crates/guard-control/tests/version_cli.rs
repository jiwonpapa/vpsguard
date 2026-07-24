//! OPS-007 release artifact용 Control binary metadata 실행 회귀입니다.

use std::process::Command;

#[test]
fn control_and_privileged_binaries_expose_the_package_version()
-> Result<(), Box<dyn std::error::Error>> {
    for (name, binary) in [
        ("vps-guard-control", env!("CARGO_BIN_EXE_vps-guard-control")),
        (
            "vps-guard-privileged",
            env!("CARGO_BIN_EXE_vps-guard-privileged"),
        ),
    ] {
        let output = Command::new(binary).arg("--version").output()?;
        assert!(
            output.status.success(),
            "{name} --version failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout)?;
        assert!(stdout.contains(name));
        assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
    }
    Ok(())
}
