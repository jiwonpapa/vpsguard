//! `vps-guard-control` 실행 진입점입니다.

fn main() {
    println!(
        "vps-guard-control scaffold embedded_agent={}",
        guard_control::embeds_agent()
    );
}
