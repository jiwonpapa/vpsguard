//! Policy runtime 회귀 테스트입니다.

use std::fs;
use std::net::{IpAddr, Ipv4Addr};

use guard_core::policy::{ClientRule, RouteRule, StaticLimits};
use guard_core::{Decision, GuardMode, PolicySnapshot};
use tempfile::tempdir;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use super::PolicyRuntime;

fn policy(version: u64, now: OffsetDateTime) -> Result<PolicySnapshot, Box<dyn std::error::Error>> {
    Ok(PolicySnapshot {
        schema_version: 1,
        policy_version: version,
        generated_at: now.format(&Rfc3339).unwrap_or_default(),
        expires_at: (now + Duration::hours(1))
            .format(&Rfc3339)
            .unwrap_or_default(),
        mode: GuardMode::LocalGuard,
        route_rules: vec![RouteRule {
            route_class: "strict".to_owned(),
            requests_per_minute: 7,
        }],
        client_rules: vec![ClientRule {
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            action: Decision::Deny,
            expires_at: (now + Duration::minutes(10))
                .format(&Rfc3339)
                .unwrap_or_default(),
            reason_codes: Vec::new(),
        }],
        static_limits: StaticLimits {
            max_body_bytes: 1024,
            max_tracked_clients: 100,
        },
        content_sha256: String::new(),
    }
    .seal()?)
}

#[test]
fn invalid_new_policy_keeps_last_known_good() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let path = directory.path().join("policy.json");
    let runtime = PolicyRuntime::new(path.clone());
    let now = OffsetDateTime::now_utc();
    let valid = serde_json::to_vec(&policy(1, now)?)?;
    fs::write(&path, valid)?;
    assert_eq!(runtime.reload_at(now).ok(), Some(true));

    fs::write(&path, b"{broken")?;
    assert!(runtime.reload_at(now).is_err());
    assert_eq!(runtime.version(), 1);
    Ok(())
}

#[test]
fn applies_client_and_route_rules_without_file_access() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let path = directory.path().join("policy.json");
    let runtime = PolicyRuntime::new(path.clone());
    let now = OffsetDateTime::now_utc();
    fs::write(&path, serde_json::to_vec(&policy(4, now)?)?)?;
    assert_eq!(runtime.reload_at(now).ok(), Some(true));
    fs::remove_file(path)?;

    let decision = runtime.decision_at(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), "strict", now);
    assert_eq!(decision.action, Some(Decision::Deny));
    assert_eq!(decision.requests_per_minute, Some(7));
    assert_eq!(decision.policy_version, 4);
    Ok(())
}
