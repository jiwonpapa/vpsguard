//! Standalone 설치에서 VPSGuard 소유 UFW rule만 안전하게 변경합니다.

#[cfg(test)]
use std::collections::VecDeque;

use guard_core::config::FirewallMode;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::command::{
    CommandAudit, CommandError, CommandOutput, OwnedProgram, SystemCommandRunner,
};

const COMMENT_PREFIX: &str = "vps-guard:";

/// UFW rule 동작입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UfwAction {
    /// 일치하는 inbound traffic을 허용합니다.
    Allow,
    /// 일치하는 inbound traffic을 거부합니다.
    Deny,
}

impl UfwAction {
    const fn as_arg(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// UFW transport protocol입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UfwProtocol {
    /// TCP입니다.
    Tcp,
    /// UDP입니다.
    Udp,
    /// protocol을 제한하지 않습니다.
    Any,
}

impl UfwProtocol {
    const fn as_arg(self) -> Option<&'static str> {
        match self {
            Self::Tcp => Some("tcp"),
            Self::Udp => Some("udp"),
            Self::Any => None,
        }
    }
}

/// VPSGuard가 소유하는 단일 inbound UFW rule입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UfwRule {
    /// 주석 namespace에 쓰는 안정된 rule ID입니다.
    pub id: String,
    /// 허용 또는 거부입니다.
    pub action: UfwAction,
    /// source IP 또는 CIDR입니다. 없으면 모든 source입니다.
    pub source: Option<IpNet>,
    /// destination port입니다. source deny에는 생략할 수 있습니다.
    pub destination_port: Option<u16>,
    /// transport protocol입니다.
    pub protocol: UfwProtocol,
}

impl UfwRule {
    /// 사용자 입력을 command argv로 만들기 전에 안전 계약을 검증합니다.
    ///
    /// # Errors
    ///
    /// 잘못된 ID, 0번 port, SSH port 거부 또는 무제한 catch-all 거부를 반환합니다.
    pub fn validate(&self, ssh_port: u16) -> Result<(), UfwError> {
        if self.id.is_empty()
            || self.id.len() > 48
            || !self
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(UfwError::InvalidRule(
                "rule ID는 48자 이하 영문자·숫자·밑줄·하이픈이어야 합니다".to_owned(),
            ));
        }
        if self.destination_port == Some(0) {
            return Err(UfwError::InvalidRule(
                "0번 port는 사용할 수 없습니다".to_owned(),
            ));
        }
        if self.action == UfwAction::Deny
            && (self.destination_port == Some(ssh_port)
                || (self.source.is_none() && self.destination_port.is_none()))
        {
            return Err(UfwError::SshInvariant);
        }
        if self.destination_port.is_none() && self.protocol != UfwProtocol::Any {
            return Err(UfwError::InvalidRule(
                "port 없는 source rule은 protocol=any여야 합니다".to_owned(),
            ));
        }
        Ok(())
    }

    fn comment(&self) -> String {
        format!("{COMMENT_PREFIX}{}", self.id)
    }

    fn add_arguments(&self, dry_run: bool) -> Vec<String> {
        let mut arguments = Vec::new();
        if dry_run {
            arguments.push("--dry-run".to_owned());
        }
        arguments.extend([self.action.as_arg().to_owned(), "in".to_owned()]);
        if let Some(source) = self.source {
            arguments.extend(["from".to_owned(), source.to_string()]);
        }
        if self.destination_port.is_some() {
            arguments.extend(["to".to_owned(), "any".to_owned()]);
        }
        if let Some(port) = self.destination_port {
            arguments.extend(["port".to_owned(), port.to_string()]);
        }
        if let Some(protocol) = self.protocol.as_arg() {
            arguments.extend(["proto".to_owned(), protocol.to_owned()]);
        }
        arguments.extend(["comment".to_owned(), self.comment()]);
        arguments
    }
}

/// UFW rule 변경 종류입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UfwMutation {
    /// 새 VPSGuard rule을 추가합니다.
    Add {
        /// 추가할 typed rule입니다.
        rule: UfwRule,
    },
    /// 정확한 VPSGuard rule ID 하나를 제거합니다.
    Remove {
        /// 삭제와 rollback에 사용할 typed rule입니다.
        rule: UfwRule,
    },
}

impl UfwMutation {
    fn rule(&self) -> &UfwRule {
        match self {
            Self::Add { rule } | Self::Remove { rule } => rule,
        }
    }
}

/// `ufw status numbered`에서 관측한 VPSGuard 소유 rule입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UfwObservedRule {
    /// 현재 UFW 번호입니다.
    pub number: u32,
    /// VPSGuard rule ID입니다.
    pub id: String,
    /// 민감값 없는 bounded 표시 행입니다.
    pub summary: String,
}

/// UFW read-back snapshot입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UfwSnapshot {
    /// UFW 활성 여부입니다.
    pub active: bool,
    /// 전체 status의 SHA-256입니다.
    pub fingerprint: String,
    /// VPSGuard 소유 rule입니다.
    pub owned_rules: Vec<UfwObservedRule>,
    /// 번호를 제거한 사용자/JW-agent 소유 rule입니다.
    pub foreign_rules: Vec<String>,
}

impl UfwSnapshot {
    fn parse(output: &str) -> Self {
        let active = output.lines().any(|line| {
            line.trim()
                .strip_prefix("Status:")
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("active"))
        });
        let fingerprint = hex_digest(output.as_bytes());
        let mut owned_rules = Vec::new();
        let mut foreign_rules = Vec::new();
        for line in output
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with('['))
        {
            let Some((number, body)) = split_numbered_rule(line) else {
                continue;
            };
            if let Some(id) = parse_owned_comment(body) {
                owned_rules.push(UfwObservedRule {
                    number,
                    id,
                    summary: bounded_summary(body),
                });
            } else {
                foreign_rules.push(bounded_summary(body));
            }
        }
        Self {
            active,
            fingerprint,
            owned_rules,
            foreign_rules,
        }
    }
}

/// 승인 전 UFW 변경 plan입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UfwPlan {
    /// apply 직전 일치해야 할 snapshot hash입니다.
    pub before_fingerprint: String,
    /// 단일 원자적 논리 변경입니다.
    pub mutation: UfwMutation,
    /// apply 후에도 보존할 관리 SSH port입니다.
    pub ssh_port: u16,
}

/// UFW plan·실행·검증 실패입니다.
#[derive(Debug, Error)]
pub enum UfwError {
    /// standalone 소유권이 아닙니다.
    #[error("standalone_ufw mode에서만 UFW를 변경할 수 있습니다")]
    OwnershipDenied,
    /// UFW가 비활성 상태입니다.
    #[error("UFW가 비활성 상태이므로 VPSGuard가 자동 활성화하지 않습니다")]
    Inactive,
    /// rule이 안전 계약을 위반했습니다.
    #[error("잘못된 UFW rule: {0}")]
    InvalidRule(String),
    /// SSH 접근을 위협하는 rule입니다.
    #[error("관리 SSH port를 차단하거나 무제한 deny할 수 없습니다")]
    SshInvariant,
    /// 같은 ID가 이미 존재하거나 제거 대상이 유일하지 않습니다.
    #[error("UFW rule ID 충돌 또는 부재: {0}")]
    RuleIdentity(String),
    /// plan 이후 UFW가 바뀌었습니다.
    #[error("UFW 상태가 plan 이후 변경되어 apply를 중단했습니다")]
    SnapshotChanged,
    /// read-back 또는 foreign rule 보존 검증이 실패했습니다.
    #[error("UFW 적용 후 read-back 검증이 실패했습니다")]
    VerificationFailed,
    /// rollback도 실패했습니다.
    #[error("UFW 적용 검증과 rollback이 모두 실패했습니다")]
    RollbackFailed,
    /// allowlisted command 실행 실패입니다.
    #[error(transparent)]
    Command(#[from] CommandError),
}

/// UFW command 실행 경계입니다.
pub trait UfwExecutor: Send + Sync {
    /// allowlisted UFW argv를 실행합니다.
    ///
    /// # Errors
    ///
    /// process 실행 또는 UFW 오류를 반환합니다.
    fn run(&self, arguments: &[String]) -> Result<CommandOutput, CommandError>;
}

/// 운영 `/usr/sbin/ufw` 실행기입니다.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemUfwExecutor {
    runner: SystemCommandRunner,
}

impl UfwExecutor for SystemUfwExecutor {
    fn run(&self, arguments: &[String]) -> Result<CommandOutput, CommandError> {
        self.runner.run(OwnedProgram::Ufw, arguments, None, &[])
    }
}

/// plan·dry-run·apply·read-back·rollback을 조율합니다.
pub struct UfwController<E = SystemUfwExecutor> {
    executor: E,
}

impl Default for UfwController<SystemUfwExecutor> {
    fn default() -> Self {
        Self {
            executor: SystemUfwExecutor::default(),
        }
    }
}

impl<E: UfwExecutor> UfwController<E> {
    /// 주입된 executor로 controller를 만듭니다.
    pub const fn new(executor: E) -> Self {
        Self { executor }
    }

    /// UFW 상태와 소유 rule을 읽습니다.
    ///
    /// # Errors
    ///
    /// `ufw status numbered` 실행 실패를 반환합니다.
    pub fn snapshot(&self) -> Result<(UfwSnapshot, CommandAudit), UfwError> {
        let output = self
            .executor
            .run(&["status".to_owned(), "numbered".to_owned()])?;
        Ok((UfwSnapshot::parse(&output.stdout), output.audit))
    }

    /// 현재 snapshot에 묶인 안전한 단일 변경 plan을 만듭니다.
    ///
    /// # Errors
    ///
    /// 소유권, 비활성 UFW, rule 안전성 또는 ID 충돌을 반환합니다.
    pub fn plan(
        mode: FirewallMode,
        snapshot: &UfwSnapshot,
        mutation: UfwMutation,
        ssh_port: u16,
    ) -> Result<UfwPlan, UfwError> {
        if mode != FirewallMode::StandaloneUfw {
            return Err(UfwError::OwnershipDenied);
        }
        if !snapshot.active {
            return Err(UfwError::Inactive);
        }
        mutation.rule().validate(ssh_port)?;
        let matches = snapshot
            .owned_rules
            .iter()
            .filter(|observed| observed.id == mutation.rule().id)
            .count();
        match mutation {
            UfwMutation::Add { .. } if matches != 0 => {
                return Err(UfwError::RuleIdentity("이미 존재하는 ID".to_owned()));
            }
            UfwMutation::Remove { .. } if matches != 1 => {
                return Err(UfwError::RuleIdentity(
                    "제거 대상은 정확히 하나여야 함".to_owned(),
                ));
            }
            UfwMutation::Add { .. } | UfwMutation::Remove { .. } => {}
        }
        Ok(UfwPlan {
            before_fingerprint: snapshot.fingerprint.clone(),
            mutation,
            ssh_port,
        })
    }

    /// add plan의 UFW parser dry-run을 실행합니다. remove는 snapshot 검증으로 대체합니다.
    ///
    /// # Errors
    ///
    /// command dry-run 실패를 반환합니다.
    pub fn dry_run(&self, plan: &UfwPlan) -> Result<Vec<CommandAudit>, UfwError> {
        match &plan.mutation {
            UfwMutation::Add { rule } => {
                Ok(vec![self.executor.run(&rule.add_arguments(true))?.audit])
            }
            UfwMutation::Remove { .. } => Ok(Vec::new()),
        }
    }

    /// snapshot 일치 확인 뒤 적용하고 foreign rule과 목표 상태를 read-back합니다.
    ///
    /// 검증 실패 시 현재 변경만 원복합니다.
    ///
    /// # Errors
    ///
    /// snapshot drift, command, 검증 또는 rollback 실패를 반환합니다.
    pub fn apply(&self, plan: &UfwPlan) -> Result<Vec<CommandAudit>, UfwError> {
        let (before, before_audit) = self.snapshot()?;
        if before.fingerprint != plan.before_fingerprint {
            return Err(UfwError::SnapshotChanged);
        }
        let mut audits = vec![before_audit];
        audits.extend(self.dry_run(plan)?);
        let mutation_audit = match &plan.mutation {
            UfwMutation::Add { rule } => self.executor.run(&rule.add_arguments(false))?.audit,
            UfwMutation::Remove { rule } => {
                let number = unique_rule_number(&before, &rule.id)?;
                self.executor
                    .run(&[
                        "--force".to_owned(),
                        "delete".to_owned(),
                        number.to_string(),
                    ])?
                    .audit
            }
        };
        audits.push(mutation_audit);
        let (after, after_audit) = self.snapshot()?;
        audits.push(after_audit);
        if verifies_transition(&before, &after, plan) {
            return Ok(audits);
        }
        let rollback_result = self.rollback_transition(&before, &after, plan);
        match rollback_result {
            Ok(mut rollback_audits) => {
                audits.append(&mut rollback_audits);
                Err(UfwError::VerificationFailed)
            }
            Err(_) => Err(UfwError::RollbackFailed),
        }
    }

    fn rollback_transition(
        &self,
        before: &UfwSnapshot,
        current: &UfwSnapshot,
        plan: &UfwPlan,
    ) -> Result<Vec<CommandAudit>, UfwError> {
        let mut audits = Vec::new();
        match &plan.mutation {
            UfwMutation::Add { rule } => {
                let number = unique_rule_number(current, &rule.id)?;
                audits.push(
                    self.executor
                        .run(&[
                            "--force".to_owned(),
                            "delete".to_owned(),
                            number.to_string(),
                        ])?
                        .audit,
                );
            }
            UfwMutation::Remove { rule } => {
                audits.push(self.executor.run(&rule.add_arguments(false))?.audit);
            }
        }
        let (restored, readback) = self.snapshot()?;
        audits.push(readback);
        if restored.active == before.active
            && restored.foreign_rules == before.foreign_rules
            && owned_rule_ids(&restored) == owned_rule_ids(before)
        {
            Ok(audits)
        } else {
            Err(UfwError::RollbackFailed)
        }
    }
}

fn owned_rule_ids(snapshot: &UfwSnapshot) -> Vec<&str> {
    let mut ids = snapshot
        .owned_rules
        .iter()
        .map(|rule| rule.id.as_str())
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids
}

/// Root helper가 받은 UFW add argv가 typed rule 생성기와 같은 제한 문법인지 검증합니다.
///
/// # Errors
///
/// 알 수 없는 token, 잘못된 source·port·ID 또는 SSH 보호 불변조건 위반을 반환합니다.
pub fn validate_ufw_add_arguments(arguments: &[String], ssh_port: u16) -> Result<(), UfwError> {
    let mut index = 0;
    if arguments
        .get(index)
        .is_some_and(|value| value == "--dry-run")
    {
        index += 1;
    }
    let action = match arguments.get(index).map(String::as_str) {
        Some("allow") => UfwAction::Allow,
        Some("deny") => UfwAction::Deny,
        _ => {
            return Err(UfwError::InvalidRule("허용되지 않은 action".to_owned()));
        }
    };
    index += 1;
    take_exact(arguments, &mut index, "in")?;

    let source =
        if arguments.get(index).is_some_and(|value| value == "from") {
            index += 1;
            let value = arguments
                .get(index)
                .ok_or_else(|| UfwError::InvalidRule("source가 없습니다".to_owned()))?;
            index += 1;
            Some(value.parse::<IpNet>().map_err(|_| {
                UfwError::InvalidRule("source IP/CIDR가 올바르지 않습니다".to_owned())
            })?)
        } else {
            None
        };

    if arguments.get(index).is_some_and(|value| value == "to") {
        index += 1;
        take_exact(arguments, &mut index, "any")?;
    }
    let destination_port = if arguments.get(index).is_some_and(|value| value == "port") {
        index += 1;
        let port = arguments
            .get(index)
            .ok_or_else(|| UfwError::InvalidRule("port가 없습니다".to_owned()))?
            .parse::<u16>()
            .map_err(|_| UfwError::InvalidRule("port가 올바르지 않습니다".to_owned()))?;
        index += 1;
        Some(port)
    } else {
        None
    };
    let protocol = if arguments.get(index).is_some_and(|value| value == "proto") {
        index += 1;
        let protocol = match arguments.get(index).map(String::as_str) {
            Some("tcp") => UfwProtocol::Tcp,
            Some("udp") => UfwProtocol::Udp,
            _ => {
                return Err(UfwError::InvalidRule(
                    "protocol이 올바르지 않습니다".to_owned(),
                ));
            }
        };
        index += 1;
        protocol
    } else {
        UfwProtocol::Any
    };
    take_exact(arguments, &mut index, "comment")?;
    let comment = arguments
        .get(index)
        .ok_or_else(|| UfwError::InvalidRule("소유권 comment가 없습니다".to_owned()))?;
    index += 1;
    if index != arguments.len() {
        return Err(UfwError::InvalidRule("알 수 없는 UFW token".to_owned()));
    }
    let id = comment
        .strip_prefix(COMMENT_PREFIX)
        .ok_or_else(|| UfwError::InvalidRule("VPSGuard 소유권 comment가 필요합니다".to_owned()))?
        .to_owned();
    UfwRule {
        id,
        action,
        source,
        destination_port,
        protocol,
    }
    .validate(ssh_port)
}

fn take_exact(arguments: &[String], index: &mut usize, expected: &str) -> Result<(), UfwError> {
    if arguments.get(*index).is_some_and(|value| value == expected) {
        *index += 1;
        Ok(())
    } else {
        Err(UfwError::InvalidRule(format!(
            "UFW token `{expected}`가 필요합니다"
        )))
    }
}

fn unique_rule_number(snapshot: &UfwSnapshot, id: &str) -> Result<u32, UfwError> {
    let matches = snapshot
        .owned_rules
        .iter()
        .filter(|rule| rule.id == id)
        .map(|rule| rule.number)
        .collect::<Vec<_>>();
    if let [number] = matches.as_slice() {
        Ok(*number)
    } else {
        Err(UfwError::RuleIdentity(id.to_owned()))
    }
}

fn verifies_transition(before: &UfwSnapshot, after: &UfwSnapshot, plan: &UfwPlan) -> bool {
    if !after.active || before.foreign_rules != after.foreign_rules {
        return false;
    }
    let count = after
        .owned_rules
        .iter()
        .filter(|rule| rule.id == plan.mutation.rule().id)
        .count();
    match plan.mutation {
        UfwMutation::Add { .. } => count == 1,
        UfwMutation::Remove { .. } => count == 0,
    }
}

fn split_numbered_rule(line: &str) -> Option<(u32, &str)> {
    let close = line.find(']')?;
    let number = line.get(1..close)?.trim().parse().ok()?;
    Some((number, line.get(close + 1..)?.trim()))
}

fn parse_owned_comment(body: &str) -> Option<String> {
    let (_, comment) = body.rsplit_once('#')?;
    let id = comment.trim().strip_prefix(COMMENT_PREFIX)?.trim();
    if id.is_empty()
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return None;
    }
    Some(id.to_owned())
}

fn bounded_summary(value: &str) -> String {
    value.chars().take(512).collect()
}

fn hex_digest(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    const ACTIVE: &str = "Status: active\n\n     To                         Action      From\n     --                         ------      ----\n[ 1] 22/tcp                     ALLOW IN    Anywhere\n";

    #[derive(Default)]
    struct FakeExecutor {
        outputs: Mutex<VecDeque<Result<String, CommandError>>>,
        arguments: Mutex<Vec<Vec<String>>>,
    }

    impl FakeExecutor {
        fn with_outputs(outputs: &[&str]) -> Self {
            Self {
                outputs: Mutex::new(
                    outputs
                        .iter()
                        .map(|value| Ok((*value).to_owned()))
                        .collect(),
                ),
                arguments: Mutex::new(Vec::new()),
            }
        }
    }

    impl UfwExecutor for FakeExecutor {
        fn run(&self, arguments: &[String]) -> Result<CommandOutput, CommandError> {
            self.arguments
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(arguments.to_vec());
            let stdout = self
                .outputs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front()
                .unwrap_or_else(|| Ok(String::new()))?;
            Ok(CommandOutput {
                stdout,
                audit: CommandAudit {
                    occurred_at: "2026-07-22T00:00:00Z".to_owned(),
                    program: "/usr/sbin/ufw".to_owned(),
                    argv: arguments.to_vec(),
                    exit_code: Some(0),
                    duration_ms: 1,
                },
            })
        }
    }

    fn web_rule() -> UfwRule {
        UfwRule {
            id: "public_https".to_owned(),
            action: UfwAction::Allow,
            source: None,
            destination_port: Some(443),
            protocol: UfwProtocol::Tcp,
        }
    }

    #[test]
    fn delegated_mode_and_ssh_deny_fail_closed() {
        let snapshot = UfwSnapshot::parse(ACTIVE);
        assert!(matches!(
            UfwController::<FakeExecutor>::plan(
                FirewallMode::JwAgentDelegated,
                &snapshot,
                UfwMutation::Add { rule: web_rule() },
                22,
            ),
            Err(UfwError::OwnershipDenied)
        ));
        let mut deny_ssh = web_rule();
        deny_ssh.action = UfwAction::Deny;
        deny_ssh.destination_port = Some(22);
        assert!(matches!(
            UfwController::<FakeExecutor>::plan(
                FirewallMode::StandaloneUfw,
                &snapshot,
                UfwMutation::Add { rule: deny_ssh },
                22,
            ),
            Err(UfwError::SshInvariant)
        ));
    }

    #[test]
    fn add_runs_dry_run_and_preserves_foreign_rules() -> Result<(), Box<dyn std::error::Error>> {
        let after = format!(
            "{ACTIVE}[ 2] 443/tcp                    ALLOW IN    Anywhere                   # vps-guard:public_https\n"
        );
        let executor = FakeExecutor::with_outputs(&[ACTIVE, "dry-run ok", "", &after]);
        let controller = UfwController::new(executor);
        let before = UfwSnapshot::parse(ACTIVE);
        let plan = UfwController::<FakeExecutor>::plan(
            FirewallMode::StandaloneUfw,
            &before,
            UfwMutation::Add { rule: web_rule() },
            22,
        )?;
        let audits = controller.apply(&plan)?;
        assert_eq!(audits.len(), 4);
        let arguments = controller
            .executor
            .arguments
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(arguments[1].first().map(String::as_str), Some("--dry-run"));
        assert_eq!(
            arguments[2].last().map(String::as_str),
            Some("vps-guard:public_https")
        );
        Ok(())
    }

    #[test]
    fn parser_exposes_only_owned_comment_namespace() {
        let output = format!(
            "{ACTIVE}[ 2] 443/tcp ALLOW IN Anywhere # vps-guard:public_https\n[ 3] 3306/tcp DENY IN Anywhere # user-rule\n"
        );
        let snapshot = UfwSnapshot::parse(&output);
        assert!(snapshot.active);
        assert_eq!(snapshot.owned_rules.len(), 1);
        assert_eq!(snapshot.owned_rules[0].id, "public_https");
        assert_eq!(snapshot.foreign_rules.len(), 2);
    }

    #[test]
    fn privileged_argument_validator_accepts_generated_rule_only() {
        let arguments = web_rule().add_arguments(true);
        assert!(validate_ufw_add_arguments(&arguments, 22).is_ok());
        let mut injected = arguments;
        injected.push("enable".to_owned());
        assert!(validate_ufw_add_arguments(&injected, 22).is_err());
    }

    #[test]
    fn failed_readback_rolls_back_to_the_pre_change_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let invalid_after = format!(
            "{ACTIVE}[ 2] 443/tcp ALLOW IN Anywhere # vps-guard:public_https\n[ 3] 8080/tcp ALLOW IN Anywhere # foreign-change\n"
        );
        let executor =
            FakeExecutor::with_outputs(&[ACTIVE, "dry-run ok", "", &invalid_after, "", ACTIVE]);
        let controller = UfwController::new(executor);
        let before = UfwSnapshot::parse(ACTIVE);
        let plan = UfwController::<FakeExecutor>::plan(
            FirewallMode::StandaloneUfw,
            &before,
            UfwMutation::Add { rule: web_rule() },
            22,
        )?;

        assert!(matches!(
            controller.apply(&plan),
            Err(UfwError::VerificationFailed)
        ));
        Ok(())
    }
}
