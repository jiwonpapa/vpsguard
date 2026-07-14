//! SSH rule을 건드리지 않는 VPSGuard-owned nftables origin protection table입니다.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::command::{CommandAudit, CommandError, OwnedProgram, SystemCommandRunner};

const TABLE_NAME: &str = "vps_guard";

/// Cloudflare CIDR allowlist 기반 origin 보호 plan입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OriginFirewallPlan {
    /// IPv4 Cloudflare network입니다.
    pub ipv4_networks: Vec<IpNet>,
    /// IPv6 Cloudflare network입니다.
    pub ipv6_networks: Vec<IpNet>,
}

impl OriginFirewallPlan {
    /// CIDR을 address family별로 분리하고 빈 allowlist를 거부합니다.
    ///
    /// # Errors
    ///
    /// IPv4 또는 IPv6 allowlist가 모두 비면 거부합니다.
    pub fn new(networks: Vec<IpNet>) -> Result<Self, NftablesError> {
        let (ipv4_networks, ipv6_networks): (Vec<IpNet>, Vec<IpNet>) = networks
            .into_iter()
            .partition(|network| matches!(network, IpNet::V4(_)));
        if ipv4_networks.is_empty() && ipv6_networks.is_empty() {
            return Err(NftablesError::EmptyAllowlist);
        }
        Ok(Self {
            ipv4_networks,
            ipv6_networks,
        })
    }

    /// 원본 web port만 보호하는 nft script를 생성합니다.
    #[must_use]
    pub fn render(&self) -> String {
        let mut sets = String::new();
        let mut rules = String::new();
        if !self.ipv4_networks.is_empty() {
            sets.push_str(&format!(
                "  set cloudflare_v4 {{ type ipv4_addr; flags interval; elements = {{ {} }} }}\n",
                join_networks(&self.ipv4_networks)
            ));
            rules.push_str(
                "    meta nfproto ipv4 tcp dport { 80, 443 } ip saddr != @cloudflare_v4 drop\n",
            );
        }
        if !self.ipv6_networks.is_empty() {
            sets.push_str(&format!(
                "  set cloudflare_v6 {{ type ipv6_addr; flags interval; elements = {{ {} }} }}\n",
                join_networks(&self.ipv6_networks)
            ));
            rules.push_str(
                "    meta nfproto ipv6 tcp dport { 80, 443 } ip6 saddr != @cloudflare_v6 drop\n",
            );
        }
        format!(
            "table inet {TABLE_NAME} {{\n{sets}  chain origin_input {{\n    type filter hook input priority -10; policy accept;\n{rules}  }}\n}}\n"
        )
    }
}

/// nftables apply/read-back 실패입니다.
#[derive(Debug, Error)]
pub enum NftablesError {
    /// allowlist가 비었습니다.
    #[error("Cloudflare origin allowlist가 비었습니다")]
    EmptyAllowlist,
    /// 공통 command runner 실패입니다.
    #[error(transparent)]
    Command(#[from] CommandError),
}

/// `inet vps_guard` table만 소유하는 nftables adapter입니다.
#[derive(Debug, Default, Clone, Copy)]
pub struct VpsGuardNftables {
    runner: SystemCommandRunner,
}

impl VpsGuardNftables {
    /// syntax check 후 VPSGuard table을 적용합니다.
    ///
    /// # Errors
    ///
    /// nft syntax 또는 apply 실패를 반환합니다.
    pub fn apply(&self, plan: &OriginFirewallPlan) -> Result<Vec<CommandAudit>, NftablesError> {
        let source = plan.render();
        let check = self.runner.run(
            OwnedProgram::Nft,
            &["--check".to_owned(), "--file".to_owned(), "-".to_owned()],
            Some(source.as_bytes()),
            &[],
        )?;
        let mut audits = vec![check.audit];
        audits.extend(self.remove_if_present()?);
        let apply = self.runner.run(
            OwnedProgram::Nft,
            &["--file".to_owned(), "-".to_owned()],
            Some(source.as_bytes()),
            &[],
        )?;
        audits.push(apply.audit);
        Ok(audits)
    }

    /// VPSGuard table을 제거합니다. 없는 table은 정상 no-op입니다.
    ///
    /// # Errors
    ///
    /// nft 명령 실패를 반환합니다.
    pub fn remove_if_present(&self) -> Result<Vec<CommandAudit>, NftablesError> {
        if !self.table_exists()? {
            return Ok(Vec::new());
        }
        let output = self.runner.run(
            OwnedProgram::Nft,
            &[
                "delete".to_owned(),
                "table".to_owned(),
                "inet".to_owned(),
                TABLE_NAME.to_owned(),
            ],
            None,
            &[],
        )?;
        Ok(vec![output.audit])
    }

    /// VPSGuard table이 실제 kernel에 있는지 read-back합니다.
    ///
    /// # Errors
    ///
    /// nft read-back 명령 실패를 반환합니다.
    pub fn is_applied(&self) -> Result<bool, NftablesError> {
        if !self.table_exists()? {
            return Ok(false);
        }
        let output = self.runner.run(
            OwnedProgram::Nft,
            &[
                "list".to_owned(),
                "table".to_owned(),
                "inet".to_owned(),
                TABLE_NAME.to_owned(),
            ],
            None,
            &[],
        )?;
        Ok(output.stdout.contains("chain origin_input"))
    }

    fn table_exists(&self) -> Result<bool, NftablesError> {
        let tables = self.runner.run(
            OwnedProgram::Nft,
            &["list".to_owned(), "tables".to_owned()],
            None,
            &[],
        )?;
        Ok(table_list_contains(&tables.stdout))
    }
}

fn table_list_contains(output: &str) -> bool {
    output
        .lines()
        .any(|line| line.split_whitespace().eq(["table", "inet", TABLE_NAME]))
}

fn join_networks(networks: &[IpNet]) -> String {
    networks
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use ipnet::IpNet;

    use super::{OriginFirewallPlan, table_list_contains};

    #[test]
    fn rendered_table_only_filters_web_ports() -> Result<(), Box<dyn std::error::Error>> {
        let plan = OriginFirewallPlan::new(vec!["192.0.2.0/24".parse::<IpNet>()?])?;
        let source = plan.render();
        assert!(source.contains("tcp dport { 80, 443 }"));
        assert!(!source.contains("dport 22"));
        assert!(!source.contains("policy drop"));
        assert!(source.contains("table inet vps_guard"));
        Ok(())
    }

    #[test]
    fn empty_origin_allowlist_is_rejected() {
        assert!(OriginFirewallPlan::new(Vec::new()).is_err());
    }

    #[test]
    fn missing_owned_table_is_a_normal_unlocked_state() {
        assert!(!table_list_contains("table inet filter\ntable ip nat\n"));
        assert!(table_list_contains(
            "table inet filter\ntable inet vps_guard\n"
        ));
    }
}
