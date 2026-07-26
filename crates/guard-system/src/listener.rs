//! `ss` 출력을 transport가 포함된 안정적인 listener identity로 정규화합니다.

use std::collections::BTreeSet;

/// listener transport입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListenerTransport {
    /// 연결형 TCP listener입니다.
    Tcp,
    /// datagram UDP listener입니다.
    Udp,
}

/// deployment snapshot에 보존할 listener identity를 만듭니다.
///
/// 기존 TCP snapshot 형식은 그대로 유지하고 UDP에만 `udp:` prefix를 붙입니다.
#[must_use]
pub(crate) fn deployment_listeners(output: &str, transport: ListenerTransport) -> BTreeSet<String> {
    output
        .lines()
        .filter_map(|line| listener_endpoint(line, transport))
        .filter(|endpoint| !is_vpsguard_owned(endpoint, transport))
        .map(|endpoint| match transport {
            ListenerTransport::Tcp => endpoint.to_owned(),
            ListenerTransport::Udp => format!("udp:{endpoint}"),
        })
        .collect()
}

/// ingress 전환 전후에 동일해야 할 비소유 listener identity를 만듭니다.
#[must_use]
pub(crate) fn protected_listeners(output: &str, transport: ListenerTransport) -> BTreeSet<String> {
    output
        .lines()
        .filter_map(|line| listener_endpoint(line, transport))
        .filter(|endpoint| !is_vpsguard_owned(endpoint, transport))
        .filter(|endpoint| {
            transport == ListenerTransport::Udp
                || listener_port(endpoint)
                    .is_none_or(|port| !matches!(port, 80 | 443 | 7443 | 18080 | 18081))
        })
        .map(|endpoint| match transport {
            ListenerTransport::Tcp => endpoint.to_owned(),
            ListenerTransport::Udp => format!("udp:{endpoint}"),
        })
        .collect()
}

fn listener_endpoint(line: &str, transport: ListenerTransport) -> Option<&str> {
    let fields: Vec<_> = line.split_whitespace().collect();
    match transport {
        ListenerTransport::Tcp | ListenerTransport::Udp => fields.get(3).copied(),
    }
}

fn listener_port(endpoint: &str) -> Option<u16> {
    endpoint
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
}

fn is_vpsguard_owned(endpoint: &str, transport: ListenerTransport) -> bool {
    let port = listener_port(endpoint);
    match transport {
        ListenerTransport::Tcp => matches!(port, Some(7727 | 18080)),
        ListenerTransport::Udp => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{ListenerTransport, deployment_listeners, protected_listeners};

    #[test]
    fn act_010_deployment_inventory_preserves_udp_443() {
        let tcp = "LISTEN 0 511 *:22 *:*\nLISTEN 0 511 *:443 *:*\n";
        let udp = "UNCONN 0 0 *:443 *:* users:((\"nginx\",pid=10,fd=7))\n";
        let inventory = deployment_listeners(tcp, ListenerTransport::Tcp)
            .into_iter()
            .chain(deployment_listeners(udp, ListenerTransport::Udp))
            .collect::<Vec<_>>();

        assert!(inventory.contains(&"*:22".to_owned()));
        assert!(inventory.contains(&"*:443".to_owned()));
        assert!(inventory.contains(&"udp:*:443".to_owned()));
    }

    #[test]
    fn act_010_ingress_may_replace_tcp_web_but_never_udp_443() {
        let tcp = "LISTEN 0 511 *:22 *:*\nLISTEN 0 511 *:443 *:*\n";
        let udp = "UNCONN 0 0 *:443 *:* users:((\"nginx\",pid=10,fd=7))\n";
        let protected = protected_listeners(tcp, ListenerTransport::Tcp)
            .into_iter()
            .chain(protected_listeners(udp, ListenerTransport::Udp))
            .collect::<BTreeSet<_>>();

        assert_eq!(
            protected,
            BTreeSet::from(["*:22".to_owned(), "udp:*:443".to_owned()])
        );
    }

    use std::collections::BTreeSet;
}
