//! Public listener, HTTP header와 served certificate read-back adapter입니다.

use std::collections::BTreeSet;
use std::fs;

use super::host::{read_first_line, write_state};
use super::{CERTIFICATE, IngressStateError, IngressStateStore};
use crate::listener::{ListenerTransport, protected_listeners as parse_protected_listeners};
use crate::{IngressTopology, OwnedProgram};

impl IngressStateStore {
    /// 현재 public 443 process owner topology를 read-back합니다.
    ///
    /// # Errors
    ///
    /// listener command 또는 fixture 상태 읽기 실패를 반환합니다.
    pub fn current_topology(&mut self) -> Result<IngressTopology, IngressStateError> {
        if let Some(root) = &self.config.test_state_root {
            let marker = read_first_line(&root.join("edge-public"))?;
            return Ok(if marker.as_deref() == Some("true") {
                IngressTopology::VpsGuardPublic
            } else {
                IngressTopology::NginxPublic
            });
        }
        let output = self.runner.run(
            OwnedProgram::Ss,
            &["-H".to_owned(), "-ltnp".to_owned()],
            None,
            &[],
        )?;
        let edge = output
            .stdout
            .lines()
            .any(|line| listener_port(line) == Some(443) && line.contains("vps-guard-edge"));
        self.record_audit(output.audit);
        Ok(if edge {
            IngressTopology::VpsGuardPublic
        } else {
            IngressTopology::NginxPublic
        })
    }

    pub(super) fn set_fixture_topology(&self, edge_public: bool) -> Result<(), IngressStateError> {
        if let Some(root) = &self.config.test_state_root {
            write_state(
                &root.join("edge-public"),
                if edge_public { "true" } else { "false" },
            )?;
            write_state(
                &root.join("public-edge-header"),
                if edge_public { "present" } else { "absent" },
            )?;
        }
        Ok(())
    }

    pub(super) fn public_edge_header(&mut self) -> Result<bool, IngressStateError> {
        if let Some(root) = &self.config.test_state_root {
            return Ok(
                read_first_line(&root.join("public-edge-header"))?.as_deref() == Some("present"),
            );
        }
        let output = self.runner.run(
            OwnedProgram::Curl,
            &[
                "--fail".to_owned(),
                "--silent".to_owned(),
                "--show-error".to_owned(),
                "--max-time".to_owned(),
                "15".to_owned(),
                "--dump-header".to_owned(),
                "-".to_owned(),
                "--output".to_owned(),
                "/dev/null".to_owned(),
                self.config.public_probe_url.clone(),
            ],
            None,
            &[],
        )?;
        let present = output.stdout.lines().any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case("x-vps-guard")
                    && value.trim().eq_ignore_ascii_case("guard-edge")
            })
        });
        self.record_audit(output.audit);
        Ok(present)
    }

    pub(super) fn certificate_fingerprint(&mut self) -> Result<String, IngressStateError> {
        if self.config.test_root.is_some() {
            return Ok("test-certificate".to_owned());
        }
        let certificate = self.logical_path(CERTIFICATE)?;
        let output = self.runner.run(
            OwnedProgram::Openssl,
            &[
                "x509".to_owned(),
                "-in".to_owned(),
                certificate.display().to_string(),
                "-noout".to_owned(),
                "-fingerprint".to_owned(),
                "-sha256".to_owned(),
            ],
            None,
            &[],
        )?;
        let fingerprint = first_line(&output.stdout);
        self.record_audit(output.audit);
        require_fingerprint(fingerprint, "certificate")
    }

    pub(super) fn served_certificate_fingerprint(&mut self) -> Result<String, IngressStateError> {
        if self.config.test_root.is_some() {
            return Ok("test-certificate".to_owned());
        }
        let handshake = self.runner.run(
            OwnedProgram::Openssl,
            &[
                "s_client".to_owned(),
                "-connect".to_owned(),
                "127.0.0.1:443".to_owned(),
                "-servername".to_owned(),
                self.config.server_name.clone(),
            ],
            Some(b""),
            &[],
        )?;
        self.record_audit(handshake.audit);
        let certificate = self.runner.run(
            OwnedProgram::Openssl,
            &[
                "x509".to_owned(),
                "-noout".to_owned(),
                "-fingerprint".to_owned(),
                "-sha256".to_owned(),
            ],
            Some(handshake.stdout.as_bytes()),
            &[],
        )?;
        let fingerprint = first_line(&certificate.stdout);
        self.record_audit(certificate.audit);
        require_fingerprint(fingerprint, "served certificate")
    }

    pub(super) fn protected_listeners(&mut self) -> Result<BTreeSet<String>, IngressStateError> {
        if let Some(root) = &self.config.test_state_root {
            let value = fs::read_to_string(root.join("protected-listeners")).unwrap_or_default();
            return Ok(value
                .lines()
                .filter(|line| !line.is_empty())
                .map(str::to_owned)
                .collect());
        }
        let tcp = self.runner.run(
            OwnedProgram::Ss,
            &["-H".to_owned(), "-ltnp".to_owned()],
            None,
            &[],
        )?;
        let udp = self.runner.run(
            OwnedProgram::Ss,
            &["-H".to_owned(), "-lunp".to_owned()],
            None,
            &[],
        )?;
        let listeners = parse_protected_listeners(&tcp.stdout, ListenerTransport::Tcp)
            .into_iter()
            .chain(parse_protected_listeners(
                &udp.stdout,
                ListenerTransport::Udp,
            ))
            .collect();
        self.record_audit(tcp.audit);
        self.record_audit(udp.audit);
        Ok(listeners)
    }
}

fn first_line(value: &str) -> String {
    value
        .lines()
        .next()
        .map(str::trim)
        .unwrap_or_default()
        .to_owned()
}

fn require_fingerprint(value: String, label: &str) -> Result<String, IngressStateError> {
    if value.is_empty() {
        Err(IngressStateError::Contract(format!(
            "{label} fingerprint가 비었습니다"
        )))
    } else {
        Ok(value)
    }
}

fn listener_port(line: &str) -> Option<u16> {
    line.split_whitespace()
        .nth(3)
        .and_then(|address| address.rsplit_once(':'))
        .and_then(|(_, port)| port.parse().ok())
}

#[cfg(test)]
mod tests {
    use crate::listener::{ListenerTransport, protected_listeners};

    #[test]
    fn ops_011_listener_identity_ignores_process_pid_and_owned_web_ports() {
        let before = "LISTEN 0 511 *:22 *:* users:((\"sshd\",pid=101,fd=3))";
        let after = "LISTEN 0 511 *:22 *:* users:((\"sshd\",pid=202,fd=3))";
        assert_eq!(
            protected_listeners(before, ListenerTransport::Tcp),
            ["*:22".to_owned()].into()
        );
        assert_eq!(
            protected_listeners(after, ListenerTransport::Tcp),
            ["*:22".to_owned()].into()
        );
        assert_eq!(
            protected_listeners(
                "LISTEN 0 511 127.0.0.1:3306 0.0.0.0:*",
                ListenerTransport::Tcp
            ),
            ["127.0.0.1:3306".to_owned()].into()
        );
        for port in [80, 443, 7443, 18080, 18081] {
            assert!(
                protected_listeners(
                    &format!("LISTEN 0 511 127.0.0.1:{port} 0.0.0.0:*"),
                    ListenerTransport::Tcp
                )
                .is_empty()
            );
        }
    }
}
