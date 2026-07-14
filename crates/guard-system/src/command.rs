//! root 변경 외부 명령의 allowlist, 비밀 마스킹과 구조화 감사를 제공합니다.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// 실행할 수 있는 OS program allowlist입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnedProgram {
    /// nftables CLI입니다.
    Nft,
    /// VPSGuard-owned systemd unit 제어입니다.
    Systemctl,
    /// Nginx 후보 설정 검사입니다.
    Nginx,
}

impl OwnedProgram {
    fn path(self) -> &'static str {
        match self {
            Self::Nft => "/usr/sbin/nft",
            Self::Systemctl => "/usr/bin/systemctl",
            Self::Nginx => "/usr/sbin/nginx",
        }
    }
}

/// 비밀값을 제거한 command 감사 row입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandAudit {
    /// 실행 시작 RFC3339입니다.
    pub occurred_at: String,
    /// allowlist program입니다.
    pub program: String,
    /// 민감 인자를 `***`로 바꾼 argv입니다.
    pub argv: Vec<String>,
    /// process exit code입니다.
    pub exit_code: Option<i32>,
    /// 실행 시간 milliseconds입니다.
    pub duration_ms: u64,
}

/// command stdout과 감사 결과입니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// UTF-8 lossy stdout입니다.
    pub stdout: String,
    /// 구조화 감사 row입니다.
    pub audit: CommandAudit,
}

/// allowlist command 실행 실패입니다.
#[derive(Debug, Error)]
pub enum CommandError {
    /// process 시작 또는 I/O 실패입니다.
    #[error("OS command 실행 실패: {0}")]
    Io(#[from] std::io::Error),
    /// program이 non-zero로 종료했습니다.
    #[error("OS command 실패: program={program}, exit={exit_code:?}, stderr={stderr}")]
    Failed {
        /// program 경로입니다.
        program: String,
        /// exit code입니다.
        exit_code: Option<i32>,
        /// bounded stderr입니다.
        stderr: String,
    },
}

/// allowlist OS command runner입니다.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemCommandRunner;

impl SystemCommandRunner {
    /// 명령을 실행하고 성공 결과만 반환합니다.
    ///
    /// # Errors
    ///
    /// process I/O 또는 non-zero exit를 반환합니다.
    pub fn run(
        &self,
        program: OwnedProgram,
        arguments: &[String],
        stdin: Option<&[u8]>,
        sensitive_indices: &[usize],
    ) -> Result<CommandOutput, CommandError> {
        let started = Instant::now();
        let mut child = Command::new(program.path())
            .args(arguments)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let (Some(input), Some(mut child_stdin)) = (stdin, child.stdin.take()) {
            child_stdin.write_all(input)?;
        }
        let output = child.wait_with_output()?;
        let audit = CommandAudit {
            occurred_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            program: program.path().to_owned(),
            argv: arguments
                .iter()
                .enumerate()
                .map(|(index, value)| {
                    if sensitive_indices.contains(&index) {
                        "***".to_owned()
                    } else {
                        value.clone()
                    }
                })
                .collect(),
            exit_code: output.status.code(),
            duration_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        };
        if !output.status.success() {
            return Err(CommandError::Failed {
                program: program.path().to_owned(),
                exit_code: output.status.code(),
                stderr: bounded_text(&output.stderr),
            });
        }
        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            audit,
        })
    }
}

fn bounded_text(bytes: &[u8]) -> String {
    const MAX_BYTES: usize = 4_096;
    String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_BYTES)]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::{CommandAudit, OwnedProgram};

    #[test]
    fn program_paths_are_fixed_and_audit_is_serializable() -> Result<(), Box<dyn std::error::Error>>
    {
        assert_eq!(OwnedProgram::Nft.path(), "/usr/sbin/nft");
        let audit = CommandAudit {
            occurred_at: "2026-07-14T00:00:00Z".to_owned(),
            program: OwnedProgram::Systemctl.path().to_owned(),
            argv: vec!["restart".to_owned(), "***".to_owned()],
            exit_code: Some(0),
            duration_ms: 3,
        };
        let json = serde_json::to_string(&audit)?;
        assert!(!json.contains("secret-token"));
        assert!(json.contains("***"));
        Ok(())
    }
}
