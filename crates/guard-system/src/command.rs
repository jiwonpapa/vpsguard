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
    /// VPSGuard 설정 검사 CLI입니다.
    VpsGuard,
    /// bounded public HTTP read-back client입니다.
    Curl,
    /// certificate fingerprint read-back client입니다.
    Openssl,
    /// listener inventory를 읽는 iproute2 CLI입니다.
    Ss,
    /// system account와 group을 조회합니다.
    Getent,
    /// system account process를 조회합니다.
    Pgrep,
    /// VPSGuard system account를 제거합니다.
    Userdel,
    /// VPSGuard system group을 제거합니다.
    Groupdel,
}

impl OwnedProgram {
    fn path(self) -> &'static str {
        match self {
            Self::Nft => "/usr/sbin/nft",
            Self::Systemctl => "/usr/bin/systemctl",
            Self::Nginx => "/usr/sbin/nginx",
            Self::VpsGuard => "/usr/local/bin/vps-guard",
            Self::Curl => "/usr/bin/curl",
            Self::Openssl => "/usr/bin/openssl",
            Self::Ss => "/usr/bin/ss",
            Self::Getent => "/usr/bin/getent",
            Self::Pgrep => "/usr/bin/pgrep",
            Self::Userdel => "/usr/sbin/userdel",
            Self::Groupdel => "/usr/sbin/groupdel",
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
        self.run_accepting(program, arguments, stdin, sensitive_indices, &[0])
    }

    /// 명령을 실행하고 계약에 명시된 exit code를 정상 결과로 반환합니다.
    ///
    /// `systemctl is-active`, `getent`처럼 정상적인 부재 상태를 non-zero로
    /// 보고하는 read 명령에만 사용합니다.
    ///
    /// # Errors
    ///
    /// process I/O 또는 허용되지 않은 exit code를 반환합니다.
    pub fn run_accepting(
        &self,
        program: OwnedProgram,
        arguments: &[String],
        stdin: Option<&[u8]>,
        sensitive_indices: &[usize],
        accepted_exit_codes: &[i32],
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
        if !output
            .status
            .code()
            .is_some_and(|code| accepted_exit_codes.contains(&code))
        {
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
    use super::{CommandAudit, OwnedProgram, bounded_text};

    #[test]
    fn program_paths_are_fixed_and_audit_is_serializable() -> Result<(), Box<dyn std::error::Error>>
    {
        assert_eq!(OwnedProgram::Nft.path(), "/usr/sbin/nft");
        assert_eq!(OwnedProgram::VpsGuard.path(), "/usr/local/bin/vps-guard");
        assert_eq!(OwnedProgram::Curl.path(), "/usr/bin/curl");
        assert_eq!(OwnedProgram::Openssl.path(), "/usr/bin/openssl");
        assert_eq!(OwnedProgram::Ss.path(), "/usr/bin/ss");
        assert_eq!(OwnedProgram::Getent.path(), "/usr/bin/getent");
        assert_eq!(OwnedProgram::Pgrep.path(), "/usr/bin/pgrep");
        assert_eq!(OwnedProgram::Userdel.path(), "/usr/sbin/userdel");
        assert_eq!(OwnedProgram::Groupdel.path(), "/usr/sbin/groupdel");
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

    #[test]
    fn stderr_text_is_lossy_utf8_and_bounded() {
        let mut bytes = vec![b'x'; 5_000];
        bytes[0] = 0xff;
        let bounded = bounded_text(&bytes);

        assert!(bounded.starts_with('\u{fffd}'));
        assert!(bounded.len() <= 4_098);
        assert!(!bounded.contains("secret-token"));
    }
}
