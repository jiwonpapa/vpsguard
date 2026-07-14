//! Local 관리자 socket의 versioned 요청·응답 계약을 정의합니다.

use serde::{Deserialize, Serialize};

/// 현재 local 관리자 protocol 버전입니다.
pub const ADMIN_PROTOCOL_VERSION: u32 = 1;

/// peer credential 검증 뒤 수행할 수 있는 local 관리자 명령입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AdminCommand {
    /// 짧게 만료되는 단회 웹 로그인 코드를 발급합니다.
    IssueLoginCode {
        /// 코드 유효시간입니다.
        ttl_seconds: u64,
    },
}

/// local 관리자 socket 요청입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminRequest {
    /// protocol schema 버전입니다.
    pub schema_version: u32,
    /// 실행할 typed 명령입니다.
    pub command: AdminCommand,
}

/// local 관리자 socket의 안정적인 오류 코드입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdminErrorCode {
    /// socket peer가 root 또는 service owner가 아닙니다.
    UnauthorizedPeer,
    /// JSON, schema 또는 명령 값이 잘못됐습니다.
    InvalidRequest,
    /// code 발급 중 내부 처리가 실패했습니다.
    InternalFailure,
}

/// 로그인 코드 또는 구조화 오류를 반환하는 local 관리자 응답입니다.
///
/// 로그인 코드를 포함하므로 의도적인 로그 출력을 막기 위해 `Debug`를 구현하지 않습니다.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AdminResponse {
    /// 새 단회 로그인 코드입니다.
    LoginCode {
        /// protocol schema 버전입니다.
        schema_version: u32,
        /// 브라우저에 한 번 입력할 원문 코드입니다.
        login_code: String,
        /// 발급 시점부터 만료까지의 초입니다.
        expires_in_seconds: u64,
    },
    /// 사용자에게 그대로 전달 가능한 구조화 오류입니다.
    Error {
        /// protocol schema 버전입니다.
        schema_version: u32,
        /// 안정적인 machine code입니다.
        code: AdminErrorCode,
        /// 발생한 문제입니다.
        problem: String,
        /// 수행되지 않은 작업 또는 영향입니다.
        impact: String,
        /// 운영자가 취할 다음 조치입니다.
        next_action: String,
    },
}

#[cfg(test)]
mod tests {
    use super::{ADMIN_PROTOCOL_VERSION, AdminCommand, AdminRequest};

    #[test]
    fn rejects_unknown_admin_request_fields() {
        let source = r#"{"schema_version":1,"command":{"kind":"issue_login_code","ttl_seconds":300},"extra":true}"#;
        assert!(serde_json::from_str::<AdminRequest>(source).is_err());
    }

    #[test]
    fn round_trips_typed_login_code_request() -> Result<(), Box<dyn std::error::Error>> {
        let request = AdminRequest {
            schema_version: ADMIN_PROTOCOL_VERSION,
            command: AdminCommand::IssueLoginCode { ttl_seconds: 300 },
        };
        let encoded = serde_json::to_vec(&request)?;
        assert_eq!(serde_json::from_slice::<AdminRequest>(&encoded)?, request);
        Ok(())
    }
}
