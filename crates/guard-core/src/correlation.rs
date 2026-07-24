//! Edge와 Control이 공유하는 canonical request ID 계약입니다.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use uuid::Uuid;

const REQUEST_ID_PREFIX: &str = "guard-";
const PROCESS_NONCE_HEX_LEN: usize = 32;
const SEQUENCE_HEX_LEN: usize = 16;
const REQUEST_ID_LEN: usize =
    REQUEST_ID_PREFIX.len() + PROCESS_NONCE_HEX_LEN + 1 + SEQUENCE_HEX_LEN;

/// structured operational log 계약 버전입니다.
pub const LOG_SCHEMA_VERSION: u32 = 1;

/// 재시작마다 달라지는 process nonce와 lock-free sequence를 결합합니다.
///
/// UUID는 generator 생성 시 한 번만 만들고 요청 hot path에서는 atomic 증가와
/// bounded 문자열 formatting만 수행합니다. 생성된 ID에는 client 정보나 비밀값이 없습니다.
#[derive(Debug)]
pub struct RequestIdGenerator {
    process_nonce_hex: String,
    sequence: AtomicU64,
}

impl RequestIdGenerator {
    /// 새 process 범위 request ID generator를 만듭니다.
    #[must_use]
    pub fn new() -> Self {
        Self::with_process_nonce(*Uuid::new_v4().as_bytes())
    }

    fn with_process_nonce(process_nonce: [u8; 16]) -> Self {
        let mut process_nonce_hex = String::with_capacity(PROCESS_NONCE_HEX_LEN);
        for byte in process_nonce {
            let _format_result = write!(process_nonce_hex, "{byte:02x}");
        }
        Self {
            process_nonce_hex,
            sequence: AtomicU64::new(1),
        }
    }

    /// 다음 canonical request ID를 반환합니다.
    #[must_use]
    pub fn next_id(&self) -> String {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let mut request_id = String::with_capacity(REQUEST_ID_LEN);
        request_id.push_str(REQUEST_ID_PREFIX);
        request_id.push_str(&self.process_nonce_hex);
        request_id.push('-');
        let _format_result = write!(request_id, "{sequence:016x}");
        request_id
    }
}

impl Default for RequestIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// 문자열이 VPSGuard가 생성하는 canonical request ID 형식인지 확인합니다.
///
/// 공개 client가 보낸 임의 추적값을 신뢰 경계 안의 request ID로 승격하지 않기 위한
/// 형식 검사이며, 값의 발급 주체 인증을 대신하지 않습니다.
#[must_use]
pub fn is_valid_request_id(value: &str) -> bool {
    if value.len() != REQUEST_ID_LEN || !value.starts_with(REQUEST_ID_PREFIX) {
        return false;
    }
    let nonce_start = REQUEST_ID_PREFIX.len();
    let nonce_end = nonce_start + PROCESS_NONCE_HEX_LEN;
    let sequence_start = nonce_end + 1;
    value.as_bytes().get(nonce_end) == Some(&b'-')
        && value[nonce_start..nonce_end]
            .bytes()
            .all(is_lower_hexadecimal)
        && value[sequence_start..].bytes().all(is_lower_hexadecimal)
}

const fn is_lower_hexadecimal(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

#[cfg(test)]
mod tests {
    use super::{RequestIdGenerator, is_valid_request_id};

    #[test]
    fn process_nonce_and_sequence_make_canonical_ids() {
        let generator = RequestIdGenerator::with_process_nonce([0xab; 16]);

        assert_eq!(
            generator.next_id(),
            "guard-abababababababababababababababab-0000000000000001"
        );
        assert_eq!(
            generator.next_id(),
            "guard-abababababababababababababababab-0000000000000002"
        );
    }

    #[test]
    fn validation_rejects_legacy_spoofed_and_malformed_ids() {
        assert!(is_valid_request_id(
            "guard-0123456789abcdef0123456789abcdef-0000000000000001"
        ));
        assert!(!is_valid_request_id("guard-0000000000000001"));
        assert!(!is_valid_request_id(
            "guard-0123456789ABCDEF0123456789ABCDEF-0000000000000001"
        ));
        assert!(!is_valid_request_id(
            "client-0123456789abcdef0123456789abcdef-0000000000000001"
        ));
    }
}
