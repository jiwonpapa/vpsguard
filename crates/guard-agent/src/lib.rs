//! OS, Nginx, PHP-FPM, MySQL과 Redis의 읽기 전용 collector 계약을 소유합니다.
//!
//! MVP에서는 별도 daemon이 아니라 `guard-control` 프로세스에 library로 포함됩니다.

/// MVP agent가 control 프로세스에 포함되는 계약입니다.
pub const EMBEDDED_IN_CONTROL: bool = true;
