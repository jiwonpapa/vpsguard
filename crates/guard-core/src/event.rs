//! 사건, 감사와 복구 타임라인의 공통 event 계약입니다.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::detection::ReasonCode;

/// 사건 심각도입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// 정상 정보입니다.
    Info,
    /// 운영자 확인이 필요합니다.
    Warning,
    /// 즉시 대응이 필요합니다.
    Critical,
}

/// 중요 판단과 action의 공통 event입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GuardEvent {
    /// event schema 버전입니다.
    pub schema_version: u32,
    /// 전역 고유 event 식별자입니다.
    pub event_id: String,
    /// 발생 시각 RFC3339 문자열입니다.
    pub occurred_at: String,
    /// 심각도입니다.
    pub severity: Severity,
    /// 안정적인 event 종류입니다.
    pub kind: String,
    /// 한국어 기본 요약입니다.
    pub summary: String,
    /// 탐지 근거입니다.
    pub reason_codes: Vec<ReasonCode>,
    /// 민감값을 제거한 증거입니다.
    pub evidence: BTreeMap<String, String>,
    /// 수행한 action입니다.
    pub action: BTreeMap<String, String>,
    /// action 결과입니다.
    pub result: BTreeMap<String, String>,
    /// 다음 복구 단계입니다.
    pub recovery: BTreeMap<String, String>,
}
