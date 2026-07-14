//! 설치·cutover·bypass 전 변경 영향과 보존 불변조건을 표현합니다.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// plan에 포함되는 한 변경입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlannedChange {
    /// VPSGuard 소유 파일을 생성·교체합니다.
    WriteOwnedFile {
        /// 파일 경로입니다.
        path: PathBuf,
    },
    /// VPSGuard systemd service를 재시작합니다.
    RestartOwnedService {
        /// service unit 이름입니다.
        unit: String,
    },
    /// Nginx 후보 설정을 configtest 후 반영합니다.
    ValidateNginxCandidate {
        /// 후보 설정 경로입니다.
        path: PathBuf,
    },
}

/// 실행 전 사용자에게 표시하는 변경 plan입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MutationPlan {
    /// plan schema 버전입니다.
    pub schema_version: u32,
    /// 실행 식별자입니다.
    pub operation_id: String,
    /// 실행할 변경입니다.
    pub changes: Vec<PlannedChange>,
    /// 반드시 보존할 항목입니다.
    pub preserve: Vec<String>,
}

/// 안전하지 않은 plan 오류입니다.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PlanError {
    /// 미래 schema입니다.
    #[error("지원하지 않는 plan schema입니다: {0}")]
    UnsupportedSchema(u32),
    /// VPSGuard 소유권 밖 파일입니다.
    #[error("VPSGuard 소유권 밖 파일 변경입니다: {0}")]
    ForeignPath(String),
    /// VPSGuard 외 service 변경입니다.
    #[error("VPSGuard 외 service 변경입니다: {0}")]
    ForeignService(String),
    /// 필수 보존 항목이 누락됐습니다.
    #[error("필수 보존 항목이 누락됐습니다: {0}")]
    MissingPreservation(&'static str),
}

impl MutationPlan {
    /// SSH, 인증서와 사이트 데이터 보존 및 소유권 범위를 검증합니다.
    ///
    /// # Errors
    ///
    /// 미래 schema, 외부 경로·service 또는 보존 누락을 반환합니다.
    pub fn validate(&self) -> Result<(), PlanError> {
        if self.schema_version != 1 {
            return Err(PlanError::UnsupportedSchema(self.schema_version));
        }
        for required in ["ssh", "certificates", "site-data"] {
            if !self.preserve.iter().any(|entry| entry == required) {
                return Err(PlanError::MissingPreservation(required));
            }
        }
        for change in &self.changes {
            match change {
                PlannedChange::WriteOwnedFile { path } => {
                    let allowed = [
                        "/etc/vps-guard/",
                        "/var/lib/vps-guard/",
                        "/run/vps-guard/",
                        "/etc/systemd/system/vps-guard-",
                    ];
                    let path_text = path.display().to_string();
                    if !allowed.iter().any(|prefix| path_text.starts_with(prefix)) {
                        return Err(PlanError::ForeignPath(path_text));
                    }
                }
                PlannedChange::RestartOwnedService { unit } => {
                    if !unit.starts_with("vps-guard-") || !unit.ends_with(".service") {
                        return Err(PlanError::ForeignService(unit.clone()));
                    }
                }
                PlannedChange::ValidateNginxCandidate { path } => {
                    if !path.starts_with("/etc/vps-guard/nginx/") {
                        return Err(PlanError::ForeignPath(path.display().to_string()));
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "plan/tests.rs"]
mod tests;
