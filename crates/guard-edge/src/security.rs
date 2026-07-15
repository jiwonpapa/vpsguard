//! 범용 response 보안 header와 위험 HTTP method 불변조건을 적용합니다.

use guard_core::config::{CspMode, InspectionMode, SecurityConfig};
use guard_profiles::{ApplicationProfile, security_profile};
use pingora_http::ResponseHeader;

/// 검증된 설정과 app overlay를 합성한 불변 response 정책입니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResponseSecurityPolicy {
    baseline_response_headers: bool,
    strip_origin_headers: bool,
    csp: Option<(CspMode, String)>,
    hsts_max_age_seconds: u64,
}

impl ResponseSecurityPolicy {
    /// core 설정과 app profile을 hot path 친화적인 값으로 합성합니다.
    #[must_use]
    pub(crate) fn from_config(
        config: &SecurityConfig,
        inspection: InspectionMode,
        profile: ApplicationProfile,
    ) -> Self {
        let csp = (inspection == InspectionMode::Profiled && config.csp_mode != CspMode::Off).then(
            || {
                (
                    config.csp_mode,
                    config
                        .csp_policy
                        .clone()
                        .unwrap_or_else(|| security_profile(profile).csp_policy.to_owned()),
                )
            },
        );
        Self {
            baseline_response_headers: config.baseline_response_headers,
            strip_origin_headers: config.strip_origin_headers,
            csp,
            hsts_max_age_seconds: config.hsts_max_age_seconds,
        }
    }

    /// origin 응답에 안전 header를 추가하고 구현 version 노출을 제거합니다.
    pub(crate) fn apply(
        &self,
        response: &mut ResponseHeader,
        is_https: bool,
    ) -> pingora_core::Result<()> {
        if self.strip_origin_headers {
            response.remove_header("server");
            response.remove_header("x-powered-by");
            response.remove_header("x-aspnet-version");
        }
        if self.baseline_response_headers {
            insert_if_absent(response, "x-content-type-options", "nosniff")?;
            insert_if_absent(
                response,
                "referrer-policy",
                "strict-origin-when-cross-origin",
            )?;
        }
        if is_https && self.hsts_max_age_seconds > 0 {
            insert_if_absent(
                response,
                "strict-transport-security",
                &format!("max-age={}", self.hsts_max_age_seconds),
            )?;
        }
        if let Some((mode, policy)) = self.csp.as_ref() {
            let name = match mode {
                CspMode::ReportOnly => "content-security-policy-report-only",
                CspMode::Enforce => "content-security-policy",
                CspMode::Off => return Ok(()),
            };
            insert_if_absent(response, name, policy)?;
        }
        Ok(())
    }
}

/// reverse proxy가 tunnel이나 cross-site tracing으로 전달하지 않는 method입니다.
#[must_use]
pub(crate) fn rejects_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "CONNECT" | "TRACE" | "TRACK"
    )
}

fn insert_if_absent(
    response: &mut ResponseHeader,
    name: &'static str,
    value: &str,
) -> pingora_core::Result<()> {
    if !response.headers.contains_key(name) {
        response.insert_header(name, value)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "security/tests.rs"]
mod tests;
