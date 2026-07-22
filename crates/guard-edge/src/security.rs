//! 범용 response 보안 header와 위험 HTTP method 불변조건을 적용합니다.

use guard_core::config::{CspMode, InspectionMode, SecurityConfig};
use guard_profiles::{ApplicationProfile, security_profile};
use pingora_http::{RequestHeader, ResponseHeader};

/// origin 전달을 거부하는 ambiguous request framing입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FramingViolation {
    /// Host header가 둘 이상입니다.
    DuplicateHost,
    /// Content-Length가 둘 이상입니다.
    DuplicateContentLength,
    /// Content-Length와 Transfer-Encoding이 함께 있습니다.
    ConflictingLengthSignals,
    /// 지원하지 않는 Transfer-Encoding 조합입니다.
    InvalidTransferEncoding,
}

/// Pingora parser를 통과한 요청도 origin보다 엄격한 framing 불변조건을 적용합니다.
pub(crate) fn validate_request_framing(
    raw_header: &[u8],
    request: &RequestHeader,
) -> Result<(), FramingViolation> {
    let raw = RawFramingHeaders::parse(raw_header);
    if raw
        .host_count
        .max(request.headers.get_all("host").iter().count())
        > 1
    {
        return Err(FramingViolation::DuplicateHost);
    }
    let content_lengths = raw
        .content_length_count
        .max(request.headers.get_all("content-length").iter().count());
    if content_lengths > 1 {
        return Err(FramingViolation::DuplicateContentLength);
    }
    let normalized_transfer_encodings = request
        .headers
        .get_all("transfer-encoding")
        .iter()
        .collect::<Vec<_>>();
    let transfer_encoding_count = raw
        .transfer_encoding_count
        .max(normalized_transfer_encodings.len());
    if content_lengths > 0 && transfer_encoding_count > 0 {
        return Err(FramingViolation::ConflictingLengthSignals);
    }
    let invalid_normalized_transfer_encoding = !normalized_transfer_encodings.is_empty()
        && (normalized_transfer_encodings.len() != 1
            || normalized_transfer_encodings[0]
                .to_str()
                .ok()
                .map(str::trim)
                .is_none_or(|value| !value.eq_ignore_ascii_case("chunked")));
    if raw.invalid_transfer_encoding || invalid_normalized_transfer_encoding {
        return Err(FramingViolation::InvalidTransferEncoding);
    }
    Ok(())
}

#[derive(Debug, Default)]
struct RawFramingHeaders {
    host_count: usize,
    content_length_count: usize,
    transfer_encoding_count: usize,
    invalid_transfer_encoding: bool,
}

impl RawFramingHeaders {
    fn parse(raw_header: &[u8]) -> Self {
        let mut result = Self::default();
        for line in raw_header.split(|byte| *byte == b'\n').skip(1) {
            let line = trim_ascii(line);
            if line.is_empty() {
                break;
            }
            let Some(separator) = line.iter().position(|byte| *byte == b':') else {
                continue;
            };
            let name = trim_ascii(&line[..separator]);
            let value = trim_ascii(&line[separator + 1..]);
            if name.eq_ignore_ascii_case(b"host") {
                result.host_count = result.host_count.saturating_add(1);
            } else if name.eq_ignore_ascii_case(b"content-length") {
                result.content_length_count = result.content_length_count.saturating_add(1);
            } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
                result.transfer_encoding_count = result.transfer_encoding_count.saturating_add(1);
                result.invalid_transfer_encoding |= !value.eq_ignore_ascii_case(b"chunked");
            }
        }
        result.invalid_transfer_encoding |= result.transfer_encoding_count > 1;
        result
    }
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len().saturating_sub(1)];
    }
    value
}

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
