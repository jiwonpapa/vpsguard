//! Cloudflare DNS read-back과 VPSGuard-owned nftables origin 보호 adapter입니다.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use guard_system::{OriginFirewallPlan, VpsGuardNftables};
use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::json;

use crate::{ProviderBackend, ProviderError, ProviderSnapshot};

const DEFAULT_API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// 원본 80/443 보호의 적용·read-back·복구 계약입니다.
pub trait OriginProtection {
    /// 보호가 현재 적용됐는지 반환합니다.
    fn is_locked(&mut self) -> Result<bool, ProviderError>;
    /// Cloudflare network 외 web ingress를 차단합니다.
    fn lock(&mut self) -> Result<(), ProviderError>;
    /// snapshot의 보호 상태로 복구합니다.
    fn restore(&mut self, locked: bool) -> Result<(), ProviderError>;
}

/// nftables `inet vps_guard` table만 사용하는 원본 보호 adapter입니다.
#[derive(Debug)]
pub struct NftOriginProtection {
    nftables: VpsGuardNftables,
    plan: OriginFirewallPlan,
}

impl NftOriginProtection {
    /// 검증된 Cloudflare CIDR plan으로 adapter를 생성합니다.
    #[must_use]
    pub fn new(plan: OriginFirewallPlan) -> Self {
        Self {
            nftables: VpsGuardNftables::default(),
            plan,
        }
    }
}

impl OriginProtection for NftOriginProtection {
    fn is_locked(&mut self) -> Result<bool, ProviderError> {
        self.nftables
            .is_applied()
            .map_err(|error| ProviderError::Backend(error.to_string()))
    }

    fn lock(&mut self) -> Result<(), ProviderError> {
        let audits = self
            .nftables
            .apply(&self.plan)
            .map_err(|error| ProviderError::Backend(error.to_string()))?;
        log_command_audits(&audits);
        Ok(())
    }

    fn restore(&mut self, locked: bool) -> Result<(), ProviderError> {
        if locked {
            self.lock()
        } else {
            let audits = self
                .nftables
                .remove_if_present()
                .map_err(|error| ProviderError::Backend(error.to_string()))?;
            log_command_audits(&audits);
            Ok(())
        }
    }
}

/// Cloudflare DNS API와 외부 HTTPS 증거를 사용하는 production backend입니다.
#[derive(Debug)]
pub struct CloudflareBackend<O> {
    client: Client,
    api_base: String,
    zone_id: String,
    allowed_records: Vec<String>,
    token: String,
    origin: O,
}

impl<O> CloudflareBackend<O>
where
    O: OriginProtection,
{
    /// root-only token 파일과 record allowlist로 backend를 생성합니다.
    ///
    /// # Errors
    ///
    /// token 파일 권한·내용, zone·allowlist 또는 HTTP client 생성 실패를 반환합니다.
    pub fn from_token_file(
        zone_id: impl Into<String>,
        allowed_records: Vec<String>,
        token_file: &Path,
        origin: O,
    ) -> Result<Self, ProviderError> {
        let metadata = fs::metadata(token_file)
            .map_err(|error| ProviderError::Backend(format!("TOKEN_READ_FAILED: {error}")))?;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ProviderError::Backend(
                "TOKEN_FILE_PERMISSIONS_MUST_BE_0600".to_owned(),
            ));
        }
        let token = fs::read_to_string(token_file)
            .map_err(|error| ProviderError::Backend(format!("TOKEN_READ_FAILED: {error}")))?
            .trim()
            .to_owned();
        let zone_id = zone_id.into();
        if token.len() < 20 || zone_id.trim().is_empty() || allowed_records.is_empty() {
            return Err(ProviderError::Backend(
                "CLOUDFLARE_CONFIGURATION_INVALID".to_owned(),
            ));
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("VPSGuard/0.1")
            .build()
            .map_err(|error| ProviderError::Backend(format!("HTTP_CLIENT_FAILED: {error}")))?;
        Ok(Self {
            client,
            api_base: DEFAULT_API_BASE.to_owned(),
            zone_id,
            allowed_records,
            token,
            origin,
        })
    }

    fn ensure_allowed(&self, record_name: &str) -> Result<(), ProviderError> {
        if self
            .allowed_records
            .iter()
            .any(|allowed| allowed == record_name)
        {
            Ok(())
        } else {
            Err(ProviderError::RecordNotAllowed(record_name.to_owned()))
        }
    }

    fn read_record(&self, record_name: &str) -> Result<DnsRecord, ProviderError> {
        self.ensure_allowed(record_name)?;
        let url = format!("{}/zones/{}/dns_records", self.api_base, self.zone_id);
        let response = self
            .client
            .get(url)
            .query(&[("name", record_name)])
            .headers(self.headers()?)
            .send()
            .map_err(http_error)?;
        let status = response.status();
        if !status.is_success() {
            return Err(ProviderError::Backend(format!(
                "CLOUDFLARE_HTTP_{}",
                status.as_u16()
            )));
        }
        let envelope = response
            .json::<CloudflareEnvelope<Vec<DnsRecord>>>()
            .map_err(http_error)?;
        if !envelope.success {
            return Err(ProviderError::Backend("CLOUDFLARE_API_REJECTED".to_owned()));
        }
        envelope
            .result
            .into_iter()
            .find(|record| record.name == record_name)
            .ok_or_else(|| ProviderError::Backend("DNS_RECORD_NOT_FOUND".to_owned()))
    }

    fn set_proxied(&self, record_name: &str, proxied: bool) -> Result<(), ProviderError> {
        let record = self.read_record(record_name)?;
        let url = format!(
            "{}/zones/{}/dns_records/{}",
            self.api_base, self.zone_id, record.id
        );
        let response = self
            .client
            .patch(url)
            .headers(self.headers()?)
            .json(&json!({ "proxied": proxied }))
            .send()
            .map_err(http_error)?;
        if !response.status().is_success() {
            return Err(ProviderError::Backend(format!(
                "CLOUDFLARE_HTTP_{}",
                response.status().as_u16()
            )));
        }
        let envelope = response
            .json::<CloudflareEnvelope<DnsRecord>>()
            .map_err(http_error)?;
        if envelope.success && envelope.result.proxied == proxied {
            Ok(())
        } else {
            Err(ProviderError::Backend(
                "CLOUDFLARE_PROXY_READBACK_MISMATCH".to_owned(),
            ))
        }
    }

    fn headers(&self) -> Result<HeaderMap, ProviderError> {
        let mut headers = HeaderMap::new();
        let value = HeaderValue::from_str(&format!("Bearer {}", self.token))
            .map_err(|_| ProviderError::Backend("CLOUDFLARE_TOKEN_INVALID".to_owned()))?;
        headers.insert(AUTHORIZATION, value);
        Ok(headers)
    }
}

impl<O> ProviderBackend for CloudflareBackend<O>
where
    O: OriginProtection,
{
    fn snapshot(&mut self, record_name: &str) -> Result<ProviderSnapshot, ProviderError> {
        let record = self.read_record(record_name)?;
        Ok(ProviderSnapshot {
            record_name: record.name,
            proxied: record.proxied,
            origin_locked: self.origin.is_locked()?,
        })
    }

    fn request_proxy_enable(&mut self, record_name: &str) -> Result<(), ProviderError> {
        self.set_proxied(record_name, true)
    }

    fn verify_proxy_enabled(&mut self, record_name: &str) -> Result<bool, ProviderError> {
        if !self.read_record(record_name)?.proxied {
            return Ok(false);
        }
        let response = self
            .client
            .get(format!("https://{record_name}/"))
            .send()
            .map_err(http_error)?;
        Ok(response.headers().contains_key("cf-ray"))
    }

    fn request_origin_lock(&mut self) -> Result<(), ProviderError> {
        self.origin.lock()
    }

    fn verify_origin_lock(&mut self) -> Result<bool, ProviderError> {
        self.origin.is_locked()
    }

    fn restore(&mut self, snapshot: &ProviderSnapshot) -> Result<(), ProviderError> {
        self.origin.restore(snapshot.origin_locked)?;
        self.set_proxied(&snapshot.record_name, snapshot.proxied)?;
        let record_matches = self.read_record(&snapshot.record_name)?.proxied == snapshot.proxied;
        let origin_matches = self.origin.is_locked()? == snapshot.origin_locked;
        if record_matches && origin_matches {
            Ok(())
        } else {
            Err(ProviderError::Backend(
                "PROVIDER_RESTORE_READBACK_MISMATCH".to_owned(),
            ))
        }
    }
}

fn log_command_audits(audits: &[guard_system::CommandAudit]) {
    for audit in audits {
        if let Ok(encoded) = serde_json::to_string(audit) {
            tracing::info!(command_audit = %encoded, "owned OS command completed");
        }
    }
}

#[derive(Debug, Deserialize)]
struct CloudflareEnvelope<T> {
    success: bool,
    result: T,
}

#[derive(Debug, Deserialize)]
struct DnsRecord {
    id: String,
    name: String,
    proxied: bool,
}

fn http_error(error: reqwest::Error) -> ProviderError {
    if error.is_timeout() {
        ProviderError::Backend("CLOUDFLARE_TIMEOUT".to_owned())
    } else {
        ProviderError::Backend(format!("CLOUDFLARE_REQUEST_FAILED: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::{CloudflareBackend, OriginProtection};
    use crate::ProviderError;

    #[derive(Debug)]
    struct FakeOrigin;

    impl OriginProtection for FakeOrigin {
        fn is_locked(&mut self) -> Result<bool, ProviderError> {
            Ok(false)
        }

        fn lock(&mut self) -> Result<(), ProviderError> {
            Ok(())
        }

        fn restore(&mut self, _locked: bool) -> Result<(), ProviderError> {
            Ok(())
        }
    }

    #[test]
    fn rejects_group_readable_token_file() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("token");
        fs::write(&path, "this-is-a-long-enough-test-token")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
        let result = CloudflareBackend::from_token_file(
            "zone",
            vec!["example.com".to_owned()],
            &path,
            FakeOrigin,
        );
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn accepts_root_only_token_file_without_network() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("token");
        fs::write(&path, "this-is-a-long-enough-test-token")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let backend = CloudflareBackend::from_token_file(
            "zone",
            vec!["example.com".to_owned()],
            &path,
            FakeOrigin,
        );
        assert!(backend.is_ok());
        Ok(())
    }
}
