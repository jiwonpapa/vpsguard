//! Cloudflare DNS read-back과 VPSGuard-owned nftables origin 보호 adapter입니다.

use std::path::Path;
use std::time::Duration;

use guard_core::config::{CloudflareRecordConfig, DnsRecordType};
use guard_system::{
    OriginFirewallPlan, SecretFileError, SecretFilePolicy, VpsGuardNftables, load_secret_file,
};
use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use reqwest::{StatusCode, redirect::Policy};
use secrecy::zeroize::Zeroize;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::json;

use crate::{ProviderBackend, ProviderError, ProviderRecordSnapshot, ProviderSnapshot};

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
            .is_applied(&self.plan)
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
    allowed_records: Vec<CloudflareRecordConfig>,
    token: SecretString,
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
        allowed_records: Vec<CloudflareRecordConfig>,
        token_file: &Path,
        origin: O,
    ) -> Result<Self, ProviderError> {
        Self::from_token_file_with_api_base(
            zone_id,
            allowed_records,
            token_file,
            origin,
            DEFAULT_API_BASE,
        )
    }

    fn from_token_file_with_api_base(
        zone_id: impl Into<String>,
        allowed_records: Vec<CloudflareRecordConfig>,
        token_file: &Path,
        origin: O,
        api_base: &str,
    ) -> Result<Self, ProviderError> {
        let token = load_secret_file(
            token_file,
            SecretFilePolicy {
                min_bytes: 40,
                max_bytes: 80,
            },
        )
        .map_err(cloudflare_secret_error)?;
        let zone_id = zone_id.into();
        validate_configuration(&zone_id, &allowed_records)?;
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("VPSGuard/0.1")
            .redirect(Policy::none())
            .build()
            .map_err(|_| ProviderError::Configuration("HTTP_CLIENT_FAILED"))?;
        Ok(Self {
            client,
            api_base: api_base.trim_end_matches('/').to_owned(),
            zone_id,
            allowed_records,
            token,
            origin,
        })
    }

    /// User API Token 활성 상태와 모든 명시적 record ID·name·type을 확인합니다.
    ///
    /// # Errors
    ///
    /// token 인증·권한·상태 또는 record allowlist read-back 불일치를 반환합니다.
    pub fn preflight(&self) -> Result<(), ProviderError> {
        let response = self
            .client
            .get(format!("{}/user/tokens/verify", self.api_base))
            .headers(self.headers()?)
            .send()
            .map_err(http_error)?;
        let token = decode_response::<TokenVerifyResult>(response)?;
        if token.status != TokenStatus::Active {
            return Err(ProviderError::TokenInactive);
        }
        let record_name = self
            .allowed_records
            .first()
            .map(|record| record.name.as_str())
            .ok_or(ProviderError::Configuration("RECORD_ALLOWLIST_EMPTY"))?;
        self.read_records(record_name)?;
        Ok(())
    }

    fn targets_for_name(
        &self,
        record_name: &str,
    ) -> Result<Vec<&CloudflareRecordConfig>, ProviderError> {
        let targets = self
            .allowed_records
            .iter()
            .filter(|record| record.name.eq_ignore_ascii_case(record_name))
            .collect::<Vec<_>>();
        if targets.is_empty() {
            Err(ProviderError::RecordNotAllowed(record_name.to_owned()))
        } else {
            Ok(targets)
        }
    }

    fn read_record(&self, target: &CloudflareRecordConfig) -> Result<DnsRecord, ProviderError> {
        let url = format!(
            "{}/zones/{}/dns_records/{}",
            self.api_base, self.zone_id, target.id
        );
        let response = self
            .client
            .get(url)
            .headers(self.headers()?)
            .send()
            .map_err(http_error)?;
        let record = decode_response::<DnsRecord>(response)?;
        validate_record(target, &record)?;
        Ok(record)
    }

    fn read_records(&self, record_name: &str) -> Result<Vec<DnsRecord>, ProviderError> {
        self.targets_for_name(record_name)?
            .into_iter()
            .map(|target| self.read_record(target))
            .collect()
    }

    fn set_record_proxied(
        &self,
        target: &CloudflareRecordConfig,
        proxied: bool,
    ) -> Result<(), ProviderError> {
        let url = format!(
            "{}/zones/{}/dns_records/{}",
            self.api_base, self.zone_id, target.id
        );
        let response = self
            .client
            .patch(url)
            .headers(self.headers()?)
            .json(&json!({ "proxied": proxied }))
            .send()
            .map_err(http_error)?;
        let record = decode_response::<DnsRecord>(response)?;
        validate_record(target, &record)?;
        if record.proxied == proxied {
            Ok(())
        } else {
            Err(ProviderError::RecordMismatch(target.id.clone()))
        }
    }

    fn set_records_proxied(&self, record_name: &str, proxied: bool) -> Result<(), ProviderError> {
        let current = self.read_records(record_name)?;
        let mut changed = Vec::new();
        for record in current {
            if record.proxied == proxied {
                continue;
            }
            let target = self
                .allowed_records
                .iter()
                .find(|target| target.id == record.id)
                .ok_or_else(|| ProviderError::RecordMismatch(record.id.clone()))?;
            if let Err(error) = self.set_record_proxied(target, proxied) {
                let rollback_ok = changed.iter().rev().all(|previous: &DnsRecord| {
                    self.allowed_records
                        .iter()
                        .find(|candidate| candidate.id == previous.id)
                        .is_some_and(|candidate| {
                            self.set_record_proxied(candidate, previous.proxied).is_ok()
                        })
                });
                return if rollback_ok {
                    Err(error)
                } else {
                    Err(ProviderError::PartialRollbackFailed)
                };
            }
            changed.push(record);
        }
        Ok(())
    }

    fn headers(&self) -> Result<HeaderMap, ProviderError> {
        let mut headers = HeaderMap::new();
        let mut bearer = String::with_capacity(self.token.expose_secret().len() + 7);
        bearer.push_str("Bearer ");
        bearer.push_str(self.token.expose_secret());
        let value = HeaderValue::from_str(&bearer)
            .map_err(|_| ProviderError::SecretFile("TOKEN_FORMAT_INVALID"));
        bearer.zeroize();
        let mut value = value?;
        value.set_sensitive(true);
        headers.insert(AUTHORIZATION, value);
        Ok(headers)
    }
}

impl<O> ProviderBackend for CloudflareBackend<O>
where
    O: OriginProtection,
{
    fn snapshot(&mut self, record_name: &str) -> Result<ProviderSnapshot, ProviderError> {
        let records = self.read_records(record_name)?;
        Ok(ProviderSnapshot {
            record_name: record_name.to_owned(),
            records: records
                .into_iter()
                .map(|record| ProviderRecordSnapshot {
                    id: record.id,
                    name: record.name,
                    record_type: record.record_type,
                    proxied: record.proxied,
                })
                .collect(),
            origin_locked: self.origin.is_locked()?,
        })
    }

    fn request_proxy_enable(&mut self, record_name: &str) -> Result<(), ProviderError> {
        self.set_records_proxied(record_name, true)
    }

    fn verify_proxy_enabled(&mut self, record_name: &str) -> Result<bool, ProviderError> {
        if !self
            .read_records(record_name)?
            .iter()
            .all(|record| record.proxied)
        {
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
        let mut first_error = None;
        for previous in &snapshot.records {
            let target = self.allowed_records.iter().find(|target| {
                target.id == previous.id
                    && target.name.eq_ignore_ascii_case(&previous.name)
                    && target.record_type == previous.record_type
            });
            let result = target.map_or_else(
                || Err(ProviderError::RecordMismatch(previous.id.clone())),
                |target| self.set_record_proxied(target, previous.proxied),
            );
            if first_error.is_none()
                && let Err(error) = result
            {
                first_error = Some(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        let current = self.read_records(&snapshot.record_name)?;
        let record_matches = snapshot.records.iter().all(|previous| {
            current.iter().any(|record| {
                record.id == previous.id
                    && record.name.eq_ignore_ascii_case(&previous.name)
                    && record.record_type == previous.record_type
                    && record.proxied == previous.proxied
            })
        });
        let origin_matches = self.origin.is_locked()? == snapshot.origin_locked;
        if record_matches && origin_matches {
            Ok(())
        } else {
            Err(ProviderError::RecordMismatch(snapshot.record_name.clone()))
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
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct DnsRecord {
    id: String,
    name: String,
    #[serde(rename = "type")]
    record_type: DnsRecordType,
    proxied: bool,
    proxiable: bool,
}

#[derive(Debug, Deserialize)]
struct TokenVerifyResult {
    status: TokenStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum TokenStatus {
    Active,
    Disabled,
    Expired,
}

fn decode_response<T: DeserializeOwned>(
    response: reqwest::blocking::Response,
) -> Result<T, ProviderError> {
    let status = response.status();
    if !status.is_success() {
        return Err(http_status_error(status));
    }
    let envelope = response
        .json::<CloudflareEnvelope<T>>()
        .map_err(|_| ProviderError::Unavailable)?;
    if !envelope.success {
        return Err(ProviderError::Unavailable);
    }
    envelope.result.ok_or(ProviderError::Unavailable)
}

fn validate_record(
    target: &CloudflareRecordConfig,
    record: &DnsRecord,
) -> Result<(), ProviderError> {
    if record.id != target.id
        || !record.name.eq_ignore_ascii_case(&target.name)
        || record.record_type != target.record_type
        || !record.proxiable
    {
        return Err(ProviderError::RecordMismatch(target.id.clone()));
    }
    Ok(())
}

fn validate_configuration(
    zone_id: &str,
    records: &[CloudflareRecordConfig],
) -> Result<(), ProviderError> {
    if !is_cloudflare_identifier(zone_id) || records.is_empty() || records.len() > 16 {
        return Err(ProviderError::Configuration("ZONE_OR_RECORDS_INVALID"));
    }
    let first_name = &records[0].name;
    if records.iter().any(|record| {
        !is_cloudflare_identifier(&record.id)
            || !record.name.eq_ignore_ascii_case(first_name)
            || record.name.starts_with("*.")
            || record.name.contains('/')
            || record.name.contains(':')
    }) {
        return Err(ProviderError::Configuration("RECORD_ALLOWLIST_INVALID"));
    }
    Ok(())
}

fn is_cloudflare_identifier(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn cloudflare_secret_error(error: SecretFileError) -> ProviderError {
    ProviderError::SecretFile(match error {
        SecretFileError::CredentialDirectoryUnavailable => {
            "SYSTEMD_CREDENTIAL_DIRECTORY_UNAVAILABLE"
        }
        SecretFileError::CredentialNameInvalid => "CREDENTIAL_NAME_INVALID",
        SecretFileError::ReadFailed => "TOKEN_READ_FAILED",
        SecretFileError::NotRegularFile => "TOKEN_MUST_BE_REGULAR_FILE",
        SecretFileError::PermissionsTooOpen => "TOKEN_FILE_PERMISSIONS_MUST_BE_0600_OR_STRICTER",
        SecretFileError::FormatInvalid => "TOKEN_FORMAT_INVALID",
    })
}

fn http_status_error(status: StatusCode) -> ProviderError {
    match status {
        StatusCode::UNAUTHORIZED => ProviderError::AuthenticationFailed,
        StatusCode::FORBIDDEN => ProviderError::PermissionDenied,
        StatusCode::TOO_MANY_REQUESTS => ProviderError::RateLimited,
        status if status.is_server_error() => ProviderError::Unavailable,
        _ => ProviderError::Unavailable,
    }
}

fn http_error(_error: reqwest::Error) -> ProviderError {
    ProviderError::Unavailable
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use guard_core::config::{CloudflareRecordConfig, DnsRecordType};

    use super::{CloudflareBackend, OriginProtection};
    use crate::{ProviderBackend, ProviderError};
    use guard_system::resolve_credential_path;

    const ZONE_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const RECORD_ID: &str = "11111111111111111111111111111111";
    const TEST_TOKEN: &str = "test_token_abcdefghijklmnopqrstuvwxyz0123456789";

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
        fs::write(&path, TEST_TOKEN)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
        let result = CloudflareBackend::from_token_file(ZONE_ID, vec![target()], &path, FakeOrigin);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn accepts_root_only_token_file_without_network() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("token");
        fs::write(&path, TEST_TOKEN)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let backend =
            CloudflareBackend::from_token_file(ZONE_ID, vec![target()], &path, FakeOrigin);
        assert!(backend.is_ok());
        Ok(())
    }

    #[test]
    fn resolves_relative_token_only_from_systemd_credentials() {
        let resolved = resolve_credential_path(
            Path::new("cloudflare-token"),
            Some(Path::new("/run/credentials/vps-guard-control.service")),
        );
        assert_eq!(
            resolved,
            Ok(
                Path::new("/run/credentials/vps-guard-control.service/cloudflare-token")
                    .to_path_buf()
            )
        );
        assert!(resolve_credential_path(Path::new("cloudflare-token"), None).is_err());
        assert!(resolve_credential_path(Path::new("../token"), Some(Path::new("/run"))).is_err());
    }

    #[test]
    fn debug_output_redacts_token() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("token");
        fs::write(&path, TEST_TOKEN)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let backend =
            CloudflareBackend::from_token_file(ZONE_ID, vec![target()], &path, FakeOrigin)?;
        let debug = format!("{backend:?}");
        assert!(!debug.contains(TEST_TOKEN));
        assert!(debug.contains("REDACTED"));
        Ok(())
    }

    #[test]
    fn preflight_verifies_user_token_and_exact_record() -> Result<(), Box<dyn std::error::Error>> {
        let mut server = mockito::Server::new();
        let token_mock = server
            .mock("GET", "/user/tokens/verify")
            .match_header("authorization", format!("Bearer {TEST_TOKEN}").as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":true,"result":{"status":"active"}}"#)
            .create();
        let record_mock = server
            .mock(
                "GET",
                format!("/zones/{ZONE_ID}/dns_records/{RECORD_ID}").as_str(),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(record_body(false))
            .create();
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("token");
        fs::write(&path, TEST_TOKEN)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let backend = CloudflareBackend::from_token_file_with_api_base(
            ZONE_ID,
            vec![target()],
            &path,
            FakeOrigin,
            &server.url(),
        )?;
        backend.preflight()?;
        token_mock.assert();
        record_mock.assert();
        Ok(())
    }

    #[test]
    fn preflight_classifies_permission_denial() -> Result<(), Box<dyn std::error::Error>> {
        let mut server = mockito::Server::new();
        let token_mock = server
            .mock("GET", "/user/tokens/verify")
            .with_status(403)
            .create();
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("token");
        fs::write(&path, TEST_TOKEN)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let backend = CloudflareBackend::from_token_file_with_api_base(
            ZONE_ID,
            vec![target()],
            &path,
            FakeOrigin,
            &server.url(),
        )?;
        assert_eq!(backend.preflight(), Err(ProviderError::PermissionDenied));
        token_mock.assert();
        Ok(())
    }

    #[test]
    fn multi_record_failure_rolls_back_already_changed_records()
    -> Result<(), Box<dyn std::error::Error>> {
        const RECORD_ID_V6: &str = "22222222222222222222222222222222";
        let mut server = mockito::Server::new();
        let read_v4 = server
            .mock(
                "GET",
                format!("/zones/{ZONE_ID}/dns_records/{RECORD_ID}").as_str(),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(record_body_for(RECORD_ID, "A", false))
            .create();
        let read_v6 = server
            .mock(
                "GET",
                format!("/zones/{ZONE_ID}/dns_records/{RECORD_ID_V6}").as_str(),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(record_body_for(RECORD_ID_V6, "AAAA", false))
            .create();
        let enable_v4 = server
            .mock(
                "PATCH",
                format!("/zones/{ZONE_ID}/dns_records/{RECORD_ID}").as_str(),
            )
            .match_body(mockito::Matcher::JsonString(
                r#"{"proxied":true}"#.to_owned(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(record_body_for(RECORD_ID, "A", true))
            .create();
        let fail_v6 = server
            .mock(
                "PATCH",
                format!("/zones/{ZONE_ID}/dns_records/{RECORD_ID_V6}").as_str(),
            )
            .match_body(mockito::Matcher::JsonString(
                r#"{"proxied":true}"#.to_owned(),
            ))
            .with_status(500)
            .create();
        let rollback_v4 = server
            .mock(
                "PATCH",
                format!("/zones/{ZONE_ID}/dns_records/{RECORD_ID}").as_str(),
            )
            .match_body(mockito::Matcher::JsonString(
                r#"{"proxied":false}"#.to_owned(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(record_body_for(RECORD_ID, "A", false))
            .create();
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("token");
        fs::write(&path, TEST_TOKEN)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let mut backend = CloudflareBackend::from_token_file_with_api_base(
            ZONE_ID,
            vec![
                target(),
                CloudflareRecordConfig {
                    id: RECORD_ID_V6.to_owned(),
                    name: "example.com".to_owned(),
                    record_type: DnsRecordType::AAAA,
                },
            ],
            &path,
            FakeOrigin,
            &server.url(),
        )?;
        assert_eq!(
            backend.request_proxy_enable("example.com"),
            Err(ProviderError::Unavailable)
        );
        read_v4.assert();
        read_v6.assert();
        enable_v4.assert();
        fail_v6.assert();
        rollback_v4.assert();
        Ok(())
    }

    fn target() -> CloudflareRecordConfig {
        CloudflareRecordConfig {
            id: RECORD_ID.to_owned(),
            name: "example.com".to_owned(),
            record_type: DnsRecordType::A,
        }
    }

    fn record_body(proxied: bool) -> String {
        record_body_for(RECORD_ID, "A", proxied)
    }

    fn record_body_for(id: &str, record_type: &str, proxied: bool) -> String {
        format!(
            r#"{{"success":true,"result":{{"id":"{id}","name":"example.com","type":"{record_type}","proxied":{proxied},"proxiable":true}}}}"#
        )
    }
}
