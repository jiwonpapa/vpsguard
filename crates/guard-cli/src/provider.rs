//! 변경 능력이 없는 Cloudflare 사전 점검 CLI입니다.

use std::path::PathBuf;

use clap::Subcommand;
use guard_provider::ProviderError;
use guard_provider::cloudflare::{CloudflareBackend, CloudflarePreflightReport, OriginProtection};

use super::{CliError, read_config};

/// Provider별 변경 없는 점검 명령입니다.
#[derive(Debug, Subcommand)]
pub(super) enum ProviderCommand {
    /// Cloudflare token과 격리 DNS record를 변경 없이 read-back합니다.
    CloudflarePreflight {
        /// 실제 provider 설정이 포함된 versioned config입니다.
        #[arg(short, long)]
        config: PathBuf,
        /// 오타·다른 zone 방지를 위해 다시 입력하는 정확한 test hostname입니다.
        #[arg(long)]
        expected_hostname: String,
        /// 운영 hostname 등 절대 허용하지 않을 이름입니다.
        #[arg(long, required = true)]
        forbid_hostname: Vec<String>,
        /// 격리 test hostname의 필수 prefix입니다.
        #[arg(long)]
        required_hostname_prefix: String,
    },
}

/// Provider 사전 점검을 실행하고 비밀 없는 JSON을 반환합니다.
pub(super) fn execute(command: ProviderCommand) -> Result<String, CliError> {
    match command {
        ProviderCommand::CloudflarePreflight {
            config,
            expected_hostname,
            forbid_hostname,
            required_hostname_prefix,
        } => {
            let parsed = read_config(&config)?;
            let provider = &parsed.cloudflare;
            if !provider.enabled {
                return Err(CliError::CloudflareDisabled);
            }
            let configured_hostname = provider
                .records
                .first()
                .map(|record| record.name.as_str())
                .ok_or(ProviderError::Configuration("RECORD_ALLOWLIST_EMPTY"))?;
            validate_test_hostname(
                configured_hostname,
                &expected_hostname,
                &forbid_hostname,
                &required_hostname_prefix,
            )?;
            let backend = CloudflareBackend::from_token_file(
                provider.zone_id.clone(),
                provider.records.clone(),
                &provider.token_file,
                ReadOnlyOrigin,
            )?;
            let report = backend.preflight_report()?;
            validate_report(&report, provider.max_dns_ttl_seconds)?;
            serde_json::to_string_pretty(&report).map_err(CliError::Json)
        }
    }
}

fn validate_test_hostname(
    configured: &str,
    expected: &str,
    forbidden: &[String],
    required_prefix: &str,
) -> Result<(), CliError> {
    if !configured.eq_ignore_ascii_case(expected) {
        return Err(CliError::CloudflareHostnameMismatch {
            configured: configured.to_owned(),
            expected: expected.to_owned(),
        });
    }
    if forbidden.is_empty() {
        return Err(CliError::CloudflareIsolationContractInvalid);
    }
    if forbidden
        .iter()
        .any(|hostname| configured.eq_ignore_ascii_case(hostname))
    {
        return Err(CliError::CloudflareHostnameForbidden(configured.to_owned()));
    }
    let normalized_prefix = required_prefix.to_ascii_lowercase();
    if !normalized_prefix.starts_with("vpsguard-")
        || !normalized_prefix.ends_with('.')
        || !configured
            .to_ascii_lowercase()
            .starts_with(&normalized_prefix)
    {
        return Err(CliError::CloudflareHostnamePrefixMissing {
            hostname: configured.to_owned(),
            prefix: required_prefix.to_owned(),
        });
    }
    Ok(())
}

fn validate_report(
    report: &CloudflarePreflightReport,
    max_dns_ttl_seconds: u32,
) -> Result<(), CliError> {
    if !report.all_dns_only {
        return Err(CliError::CloudflareDnsOnlyRequired);
    }
    if report.max_effective_ttl_seconds > max_dns_ttl_seconds {
        return Err(ProviderError::DnsTtlTooHigh {
            observed_seconds: report.max_effective_ttl_seconds,
            allowed_seconds: max_dns_ttl_seconds,
        }
        .into());
    }
    Ok(())
}

#[derive(Debug)]
struct ReadOnlyOrigin;

impl OriginProtection for ReadOnlyOrigin {
    fn is_locked(&mut self) -> Result<bool, ProviderError> {
        Err(read_only_origin_error())
    }

    fn lock(&mut self) -> Result<(), ProviderError> {
        Err(read_only_origin_error())
    }

    fn restore(&mut self, _locked: bool) -> Result<(), ProviderError> {
        Err(read_only_origin_error())
    }
}

fn read_only_origin_error() -> ProviderError {
    ProviderError::Backend("READ_ONLY_PREFLIGHT_HAS_NO_ORIGIN_CAPABILITY".to_owned())
}

#[cfg(test)]
mod tests {
    use guard_core::config::DnsRecordType;
    use guard_provider::ProviderError;
    use guard_provider::cloudflare::{CloudflarePreflightRecord, CloudflarePreflightReport};

    use super::{validate_report, validate_test_hostname};
    use crate::CliError;

    #[test]
    fn preflight_requires_exact_isolated_hostname() {
        let forbidden = vec!["g7devops.com".to_owned(), "www.g7devops.com".to_owned()];
        assert!(
            validate_test_hostname(
                "vpsguard-test.g7devops.com",
                "vpsguard-test.g7devops.com",
                &forbidden,
                "vpsguard-test."
            )
            .is_ok()
        );
        assert!(matches!(
            validate_test_hostname(
                "www.g7devops.com",
                "www.g7devops.com",
                &forbidden,
                "vpsguard-test."
            ),
            Err(CliError::CloudflareHostnameForbidden(_))
        ));
        assert!(matches!(
            validate_test_hostname(
                "staging.g7devops.com",
                "staging.g7devops.com",
                &forbidden,
                "vpsguard-test."
            ),
            Err(CliError::CloudflareHostnamePrefixMissing { .. })
        ));
        assert!(matches!(
            validate_test_hostname(
                "vpsguard-test.g7devops.com",
                "vpsguard-test.g7devops.com",
                &[],
                "vpsguard-test."
            ),
            Err(CliError::CloudflareIsolationContractInvalid)
        ));
    }

    #[test]
    fn preflight_rejects_proxied_or_excess_ttl_state() {
        let mut report = CloudflarePreflightReport {
            schema_version: 1,
            hostname: "vpsguard-test.example.com".to_owned(),
            record_count: 1,
            all_dns_only: false,
            max_effective_ttl_seconds: 300,
            records: vec![CloudflarePreflightRecord {
                id: "1".repeat(32),
                name: "vpsguard-test.example.com".to_owned(),
                record_type: DnsRecordType::A,
                proxied: true,
                ttl_seconds: 1,
                effective_ttl_seconds: 300,
            }],
        };
        assert!(matches!(
            validate_report(&report, 300),
            Err(CliError::CloudflareDnsOnlyRequired)
        ));
        report.all_dns_only = true;
        report.max_effective_ttl_seconds = 600;
        assert!(matches!(
            validate_report(&report, 300),
            Err(CliError::Provider(ProviderError::DnsTtlTooHigh { .. }))
        ));
    }
}
