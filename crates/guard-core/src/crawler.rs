//! 검색 crawler identity와 declared bot 정책의 순수 판정을 제공합니다.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// 관리자가 허용할 수 있는 검색 crawler provider입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrawlerProvider {
    /// Googlebot입니다.
    Google,
    /// Bingbot입니다.
    Bing,
    /// Naver Yeti입니다.
    Naver,
}

impl CrawlerProvider {
    /// telemetry·저장소에서 사용하는 bounded provider code입니다.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Bing => "bing",
            Self::Naver => "naver",
        }
    }
}

/// provider 공식 feed에서 가져온 crawler network 목록입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrawlerNetwork {
    /// network 소유 provider입니다.
    pub provider: CrawlerProvider,
    /// 공식 IPv4·IPv6 CIDR입니다.
    pub cidrs: Vec<IpNet>,
}

/// install-time에 공식 endpoint에서 갱신해 pin한 crawler network 파일입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedCrawlerNetworks {
    /// file contract 버전입니다.
    pub schema_version: u32,
    /// source feed 중 가장 최신 생성 시각입니다.
    pub generated_at: String,
    /// provider별 공식 source URL입니다.
    pub sources: BTreeMap<String, String>,
    /// provider별 CIDR입니다.
    pub networks: Vec<CrawlerNetwork>,
}

/// 요청 User-Agent와 source IP에 대한 declared bot 판정입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclaredBotDisposition {
    /// bot을 명시하지 않은 요청입니다.
    Undeclared,
    /// 허용 provider의 공식 network에서 온 검색 crawler입니다.
    VerifiedCrawler(CrawlerProvider),
    /// 검색 crawler UA를 사용했지만 identity가 검증되지 않았습니다.
    SpoofedCrawler(CrawlerProvider),
    /// 관리자 allowlist 밖의 AI·scraper·crawler UA입니다.
    UnapprovedDeclaredBot,
}

/// traffic telemetry에 저장하는 bounded bot 분류입니다.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BotClass {
    /// bot임을 선언하지 않은 요청입니다.
    #[default]
    Undeclared,
    /// 공식 source identity가 확인된 검색 crawler입니다.
    VerifiedCrawler,
    /// 검색 crawler UA를 사용했지만 source identity가 일치하지 않습니다.
    SpoofedCrawler,
    /// 관리자 allowlist 밖의 선언형 AI bot·scraper입니다.
    UnapprovedDeclaredBot,
}

impl BotClass {
    /// SQLite와 API에 사용하는 안정 code입니다.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Undeclared => "undeclared",
            Self::VerifiedCrawler => "verified_crawler",
            Self::SpoofedCrawler => "spoofed_crawler",
            Self::UnapprovedDeclaredBot => "unapproved_declared_bot",
        }
    }
}

/// declared bot 판정의 bounded 설명 code입니다.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BotReason {
    /// 선언형 bot 신호가 없습니다.
    #[default]
    NotDeclared,
    /// 공식 crawler network와 source IP가 일치했습니다.
    OfficialNetworkMatch,
    /// crawler UA와 공식 source identity가 일치하지 않았습니다.
    OfficialNetworkMismatch,
    /// allowlist 밖의 선언형 자동화 UA입니다.
    UnapprovedUserAgent,
}

impl BotReason {
    /// SQLite와 API에 사용하는 안정 code입니다.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotDeclared => "not_declared",
            Self::OfficialNetworkMatch => "official_network_match",
            Self::OfficialNetworkMismatch => "official_network_mismatch",
            Self::UnapprovedUserAgent => "unapproved_user_agent",
        }
    }
}

/// 원문 User-Agent를 저장하지 않는 bounded family입니다.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserAgentFamily {
    /// User-Agent가 없었습니다.
    #[default]
    Missing,
    /// Google crawler 계열입니다.
    Googlebot,
    /// Bing crawler 계열입니다.
    Bingbot,
    /// Naver crawler 계열입니다.
    Naver,
    /// allowlist 밖의 선언형 자동화 client입니다.
    DeclaredAutomation,
    /// Chromium Chrome 계열입니다.
    Chrome,
    /// Microsoft Edge 계열입니다.
    Edge,
    /// Firefox 계열입니다.
    Firefox,
    /// Safari 계열입니다.
    Safari,
    /// curl 계열입니다.
    Curl,
    /// wget 계열입니다.
    Wget,
    /// 알려지지 않은 family입니다.
    Other,
}

impl UserAgentFamily {
    /// SQLite와 API에 사용하는 안정 code입니다.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Googlebot => "googlebot",
            Self::Bingbot => "bingbot",
            Self::Naver => "naver",
            Self::DeclaredAutomation => "declared_automation",
            Self::Chrome => "chrome",
            Self::Edge => "edge",
            Self::Firefox => "firefox",
            Self::Safari => "safari",
            Self::Curl => "curl",
            Self::Wget => "wget",
            Self::Other => "other",
        }
    }
}

impl DeclaredBotDisposition {
    /// enforcement에서 거부해야 하는 판정인지 반환합니다.
    #[must_use]
    pub const fn blocked(self) -> bool {
        matches!(self, Self::SpoofedCrawler(_) | Self::UnapprovedDeclaredBot)
    }

    /// 저장·집계할 bounded bot class입니다.
    #[must_use]
    pub const fn class(self) -> BotClass {
        match self {
            Self::Undeclared => BotClass::Undeclared,
            Self::VerifiedCrawler(_) => BotClass::VerifiedCrawler,
            Self::SpoofedCrawler(_) => BotClass::SpoofedCrawler,
            Self::UnapprovedDeclaredBot => BotClass::UnapprovedDeclaredBot,
        }
    }

    /// 검색 crawler provider가 있으면 반환합니다.
    #[must_use]
    pub const fn provider(self) -> Option<CrawlerProvider> {
        match self {
            Self::VerifiedCrawler(provider) | Self::SpoofedCrawler(provider) => Some(provider),
            Self::Undeclared | Self::UnapprovedDeclaredBot => None,
        }
    }

    /// 공식 source identity 확인 여부입니다.
    #[must_use]
    pub const fn verified(self) -> bool {
        matches!(self, Self::VerifiedCrawler(_))
    }

    /// 판정에 대응하는 안정 reason입니다.
    #[must_use]
    pub const fn reason(self) -> BotReason {
        match self {
            Self::Undeclared => BotReason::NotDeclared,
            Self::VerifiedCrawler(_) => BotReason::OfficialNetworkMatch,
            Self::SpoofedCrawler(_) => BotReason::OfficialNetworkMismatch,
            Self::UnapprovedDeclaredBot => BotReason::UnapprovedUserAgent,
        }
    }
}

/// 원문을 보존하지 않고 User-Agent family만 분류합니다.
#[must_use]
pub fn user_agent_family(
    user_agent: Option<&str>,
    disposition: DeclaredBotDisposition,
) -> UserAgentFamily {
    match disposition {
        DeclaredBotDisposition::VerifiedCrawler(CrawlerProvider::Google)
        | DeclaredBotDisposition::SpoofedCrawler(CrawlerProvider::Google) => {
            return UserAgentFamily::Googlebot;
        }
        DeclaredBotDisposition::VerifiedCrawler(CrawlerProvider::Bing)
        | DeclaredBotDisposition::SpoofedCrawler(CrawlerProvider::Bing) => {
            return UserAgentFamily::Bingbot;
        }
        DeclaredBotDisposition::VerifiedCrawler(CrawlerProvider::Naver)
        | DeclaredBotDisposition::SpoofedCrawler(CrawlerProvider::Naver) => {
            return UserAgentFamily::Naver;
        }
        DeclaredBotDisposition::UnapprovedDeclaredBot => {
            return UserAgentFamily::DeclaredAutomation;
        }
        DeclaredBotDisposition::Undeclared => {}
    }
    let Some(normalized) = user_agent.map(str::to_ascii_lowercase) else {
        return UserAgentFamily::Missing;
    };
    if normalized.contains("edg/") || normalized.contains("edge/") {
        UserAgentFamily::Edge
    } else if normalized.contains("chrome/") || normalized.contains("chromium/") {
        UserAgentFamily::Chrome
    } else if normalized.contains("firefox/") {
        UserAgentFamily::Firefox
    } else if normalized.contains("safari/") && normalized.contains("version/") {
        UserAgentFamily::Safari
    } else if normalized.contains("curl/") {
        UserAgentFamily::Curl
    } else if normalized.contains("wget/") {
        UserAgentFamily::Wget
    } else {
        UserAgentFamily::Other
    }
}

/// 선언된 검색·AI bot UA를 source identity와 함께 판정합니다.
///
/// 브라우저로 위장한 bot은 이 함수만으로 판정하지 않고 계층 rate limit과
/// 행동·resource cost 신호가 담당합니다.
#[must_use]
pub fn declared_bot_disposition(
    user_agent: Option<&str>,
    client_ip: Option<IpAddr>,
    allowed_crawlers: &[CrawlerProvider],
    networks: &[CrawlerNetwork],
) -> DeclaredBotDisposition {
    let Some(user_agent) = user_agent else {
        return DeclaredBotDisposition::Undeclared;
    };
    let normalized = user_agent.to_ascii_lowercase();
    let provider =
        if normalized.contains("googlebot") || normalized.contains("google-inspectiontool") {
            Some(CrawlerProvider::Google)
        } else if normalized.contains("bingbot") {
            Some(CrawlerProvider::Bing)
        } else if normalized.contains("yeti/")
            || normalized.contains("ads-naver")
            || normalized.contains("blueno")
        {
            Some(CrawlerProvider::Naver)
        } else {
            None
        };
    if let Some(provider) = provider {
        let verified = allowed_crawlers.contains(&provider)
            && client_ip.is_some_and(|address| {
                networks.iter().any(|entry| {
                    entry.provider == provider
                        && entry.cidrs.iter().any(|network| network.contains(&address))
                })
            });
        return if verified {
            DeclaredBotDisposition::VerifiedCrawler(provider)
        } else {
            DeclaredBotDisposition::SpoofedCrawler(provider)
        };
    }
    const UNAPPROVED_TOKENS: &[&str] = &[
        "gptbot",
        "chatgpt-user",
        "claudebot",
        "claude-web",
        "anthropic-ai",
        "meta-externalagent",
        "facebookexternalhit",
        "bytespider",
        "ccbot",
        "perplexitybot",
        "amazonbot",
        "applebot-extended",
        "cohere-ai",
        "diffbot",
        "scrapy",
        "crawler",
        "spider",
        "headless",
    ];
    if UNAPPROVED_TOKENS
        .iter()
        .any(|token| normalized.contains(token))
        || normalized
            .split(|character: char| !character.is_ascii_alphanumeric())
            .any(|token| token.ends_with("bot") && token.len() > 3)
    {
        DeclaredBotDisposition::UnapprovedDeclaredBot
    } else {
        DeclaredBotDisposition::Undeclared
    }
}

/// crawler identity를 확정한 방식입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMethod {
    /// provider 공식 CIDR feed와 일치했습니다.
    OfficialCidr,
    /// provider suffix reverse DNS를 다시 forward lookup해 원 IP를 확인했습니다.
    ForwardConfirmedReverseDns,
}

/// crawler 검증 결과 reason입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationReason {
    /// 공식 CIDR가 일치했습니다.
    OfficialNetworkMatch,
    /// reverse·forward DNS가 모두 일치했습니다.
    ForwardConfirmedName,
    /// provider domain suffix가 아니었습니다.
    ReverseNameMismatch,
    /// forward lookup이 원 IP를 포함하지 않았습니다.
    ForwardAddressMismatch,
    /// 확인할 DNS 결과와 공식 CIDR가 없었습니다.
    EvidenceUnavailable,
}

/// control-plane DNS/cache adapter가 순수 verifier에 제공할 입력입니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlerVerificationInput {
    /// 검증 대상 provider입니다.
    pub provider: CrawlerProvider,
    /// 실제 source IP입니다.
    pub client_ip: IpAddr,
    /// provider 공식 feed에서 검증해 읽은 CIDR입니다.
    pub official_networks: Vec<IpNet>,
    /// PTR lookup 결과입니다.
    pub reverse_names: Vec<String>,
    /// 각 PTR hostname의 A·AAAA 결과입니다.
    pub forward_addresses: Vec<IpAddr>,
    /// cache 만료 UNIX seconds입니다.
    pub expires_at_unix: u64,
}

/// edge policy에 넣을 수 있는 설명 가능한 crawler 검증 결과입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrawlerVerification {
    /// provider입니다.
    pub provider: CrawlerProvider,
    /// 검증 성공 여부입니다.
    pub verified: bool,
    /// 성공 method입니다.
    pub method: Option<VerificationMethod>,
    /// 판정 reason입니다.
    pub reason: VerificationReason,
    /// cache 만료 UNIX seconds입니다.
    pub expires_at_unix: u64,
}

/// 공식 CIDR 또는 forward-confirmed reverse DNS로 crawler를 판정합니다.
#[must_use]
pub fn verify_crawler(input: &CrawlerVerificationInput) -> CrawlerVerification {
    if input
        .official_networks
        .iter()
        .any(|network| network.contains(&input.client_ip))
    {
        return verification(
            input,
            true,
            Some(VerificationMethod::OfficialCidr),
            VerificationReason::OfficialNetworkMatch,
        );
    }
    if input.reverse_names.is_empty() {
        return verification(input, false, None, VerificationReason::EvidenceUnavailable);
    }
    if !input
        .reverse_names
        .iter()
        .any(|name| provider_hostname(input.provider, name))
    {
        return verification(input, false, None, VerificationReason::ReverseNameMismatch);
    }
    if !input.forward_addresses.contains(&input.client_ip) {
        return verification(
            input,
            false,
            None,
            VerificationReason::ForwardAddressMismatch,
        );
    }
    verification(
        input,
        true,
        Some(VerificationMethod::ForwardConfirmedReverseDns),
        VerificationReason::ForwardConfirmedName,
    )
}

fn verification(
    input: &CrawlerVerificationInput,
    verified: bool,
    method: Option<VerificationMethod>,
    reason: VerificationReason,
) -> CrawlerVerification {
    CrawlerVerification {
        provider: input.provider,
        verified,
        method,
        reason,
        expires_at_unix: input.expires_at_unix,
    }
}

fn provider_hostname(provider: CrawlerProvider, hostname: &str) -> bool {
    let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
    let suffixes: &[&str] = match provider {
        CrawlerProvider::Google => &["googlebot.com", "google.com", "googleusercontent.com"],
        CrawlerProvider::Bing => &["search.msn.com"],
        CrawlerProvider::Naver => &["naver.com"],
    };
    suffixes.iter().any(|suffix| {
        hostname == *suffix
            || hostname
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_cidr_and_forward_confirmed_dns_verify() -> Result<(), Box<dyn std::error::Error>> {
        let cidr = CrawlerVerificationInput {
            provider: CrawlerProvider::Google,
            client_ip: "66.249.66.1".parse()?,
            official_networks: vec!["66.249.64.0/19".parse()?],
            reverse_names: Vec::new(),
            forward_addresses: Vec::new(),
            expires_at_unix: 1_800_000_000,
        };
        assert_eq!(
            verify_crawler(&cidr).method,
            Some(VerificationMethod::OfficialCidr)
        );
        let naver = CrawlerVerificationInput {
            provider: CrawlerProvider::Naver,
            client_ip: "125.209.235.169".parse()?,
            official_networks: Vec::new(),
            reverse_names: vec!["crawl.125-209-235-169.web.naver.com.".to_owned()],
            forward_addresses: vec!["125.209.235.169".parse()?],
            expires_at_unix: 1_800_000_000,
        };
        assert!(verify_crawler(&naver).verified);
        Ok(())
    }

    #[test]
    fn suffix_spoof_and_forward_mismatch_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let spoofed = CrawlerVerificationInput {
            provider: CrawlerProvider::Google,
            client_ip: "192.0.2.10".parse()?,
            official_networks: Vec::new(),
            reverse_names: vec!["googlebot.com.attacker.example".to_owned()],
            forward_addresses: vec!["192.0.2.10".parse()?],
            expires_at_unix: 1_800_000_000,
        };
        assert_eq!(
            verify_crawler(&spoofed).reason,
            VerificationReason::ReverseNameMismatch
        );
        let forward_mismatch = CrawlerVerificationInput {
            reverse_names: vec!["crawl-1.googlebot.com".to_owned()],
            forward_addresses: vec!["192.0.2.11".parse()?],
            ..spoofed
        };
        assert_eq!(
            verify_crawler(&forward_mismatch).reason,
            VerificationReason::ForwardAddressMismatch
        );
        Ok(())
    }

    #[test]
    fn declared_search_bot_requires_allowed_official_network()
    -> Result<(), Box<dyn std::error::Error>> {
        let networks = vec![CrawlerNetwork {
            provider: CrawlerProvider::Google,
            cidrs: vec!["66.249.64.0/19".parse()?],
        }];
        assert_eq!(
            declared_bot_disposition(
                Some("Mozilla/5.0 Googlebot/2.1"),
                Some("66.249.66.1".parse()?),
                &[CrawlerProvider::Google],
                &networks,
            ),
            DeclaredBotDisposition::VerifiedCrawler(CrawlerProvider::Google)
        );
        assert_eq!(
            declared_bot_disposition(
                Some("Mozilla/5.0 Googlebot/2.1"),
                Some("192.0.2.10".parse()?),
                &[CrawlerProvider::Google],
                &networks,
            ),
            DeclaredBotDisposition::SpoofedCrawler(CrawlerProvider::Google)
        );
        Ok(())
    }

    #[test]
    fn declared_ai_bots_are_unapproved_but_browser_is_undeclared() {
        assert_eq!(
            declared_bot_disposition(Some("meta-externalagent/1.1"), None, &[], &[]),
            DeclaredBotDisposition::UnapprovedDeclaredBot
        );
        assert_eq!(
            declared_bot_disposition(
                Some("Mozilla/5.0 AppleWebKit/537.36 Chrome/126.0"),
                None,
                &[],
                &[],
            ),
            DeclaredBotDisposition::Undeclared
        );
    }

    #[test]
    fn declared_bot_metadata_and_user_agent_family_are_bounded() {
        let verified = DeclaredBotDisposition::VerifiedCrawler(CrawlerProvider::Google);
        assert_eq!(verified.class(), BotClass::VerifiedCrawler);
        assert_eq!(verified.provider(), Some(CrawlerProvider::Google));
        assert!(verified.verified());
        assert_eq!(verified.reason(), BotReason::OfficialNetworkMatch);
        assert_eq!(
            user_agent_family(Some("Googlebot/2.1"), verified),
            UserAgentFamily::Googlebot
        );

        let chrome = user_agent_family(
            Some("Mozilla/5.0 Chrome/126.0 Safari/537.36"),
            DeclaredBotDisposition::Undeclared,
        );
        assert_eq!(chrome, UserAgentFamily::Chrome);
        assert_eq!(
            user_agent_family(None, DeclaredBotDisposition::Undeclared),
            UserAgentFamily::Missing
        );
    }
}
