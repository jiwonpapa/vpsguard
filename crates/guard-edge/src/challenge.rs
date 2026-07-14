//! client IP와 만료시각에 결합된 signed clearance cookie를 제공합니다.

use std::fs;
use std::net::IpAddr;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

const COOKIE_NAME: &str = "vps_guard_clearance";

/// clearance secret 로드 실패입니다.
#[derive(Debug, Error)]
pub enum ClearanceError {
    /// secret 파일을 읽지 못했습니다.
    #[error("clearance secret 읽기 실패: {0}")]
    Read(#[from] std::io::Error),
    /// secret 길이가 부족합니다.
    #[error("clearance secret은 최소 32 bytes여야 합니다")]
    WeakSecret,
}

/// signed clearance 발급·검증기입니다.
#[derive(Debug, Clone)]
pub struct ClearanceSigner {
    secret: Vec<u8>,
    ttl_seconds: u64,
}

impl ClearanceSigner {
    /// root-only 파일에서 서명 secret을 읽습니다.
    ///
    /// # Errors
    ///
    /// 파일을 읽지 못하거나 32 bytes보다 짧으면 실패합니다.
    pub fn from_file(path: &Path, ttl_seconds: u64) -> Result<Self, ClearanceError> {
        let secret = fs::read(path)?;
        Self::from_secret(secret, ttl_seconds)
    }

    /// 테스트와 secret provider용 생성자입니다.
    ///
    /// # Errors
    ///
    /// secret이 32 bytes보다 짧으면 실패합니다.
    pub fn from_secret(secret: Vec<u8>, ttl_seconds: u64) -> Result<Self, ClearanceError> {
        if secret.len() < 32 {
            return Err(ClearanceError::WeakSecret);
        }
        Ok(Self {
            secret,
            ttl_seconds,
        })
    }

    /// 현재 client에 대한 `Set-Cookie` 값을 만듭니다.
    #[must_use]
    pub fn issue_cookie(&self, client_ip: IpAddr, now_unix: u64, secure: bool) -> String {
        let expires = now_unix.saturating_add(self.ttl_seconds);
        let signature = self.signature(client_ip, expires).unwrap_or_default();
        let token = format!("v1.{expires}.{}", URL_SAFE_NO_PAD.encode(signature));
        let secure_attribute = if secure { "; Secure" } else { "" };
        format!(
            "{COOKIE_NAME}={token}; Max-Age={}; Path=/; HttpOnly; SameSite=Strict{secure_attribute}",
            self.ttl_seconds
        )
    }

    /// Cookie header의 clearance가 client와 현재 시각에 유효한지 확인합니다.
    #[must_use]
    pub fn verify_cookie(&self, header: Option<&str>, client_ip: IpAddr, now_unix: u64) -> bool {
        let Some(token) = header.and_then(find_cookie) else {
            return false;
        };
        let mut parts = token.split('.');
        if parts.next() != Some("v1") {
            return false;
        }
        let Some(expires) = parts.next().and_then(|value| value.parse::<u64>().ok()) else {
            return false;
        };
        let Some(encoded_signature) = parts.next() else {
            return false;
        };
        if parts.next().is_some() || expires <= now_unix {
            return false;
        }
        let Ok(signature) = URL_SAFE_NO_PAD.decode(encoded_signature) else {
            return false;
        };
        let Ok(mut mac) = HmacSha256::new_from_slice(&self.secret) else {
            return false;
        };
        mac.update(format!("{client_ip}|{expires}").as_bytes());
        mac.verify_slice(&signature).is_ok()
    }

    fn signature(
        &self,
        client_ip: IpAddr,
        expires: u64,
    ) -> Result<Vec<u8>, hmac::digest::InvalidLength> {
        let mut mac = HmacSha256::new_from_slice(&self.secret)?;
        mac.update(format!("{client_ip}|{expires}").as_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

fn find_cookie(header: &str) -> Option<&str> {
    header.split(';').find_map(|entry| {
        let (name, value) = entry.trim().split_once('=')?;
        (name == COOKIE_NAME).then_some(value)
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::ClearanceSigner;

    #[test]
    fn signed_cookie_is_bound_to_ip_and_expiry() -> Result<(), Box<dyn std::error::Error>> {
        let signer = ClearanceSigner::from_secret(vec![7; 32], 60)?;
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let cookie = signer.issue_cookie(ip, 100, true);
        assert!(signer.verify_cookie(Some(&cookie), ip, 120));
        assert!(!signer.verify_cookie(Some(&cookie), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 120));
        assert!(!signer.verify_cookie(Some(&cookie), ip, 161));
        Ok(())
    }
}
