//! Root helper가 소유하는 PAM 관리자 TOTP 등록·봉인·복구 코드 저장소입니다.
#![cfg_attr(not(any(test, target_os = "linux")), allow(dead_code, unused_imports))]

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use totp_rs::{Algorithm, Secret, TOTP};

const STORE_SCHEMA_VERSION: u32 = 1;
const ENROLLMENT_TTL_SECONDS: i64 = 10 * 60;
const TOTP_SECRET_BYTES: usize = 20;
const MASTER_KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const RECOVERY_CODE_COUNT: usize = 10;
const KEY_FILE_NAME: &str = ".credential-key";
const ENROLLMENT_CONTEXT: &[u8] = b"vpsguard-pam-enrollment-v1";
const AEAD_KEY_CONTEXT: &[u8] = b"vpsguard-pam-aead-key-v1";
const RECOVERY_KEY_CONTEXT: &[u8] = b"vpsguard-pam-recovery-key-v1";

type HmacSha256 = Hmac<Sha256>;

/// PAM 두 번째 인증 factor 종류입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PamMfaMethod {
    /// RFC 6238 6자리 TOTP입니다.
    Totp,
    /// 한 번 소비되는 복구 코드입니다.
    Recovery,
}

/// PAM 관리자 최초 등록 시작 응답입니다.
///
/// TOTP 원문을 포함하므로 `Debug`를 구현하지 않습니다.
pub(crate) struct PamMfaEnrollmentStart {
    pub(crate) enrollment_id: String,
    pub(crate) secret_base32: String,
    pub(crate) otpauth_uri: String,
    pub(crate) expires_in_seconds: u64,
}

/// PAM 관리자 최초 등록 완료 응답입니다.
///
/// 복구 코드 원문을 포함하므로 `Debug`를 구현하지 않습니다.
pub(crate) struct PamMfaEnrollmentComplete {
    pub(crate) actor: String,
    pub(crate) recovery_codes: Vec<String>,
}

/// PAM MFA credential 처리 실패입니다.
#[derive(Debug, Error)]
pub(crate) enum PamMfaError {
    /// 저장소 I/O 또는 권한 검증 실패입니다.
    #[error("PAM MFA credential 저장소를 사용할 수 없습니다")]
    Storage,
    /// 암호 연산 또는 CSPRNG 실패입니다.
    #[error("PAM MFA credential 암호 연산에 실패했습니다")]
    Crypto,
    /// 안전하지 않은 Unix 사용자 이름입니다.
    #[error("PAM MFA 사용자 이름이 올바르지 않습니다")]
    InvalidUsername,
    /// 최초 PAM 관리자가 이미 등록됐습니다.
    #[error("PAM MFA 관리자가 이미 등록됐습니다")]
    AlreadyConfigured,
    /// 등록 session이 없거나 만료됐습니다.
    #[error("PAM MFA 등록 session이 없거나 만료됐습니다")]
    EnrollmentUnavailable,
    /// 등록 확인 TOTP가 올바르지 않습니다.
    #[error("PAM MFA 등록 TOTP가 올바르지 않습니다")]
    InvalidTotp,
    /// 해당 PAM 사용자에게 MFA가 등록되지 않았습니다.
    #[error("PAM MFA credential이 등록되지 않았습니다")]
    NotConfigured,
    /// TOTP 또는 복구 코드가 올바르지 않습니다.
    #[error("PAM MFA 인증값이 올바르지 않습니다")]
    InvalidFactor,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedCredential {
    schema_version: u32,
    username: String,
    nonce: String,
    ciphertext: String,
    recovery_digests: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialPayload {
    secret_base32: String,
}

struct PendingEnrollment {
    enrollment_digest: [u8; 32],
    username: String,
    secret_base32: SecretString,
    recovery_codes: Vec<SecretString>,
    expires_at: i64,
}

/// root-only key와 per-user 봉인 credential을 관리합니다.
pub(crate) struct PamMfaManager {
    directory: PathBuf,
    pending: Mutex<Option<PendingEnrollment>>,
    credential_gate: Mutex<()>,
}

impl PamMfaManager {
    /// 운영 root-only 저장소를 사용합니다.
    #[must_use]
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn system() -> Self {
        Self::at(PathBuf::from("/var/lib/vps-guard/pam"))
    }

    /// 지정 저장소를 사용합니다.
    #[must_use]
    pub(crate) fn at(directory: PathBuf) -> Self {
        Self {
            directory,
            pending: Mutex::new(None),
            credential_gate: Mutex::new(()),
        }
    }

    /// 유효한 봉인 credential이 하나도 없으면 최초 등록이 필요합니다.
    pub(crate) fn setup_required(&self) -> Result<bool, PamMfaError> {
        if !self.directory.exists() {
            return Ok(true);
        }
        validate_directory(&self.directory)?;
        for entry in fs::read_dir(&self.directory).map_err(|_| PamMfaError::Storage)? {
            let entry = entry.map_err(|_| PamMfaError::Storage)?;
            let path = entry.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                let credential = read_credential(&path)?;
                validate_username(&credential.username)?;
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// 비밀번호·계정·group 검증 뒤 호출해 최초 TOTP 등록을 시작합니다.
    pub(crate) fn start_enrollment(
        &self,
        username: String,
        now: i64,
    ) -> Result<PamMfaEnrollmentStart, PamMfaError> {
        validate_username(&username)?;
        if !self.setup_required()? {
            return Err(PamMfaError::AlreadyConfigured);
        }
        let secret = random_bytes::<TOTP_SECRET_BYTES>()?;
        let totp = build_totp(&username, secret.to_vec())?;
        let secret_base32 = totp.get_secret_base32();
        let enrollment_id = URL_SAFE_NO_PAD.encode(random_bytes::<32>()?);
        let enrollment_digest = digest(ENROLLMENT_CONTEXT, enrollment_id.as_bytes());
        let recovery_codes = generate_recovery_codes()?
            .into_iter()
            .map(SecretString::from)
            .collect();
        *self.lock_pending() = Some(PendingEnrollment {
            enrollment_digest,
            username,
            secret_base32: SecretString::from(secret_base32.clone()),
            recovery_codes,
            expires_at: now.saturating_add(ENROLLMENT_TTL_SECONDS),
        });
        Ok(PamMfaEnrollmentStart {
            enrollment_id,
            secret_base32,
            otpauth_uri: totp.get_url(),
            expires_in_seconds: u64::try_from(ENROLLMENT_TTL_SECONDS).unwrap_or(600),
        })
    }

    /// TOTP를 확인하고 seed를 봉인한 뒤 복구 코드를 한 번 반환합니다.
    pub(crate) fn confirm_enrollment(
        &self,
        enrollment_id: &str,
        totp_code: &str,
        now: i64,
    ) -> Result<PamMfaEnrollmentComplete, PamMfaError> {
        if !valid_totp_shape(totp_code) {
            return Err(PamMfaError::InvalidTotp);
        }
        let mut slot = self.lock_pending();
        let Some(pending) = slot.as_ref() else {
            return Err(PamMfaError::EnrollmentUnavailable);
        };
        if pending.expires_at <= now
            || !digest_matches(
                ENROLLMENT_CONTEXT,
                enrollment_id.as_bytes(),
                &pending.enrollment_digest,
            )
        {
            if pending.expires_at <= now {
                *slot = None;
            }
            return Err(PamMfaError::EnrollmentUnavailable);
        }
        let secret = Secret::Encoded(pending.secret_base32.expose_secret().to_owned())
            .to_bytes()
            .map_err(|_| PamMfaError::Crypto)?;
        let timestamp = u64::try_from(now).map_err(|_| PamMfaError::Crypto)?;
        if !build_totp(&pending.username, secret)?.check(totp_code, timestamp) {
            return Err(PamMfaError::InvalidTotp);
        }
        ensure_directory(&self.directory)?;
        let key = load_or_create_key(&self.directory)?;
        let recovery_codes = pending
            .recovery_codes
            .iter()
            .map(|code| code.expose_secret().to_owned())
            .collect::<Vec<_>>();
        let recovery_digests = recovery_codes
            .iter()
            .map(|code| {
                let normalized = normalize_recovery_code(code).ok_or(PamMfaError::Crypto)?;
                recovery_digest(&key, &pending.username, &normalized)
                    .map(|digest| URL_SAFE_NO_PAD.encode(digest))
            })
            .collect::<Result<Vec<_>, PamMfaError>>()?;
        let credential = seal_credential(
            &key,
            &pending.username,
            pending.secret_base32.expose_secret(),
            recovery_digests,
        )?;
        write_credential(&self.directory, &credential)?;
        let actor = pending.username.clone();
        *slot = None;
        Ok(PamMfaEnrollmentComplete {
            actor,
            recovery_codes,
        })
    }

    /// 봉인 credential에서 TOTP 또는 일회용 복구 코드를 검증합니다.
    pub(crate) fn verify(
        &self,
        username: &str,
        factor: &str,
        now: i64,
    ) -> Result<PamMfaMethod, PamMfaError> {
        validate_username(username)?;
        let _credential_lease = self.lock_credential_gate();
        validate_directory(&self.directory)?;
        let key = load_existing_key(&self.directory)?;
        let path = credential_path(&self.directory, username)?;
        if !path.exists() {
            return Err(PamMfaError::NotConfigured);
        }
        let mut credential = read_credential(&path)?;
        if credential.username != username || credential.schema_version != STORE_SCHEMA_VERSION {
            return Err(PamMfaError::Storage);
        }
        let payload = open_credential(&key, &credential)?;
        if valid_totp_shape(factor) {
            let secret = Secret::Encoded(payload.secret_base32)
                .to_bytes()
                .map_err(|_| PamMfaError::Storage)?;
            let timestamp = u64::try_from(now).map_err(|_| PamMfaError::Crypto)?;
            if build_totp(username, secret)?.check(factor, timestamp) {
                return Ok(PamMfaMethod::Totp);
            }
            return Err(PamMfaError::InvalidFactor);
        }
        let normalized = normalize_recovery_code(factor).ok_or(PamMfaError::InvalidFactor)?;
        let expected = recovery_digest(&key, username, &normalized)?;
        let Some(index) = credential.recovery_digests.iter().position(|encoded| {
            URL_SAFE_NO_PAD
                .decode(encoded)
                .ok()
                .is_some_and(|candidate| constant_time_eq(&candidate, &expected))
        }) else {
            return Err(PamMfaError::InvalidFactor);
        };
        credential.recovery_digests.remove(index);
        write_credential(&self.directory, &credential)?;
        Ok(PamMfaMethod::Recovery)
    }

    fn lock_pending(&self) -> MutexGuard<'_, Option<PendingEnrollment>> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock_credential_gate(&self) -> MutexGuard<'_, ()> {
        self.credential_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn build_totp(username: &str, secret: Vec<u8>) -> Result<TOTP, PamMfaError> {
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret,
        Some("VPSGuard".to_owned()),
        username.to_owned(),
    )
    .map_err(|_| PamMfaError::Crypto)
}

fn seal_credential(
    master_key: &[u8; MASTER_KEY_BYTES],
    username: &str,
    secret_base32: &str,
    recovery_digests: Vec<String>,
) -> Result<SealedCredential, PamMfaError> {
    let nonce = random_bytes::<NONCE_BYTES>()?;
    let key = derive_key(master_key, AEAD_KEY_CONTEXT);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let plaintext = serde_json::to_vec(&CredentialPayload {
        secret_base32: secret_base32.to_owned(),
    })
    .map_err(|_| PamMfaError::Crypto)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: credential_aad(username).as_bytes(),
            },
        )
        .map_err(|_| PamMfaError::Crypto)?;
    Ok(SealedCredential {
        schema_version: STORE_SCHEMA_VERSION,
        username: username.to_owned(),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        recovery_digests,
    })
}

fn open_credential(
    master_key: &[u8; MASTER_KEY_BYTES],
    credential: &SealedCredential,
) -> Result<CredentialPayload, PamMfaError> {
    let nonce = URL_SAFE_NO_PAD
        .decode(&credential.nonce)
        .map_err(|_| PamMfaError::Storage)?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&credential.ciphertext)
        .map_err(|_| PamMfaError::Storage)?;
    let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| PamMfaError::Storage)?;
    let key = derive_key(master_key, AEAD_KEY_CONTEXT);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: credential_aad(&credential.username).as_bytes(),
            },
        )
        .map_err(|_| PamMfaError::Storage)?;
    serde_json::from_slice(&plaintext).map_err(|_| PamMfaError::Storage)
}

fn credential_aad(username: &str) -> String {
    format!("vpsguard-pam-mfa:{STORE_SCHEMA_VERSION}:{username}")
}

fn recovery_digest(
    master_key: &[u8; MASTER_KEY_BYTES],
    username: &str,
    code: &str,
) -> Result<[u8; 32], PamMfaError> {
    let key = derive_key(master_key, RECOVERY_KEY_CONTEXT);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).map_err(|_| PamMfaError::Crypto)?;
    mac.update(username.as_bytes());
    mac.update(&[0]);
    mac.update(code.as_bytes());
    let mut output = [0_u8; 32];
    output.copy_from_slice(&mac.finalize().into_bytes());
    Ok(output)
}

fn derive_key(master_key: &[u8; MASTER_KEY_BYTES], context: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(context);
    hasher.update(master_key);
    hasher.finalize().into()
}

fn generate_recovery_codes() -> Result<Vec<String>, PamMfaError> {
    let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _index in 0..RECOVERY_CODE_COUNT {
        let bytes = random_bytes::<16>()?;
        let normalized = bytes
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>();
        codes.push(format!(
            "{}-{}-{}-{}",
            &normalized[0..8],
            &normalized[8..16],
            &normalized[16..24],
            &normalized[24..32]
        ));
    }
    Ok(codes)
}

fn normalize_recovery_code(code: &str) -> Option<String> {
    let normalized = code
        .bytes()
        .filter(|byte| *byte != b'-' && !byte.is_ascii_whitespace())
        .map(char::from)
        .collect::<String>()
        .to_ascii_uppercase();
    (normalized.len() == 32 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(normalized)
}

fn valid_totp_shape(value: &str) -> bool {
    value.len() == 6 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn validate_username(username: &str) -> Result<(), PamMfaError> {
    let valid = (3..=32).contains(&username.len())
        && username
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    valid.then_some(()).ok_or(PamMfaError::InvalidUsername)
}

fn ensure_directory(directory: &Path) -> Result<(), PamMfaError> {
    if directory.exists() {
        validate_directory(directory)?;
    } else {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(directory)
            .map_err(|_| PamMfaError::Storage)?;
    }
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
        .map_err(|_| PamMfaError::Storage)
}

fn validate_directory(directory: &Path) -> Result<(), PamMfaError> {
    let metadata = fs::symlink_metadata(directory).map_err(|_| PamMfaError::Storage)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(PamMfaError::Storage);
    }
    Ok(())
}

fn load_or_create_key(directory: &Path) -> Result<[u8; MASTER_KEY_BYTES], PamMfaError> {
    let path = directory.join(KEY_FILE_NAME);
    if path.exists() {
        return read_key(&path);
    }
    let key = random_bytes::<MASTER_KEY_BYTES>()?;
    atomic_write(&path, &key)?;
    Ok(key)
}

fn load_existing_key(directory: &Path) -> Result<[u8; MASTER_KEY_BYTES], PamMfaError> {
    let path = directory.join(KEY_FILE_NAME);
    if !path.exists() {
        return Err(PamMfaError::NotConfigured);
    }
    read_key(&path)
}

fn read_key(path: &Path) -> Result<[u8; MASTER_KEY_BYTES], PamMfaError> {
    validate_secret_file(path)?;
    let bytes = fs::read(path).map_err(|_| PamMfaError::Storage)?;
    bytes.try_into().map_err(|_| PamMfaError::Storage)
}

fn credential_path(directory: &Path, username: &str) -> Result<PathBuf, PamMfaError> {
    validate_username(username)?;
    Ok(directory.join(format!("{username}.json")))
}

fn read_credential(path: &Path) -> Result<SealedCredential, PamMfaError> {
    validate_secret_file(path)?;
    let bytes = fs::read(path).map_err(|_| PamMfaError::Storage)?;
    serde_json::from_slice(&bytes).map_err(|_| PamMfaError::Storage)
}

fn write_credential(directory: &Path, credential: &SealedCredential) -> Result<(), PamMfaError> {
    let path = credential_path(directory, &credential.username)?;
    let bytes = serde_json::to_vec(credential).map_err(|_| PamMfaError::Crypto)?;
    atomic_write(&path, &bytes)
}

fn validate_secret_file(path: &Path) -> Result<(), PamMfaError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| PamMfaError::Storage)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(PamMfaError::Storage);
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), PamMfaError> {
    let parent = path.parent().ok_or(PamMfaError::Storage)?;
    ensure_directory(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or(PamMfaError::Storage)?,
        URL_SAFE_NO_PAD.encode(random_bytes::<12>()?)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| PamMfaError::Storage)?;
        file.write_all(bytes).map_err(|_| PamMfaError::Storage)?;
        file.sync_all().map_err(|_| PamMfaError::Storage)?;
        fs::rename(&temporary, path).map_err(|_| PamMfaError::Storage)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| PamMfaError::Storage)
    })();
    if result.is_err() {
        let _ignored = fs::remove_file(&temporary);
    }
    result
}

fn random_bytes<const N: usize>() -> Result<[u8; N], PamMfaError> {
    let mut bytes = [0_u8; N];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| PamMfaError::Crypto)?;
    Ok(bytes)
}

fn digest(context: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(context);
    hasher.update(value);
    hasher.finalize().into()
}

fn digest_matches(context: &[u8], value: &[u8], expected: &[u8; 32]) -> bool {
    constant_time_eq(&digest(context, value), expected)
}

fn constant_time_eq(candidate: &[u8], expected: &[u8]) -> bool {
    if candidate.len() != expected.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in candidate.iter().zip(expected) {
        difference |= left ^ right;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enrollment_code(
        secret_base32: &str,
        username: &str,
        now: i64,
    ) -> Result<String, PamMfaError> {
        let secret = Secret::Encoded(secret_base32.to_owned())
            .to_bytes()
            .map_err(|_| PamMfaError::Crypto)?;
        Ok(build_totp(username, secret)?
            .generate(u64::try_from(now).map_err(|_| PamMfaError::Crypto)?))
    }

    #[test]
    fn first_pam_enrollment_seals_totp_and_consumes_recovery_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = PamMfaManager::at(directory.path().join("pam"));
        let now = 1_784_108_000_i64;
        assert!(store.setup_required()?);
        let started = store.start_enrollment("operator".to_owned(), now)?;
        let code = enrollment_code(&started.secret_base32, "operator", now)?;
        let completed = store.confirm_enrollment(&started.enrollment_id, &code, now)?;
        assert_eq!(completed.actor, "operator");
        assert_eq!(completed.recovery_codes.len(), RECOVERY_CODE_COUNT);
        assert!(!store.setup_required()?);
        assert_eq!(store.verify("operator", &code, now)?, PamMfaMethod::Totp);

        let recovery = completed
            .recovery_codes
            .first()
            .ok_or("missing recovery code")?;
        assert_eq!(
            store.verify("operator", recovery, now)?,
            PamMfaMethod::Recovery
        );
        assert!(matches!(
            store.verify("operator", recovery, now),
            Err(PamMfaError::InvalidFactor)
        ));

        let persisted = fs::read(directory.path().join("pam/operator.json"))?;
        let persisted = String::from_utf8_lossy(&persisted);
        assert!(!persisted.contains(&started.secret_base32));
        for secret in &completed.recovery_codes {
            assert!(!persisted.contains(secret));
        }
        Ok(())
    }

    #[test]
    fn wrong_totp_and_legacy_plaintext_never_complete_setup()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let pam = directory.path().join("pam");
        ensure_directory(&pam)?;
        fs::write(pam.join("operator"), b"LEGACY-TEST-SEED\n")?;
        fs::set_permissions(pam.join("operator"), fs::Permissions::from_mode(0o600))?;
        let store = PamMfaManager::at(pam);
        assert!(store.setup_required()?);
        let started = store.start_enrollment("operator".to_owned(), 1_784_108_000)?;
        assert!(matches!(
            store.confirm_enrollment(&started.enrollment_id, "000000", 1_784_108_000),
            Err(PamMfaError::InvalidTotp)
        ));
        assert!(store.setup_required()?);
        Ok(())
    }

    #[test]
    fn one_recovery_code_succeeds_only_once_under_concurrency()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = std::sync::Arc::new(PamMfaManager::at(directory.path().join("pam")));
        let now = 1_784_108_000_i64;
        let started = store.start_enrollment("operator".to_owned(), now)?;
        let code = enrollment_code(&started.secret_base32, "operator", now)?;
        let completed = store.confirm_enrollment(&started.enrollment_id, &code, now)?;
        let recovery = completed
            .recovery_codes
            .first()
            .ok_or("missing recovery code")?
            .clone();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles = (0..2)
            .map(|_| {
                let store = std::sync::Arc::clone(&store);
                let barrier = std::sync::Arc::clone(&barrier);
                let recovery = recovery.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    store.verify("operator", &recovery, now)
                })
            })
            .collect::<Vec<_>>();
        let successes = handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .is_ok_and(|result| matches!(result, Ok(PamMfaMethod::Recovery)))
            })
            .filter(|succeeded| *succeeded)
            .count();
        assert_eq!(successes, 1);
        Ok(())
    }

    #[test]
    fn open_credential_directory_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let pam = directory.path().join("pam");
        ensure_directory(&pam)?;
        fs::set_permissions(&pam, fs::Permissions::from_mode(0o755))?;
        let store = PamMfaManager::at(pam);
        assert!(matches!(store.setup_required(), Err(PamMfaError::Storage)));
        Ok(())
    }
}
