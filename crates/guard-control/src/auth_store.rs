//! 관리자 계정, 복구 코드와 hash-only 운영 session을 SQLite에 영속화합니다.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use thiserror::Error;

const MAX_SESSIONS: i64 = 128;

/// 인증 저장소 초기화·query·migration 실패입니다.
#[derive(Debug, Error)]
pub enum AuthStoreError {
    /// database parent directory 생성 또는 권한 설정 실패입니다.
    #[error("인증 database filesystem 작업 실패: {0}")]
    Filesystem(#[from] std::io::Error),
    /// SQLite 작업 실패입니다.
    #[error("인증 SQLite 작업 실패: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// 비밀번호 검증과 TOTP seed 복호화에 필요한 봉인된 관리자 row입니다.
pub(crate) struct StoredAdminAccount {
    pub(crate) id: i64,
    pub(crate) username: String,
    pub(crate) password_hash: String,
    pub(crate) totp_ciphertext: Vec<u8>,
    pub(crate) totp_kdf_salt: Vec<u8>,
    pub(crate) totp_nonce: Vec<u8>,
}

/// 최초 등록 transaction에 저장할 관리자 계정입니다.
pub(crate) struct NewAdminAccount<'a> {
    pub(crate) username: &'a str,
    pub(crate) password_hash: &'a str,
    pub(crate) totp_ciphertext: &'a [u8],
    pub(crate) totp_kdf_salt: &'a [u8],
    pub(crate) totp_nonce: &'a [u8],
}

/// hash-only session 저장 입력입니다.
pub(crate) struct NewStoredSession<'a> {
    pub(crate) session_digest: &'a [u8],
    pub(crate) csrf_digest: &'a [u8],
    pub(crate) actor: &'a str,
    pub(crate) authentication_method: &'a str,
    pub(crate) issued_at: i64,
    pub(crate) expires_at: i64,
}

/// 유효 session을 복원하기 위한 최소 row입니다.
pub(crate) struct StoredSession {
    pub(crate) csrf_digest: Vec<u8>,
    pub(crate) actor: String,
    pub(crate) authentication_method: String,
    pub(crate) expires_at: i64,
}

/// low-frequency 관리 인증 전용 SQLite repository입니다.
pub(crate) struct AuthRepository {
    connection: Mutex<Connection>,
}

impl AuthRepository {
    /// 운영 database를 열고 인증 migration과 service-only 권한을 적용합니다.
    pub(crate) fn open(path: &Path) -> Result<Self, AuthStoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Self::from_connection(connection)
    }

    /// 독립 unit·API test용 memory repository를 만듭니다.
    #[cfg(test)]
    pub(crate) fn in_memory() -> Result<Self, AuthStoreError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(mut connection: Connection) -> Result<Self, AuthStoreError> {
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.busy_timeout(std::time::Duration::from_secs(2))?;
        apply_auth_migration(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// 최초 관리자 계정이 이미 등록됐는지 반환합니다.
    pub(crate) fn is_configured(&self) -> Result<bool, AuthStoreError> {
        let count: i64 =
            self.lock()
                .query_row("SELECT COUNT(*) FROM vpsguard_admin_accounts", [], |row| {
                    row.get(0)
                })?;
        Ok(count > 0)
    }

    /// 단일 초기 관리자, 복구 코드와 첫 session을 한 transaction으로 저장합니다.
    pub(crate) fn create_initial_admin_and_session(
        &self,
        account: &NewAdminAccount<'_>,
        recovery_code_digests: &[[u8; 32]],
        session: &NewStoredSession<'_>,
        now: i64,
    ) -> Result<bool, AuthStoreError> {
        let mut connection = self.lock();
        let transaction = connection.transaction()?;
        let existing: i64 =
            transaction.query_row("SELECT COUNT(*) FROM vpsguard_admin_accounts", [], |row| {
                row.get(0)
            })?;
        if existing > 0 {
            return Ok(false);
        }
        transaction.execute(
            "INSERT INTO vpsguard_admin_accounts(
                id, username, password_hash, totp_ciphertext, totp_kdf_salt, totp_nonce,
                created_at, updated_at
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?6)",
            params![
                account.username,
                account.password_hash,
                account.totp_ciphertext,
                account.totp_kdf_salt,
                account.totp_nonce,
                now,
            ],
        )?;
        for digest in recovery_code_digests {
            transaction.execute(
                "INSERT INTO vpsguard_admin_recovery_codes(
                    account_id, code_digest, created_at
                 ) VALUES (1, ?1, ?2)",
                params![digest.as_slice(), now],
            )?;
        }
        insert_session_row(&transaction, session)?;
        trim_sessions(&transaction)?;
        transaction.commit()?;
        Ok(true)
    }

    /// case-insensitive 정규화 username으로 관리자 row를 읽습니다.
    pub(crate) fn account(
        &self,
        normalized_username: &str,
    ) -> Result<Option<StoredAdminAccount>, AuthStoreError> {
        Ok(self
            .lock()
            .query_row(
                "SELECT id, username, password_hash, totp_ciphertext, totp_kdf_salt, totp_nonce
                 FROM vpsguard_admin_accounts WHERE username = ?1 COLLATE NOCASE",
                [normalized_username],
                |row| {
                    Ok(StoredAdminAccount {
                        id: row.get(0)?,
                        username: row.get(1)?,
                        password_hash: row.get(2)?,
                        totp_ciphertext: row.get(3)?,
                        totp_kdf_salt: row.get(4)?,
                        totp_nonce: row.get(5)?,
                    })
                },
            )
            .optional()?)
    }

    /// 복구 code 소비와 새 session 발급을 한 transaction으로 확정합니다.
    pub(crate) fn consume_recovery_code_and_insert_session(
        &self,
        account_id: i64,
        digest: &[u8; 32],
        session: &NewStoredSession<'_>,
        now: i64,
    ) -> Result<bool, AuthStoreError> {
        let mut connection = self.lock();
        let transaction = connection.transaction()?;
        let changed = transaction.execute(
            "UPDATE vpsguard_admin_recovery_codes
             SET used_at = ?1
             WHERE account_id = ?2 AND code_digest = ?3 AND used_at IS NULL",
            params![now, account_id, digest.as_slice()],
        )?;
        if changed != 1 {
            return Ok(false);
        }
        transaction.execute(
            "DELETE FROM vpsguard_admin_sessions WHERE expires_at <= ?1",
            [session.issued_at],
        )?;
        insert_session_row(&transaction, session)?;
        trim_sessions(&transaction)?;
        transaction.commit()?;
        Ok(true)
    }

    /// session 원문 없이 digest와 actor만 저장하고 전역 상한을 강제합니다.
    pub(crate) fn insert_session(
        &self,
        session: &NewStoredSession<'_>,
    ) -> Result<(), AuthStoreError> {
        let mut connection = self.lock();
        let transaction = connection.transaction()?;
        transaction.execute(
            "DELETE FROM vpsguard_admin_sessions WHERE expires_at <= ?1",
            [session.issued_at],
        )?;
        insert_session_row(&transaction, session)?;
        trim_sessions(&transaction)?;
        transaction.commit()?;
        Ok(())
    }

    /// digest가 일치하는 유효 session을 읽고 만료 row를 bounded 정리합니다.
    pub(crate) fn session(
        &self,
        session_digest: &[u8; 32],
        now: i64,
    ) -> Result<Option<StoredSession>, AuthStoreError> {
        let connection = self.lock();
        connection.execute(
            "DELETE FROM vpsguard_admin_sessions WHERE expires_at <= ?1",
            [now],
        )?;
        Ok(connection
            .query_row(
                "SELECT csrf_digest, actor, authentication_method, expires_at
                 FROM vpsguard_admin_sessions WHERE session_digest = ?1",
                [session_digest.as_slice()],
                |row| {
                    Ok(StoredSession {
                        csrf_digest: row.get(0)?,
                        actor: row.get(1)?,
                        authentication_method: row.get(2)?,
                        expires_at: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    /// 현재 cookie에 해당하는 session 하나를 폐기합니다.
    pub(crate) fn delete_session(&self, session_digest: &[u8; 32]) -> Result<bool, AuthStoreError> {
        Ok(self.lock().execute(
            "DELETE FROM vpsguard_admin_sessions WHERE session_digest = ?1",
            [session_digest.as_slice()],
        )? == 1)
    }

    /// 현재 actor의 모든 session을 폐기합니다.
    pub(crate) fn delete_actor_sessions(&self, actor: &str) -> Result<u64, AuthStoreError> {
        let changed = self.lock().execute(
            "DELETE FROM vpsguard_admin_sessions WHERE actor = ?1",
            [actor],
        )?;
        Ok(u64::try_from(changed).unwrap_or(u64::MAX))
    }

    #[cfg(test)]
    pub(crate) fn recovery_code_count(&self) -> Result<u64, AuthStoreError> {
        let count: i64 = self.lock().query_row(
            "SELECT COUNT(*) FROM vpsguard_admin_recovery_codes WHERE used_at IS NULL",
            [],
            |row| row.get(0),
        )?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn apply_auth_migration(connection: &mut Connection) -> Result<(), rusqlite::Error> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS vpsguard_auth_schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS vpsguard_admin_accounts (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            totp_ciphertext BLOB NOT NULL,
            totp_kdf_salt BLOB NOT NULL CHECK (length(totp_kdf_salt) = 16),
            totp_nonce BLOB NOT NULL CHECK (length(totp_nonce) = 24),
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS vpsguard_admin_recovery_codes (
            account_id INTEGER NOT NULL REFERENCES vpsguard_admin_accounts(id) ON DELETE CASCADE,
            code_digest BLOB NOT NULL CHECK (length(code_digest) = 32),
            created_at INTEGER NOT NULL,
            used_at INTEGER,
            PRIMARY KEY(account_id, code_digest)
        );
        CREATE TABLE IF NOT EXISTS vpsguard_admin_sessions (
            session_digest BLOB PRIMARY KEY CHECK (length(session_digest) = 32),
            csrf_digest BLOB NOT NULL CHECK (length(csrf_digest) = 32),
            actor TEXT NOT NULL,
            authentication_method TEXT NOT NULL,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS vpsguard_admin_sessions_expiry_idx
            ON vpsguard_admin_sessions(expires_at);
        INSERT OR IGNORE INTO vpsguard_auth_schema_migrations(version) VALUES (1);",
    )?;
    Ok(())
}

fn trim_sessions(transaction: &Transaction<'_>) -> Result<(), rusqlite::Error> {
    let count: i64 =
        transaction.query_row("SELECT COUNT(*) FROM vpsguard_admin_sessions", [], |row| {
            row.get(0)
        })?;
    let excess = count.saturating_sub(MAX_SESSIONS);
    if excess > 0 {
        transaction.execute(
            "DELETE FROM vpsguard_admin_sessions WHERE session_digest IN (
                SELECT session_digest FROM vpsguard_admin_sessions
                ORDER BY issued_at ASC LIMIT ?1
             )",
            [excess],
        )?;
    }
    Ok(())
}

fn insert_session_row(
    transaction: &Transaction<'_>,
    session: &NewStoredSession<'_>,
) -> Result<(), rusqlite::Error> {
    transaction.execute(
        "INSERT INTO vpsguard_admin_sessions(
            session_digest, csrf_digest, actor, authentication_method,
            issued_at, expires_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            session.session_digest,
            session.csrf_digest,
            session.actor,
            session.authentication_method,
            session.issued_at,
            session.expires_at,
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AuthRepository, NewAdminAccount, NewStoredSession};

    #[test]
    fn account_recovery_and_sessions_are_bounded_and_one_time()
    -> Result<(), Box<dyn std::error::Error>> {
        let repository = AuthRepository::in_memory()?;
        let recovery = [[7_u8; 32], [8_u8; 32]];
        let initial_session_digest = [250_u8; 32];
        let initial_csrf_digest = [251_u8; 32];
        let initial_session = NewStoredSession {
            session_digest: &initial_session_digest,
            csrf_digest: &initial_csrf_digest,
            actor: "g7devops",
            authentication_method: "password_totp",
            issued_at: 100,
            expires_at: 10_000,
        };
        assert!(repository.create_initial_admin_and_session(
            &NewAdminAccount {
                username: "g7devops",
                password_hash: "$argon2id$fixture",
                totp_ciphertext: &[9_u8; 36],
                totp_kdf_salt: &[1_u8; 16],
                totp_nonce: &[2_u8; 24],
            },
            &recovery,
            &initial_session,
            100,
        )?);
        assert!(!repository.create_initial_admin_and_session(
            &NewAdminAccount {
                username: "second",
                password_hash: "$argon2id$fixture",
                totp_ciphertext: &[9_u8; 36],
                totp_kdf_salt: &[1_u8; 16],
                totp_nonce: &[2_u8; 24],
            },
            &recovery,
            &initial_session,
            101,
        )?);
        let account = repository.account("G7DEVOPS")?.ok_or("account missing")?;
        assert_eq!(account.username, "g7devops");
        let recovery_session_digest = [252_u8; 32];
        let recovery_csrf_digest = [253_u8; 32];
        let recovery_session = NewStoredSession {
            session_digest: &recovery_session_digest,
            csrf_digest: &recovery_csrf_digest,
            actor: "g7devops",
            authentication_method: "password_recovery",
            issued_at: 110,
            expires_at: 10_000,
        };
        assert!(repository.consume_recovery_code_and_insert_session(
            account.id,
            &recovery[0],
            &recovery_session,
            110,
        )?);
        assert!(!repository.consume_recovery_code_and_insert_session(
            account.id,
            &recovery[0],
            &recovery_session,
            111,
        )?);
        assert_eq!(repository.recovery_code_count()?, 1);

        for value in 0_u8..=128 {
            let digest = [value; 32];
            repository.insert_session(&NewStoredSession {
                session_digest: &digest,
                csrf_digest: &[value.wrapping_add(1); 32],
                actor: "g7devops",
                authentication_method: "password_totp",
                issued_at: i64::from(value) + 200,
                expires_at: 10_000,
            })?;
        }
        assert!(repository.session(&[0_u8; 32], 500)?.is_none());
        assert!(repository.session(&[128_u8; 32], 500)?.is_some());
        assert_eq!(repository.delete_actor_sessions("g7devops")?, 128);
        Ok(())
    }
}
