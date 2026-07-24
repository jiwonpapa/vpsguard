//! 관리자 보호 제한의 plan, 원자 policy 적용과 재시작 복원을 담당합니다.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use guard_core::policy::{ProtectionSettings, ProtectionSettingsError, StaticLimits};
use guard_core::{GuardMode, GuardState, PolicyError, PolicySnapshot};
use guard_system::{AtomicJsonStore, StoreError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::Mutex as AsyncMutex;

const POLICY_TTL_MINUTES: i64 = 10;
const COMPLETED_OPERATION_CAPACITY: usize = 1_024;

/// 현재 관리자 보호 설정과 policy 적용 상태입니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ProtectionSnapshot {
    /// 재시작 없이 조정하는 단계별 제한입니다.
    pub(crate) settings: ProtectionSettings,
    /// policy 파일에 원자 반영된 version입니다.
    pub(crate) policy_version: u64,
    /// 현재 설정의 SHA-256 precondition입니다.
    pub(crate) fingerprint: String,
}

/// 보호 설정 한 필드의 변경 diff입니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ProtectionChange {
    /// typed 설정 필드명입니다.
    pub(crate) field: &'static str,
    /// 현재 분당 요청 한도입니다.
    pub(crate) before: u32,
    /// 후보 분당 요청 한도입니다.
    pub(crate) after: u32,
}

/// 적용 전 검증된 보호 설정 계획입니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ProtectionPlan {
    /// 적용할 typed 설정입니다.
    pub(crate) settings: ProtectionSettings,
    /// plan 생성 시점의 현재 설정 fingerprint입니다.
    pub(crate) current_fingerprint: String,
    /// 후보와 precondition을 결합한 plan hash입니다.
    pub(crate) plan_hash: String,
    /// 현재 policy version입니다.
    pub(crate) current_policy_version: u64,
    /// 변경 적용 시 생성할 다음 policy version입니다.
    pub(crate) next_policy_version: u64,
    /// 값이 실제로 달라지는 필드만 포함한 diff입니다.
    pub(crate) changes: Vec<ProtectionChange>,
}

/// 보호 설정 적용 결과입니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ProtectionApplyOutcome {
    /// 새 policy를 썼는지 여부입니다.
    pub(crate) applied: bool,
    /// 적용 뒤 현재 설정과 policy version입니다.
    pub(crate) snapshot: ProtectionSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompletedOperation {
    operation_id: String,
    plan_hash: String,
    snapshot: ProtectionSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CurrentProtection {
    settings: ProtectionSettings,
    policy_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedProtection {
    schema_version: u32,
    settings: ProtectionSettings,
    policy_version: u64,
    content_sha256: String,
}

impl PersistedProtection {
    fn new(current: CurrentProtection) -> Result<Self, ProtectionPolicyError> {
        let mut value = Self {
            schema_version: 1,
            settings: current.settings,
            policy_version: current.policy_version,
            content_sha256: String::new(),
        };
        value.content_sha256 = value.calculate_hash()?;
        Ok(value)
    }

    fn calculate_hash(&self) -> Result<String, ProtectionPolicyError> {
        let mut canonical = self.clone();
        canonical.content_sha256.clear();
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&canonical)?)
        ))
    }

    fn validate(&self) -> Result<(), ProtectionPolicyError> {
        if self.schema_version != 1 {
            return Err(ProtectionPolicyError::UnsupportedMetadataSchema(
                self.schema_version,
            ));
        }
        self.settings.validate()?;
        if self.calculate_hash()? != self.content_sha256 {
            return Err(ProtectionPolicyError::MetadataHashMismatch);
        }
        Ok(())
    }

    fn current(&self) -> CurrentProtection {
        CurrentProtection {
            settings: self.settings,
            policy_version: self.policy_version,
        }
    }
}

#[derive(Debug)]
struct ProtectionMemory {
    current: CurrentProtection,
    completed: VecDeque<CompletedOperation>,
}

/// 보호 policy 생성·쓰기·idempotency 실패입니다.
#[derive(Debug, Error)]
pub enum ProtectionPolicyError {
    /// typed 보호 제한이 범위 또는 단계 관계를 위반했습니다.
    #[error(transparent)]
    InvalidSettings(#[from] ProtectionSettingsError),
    /// 기존 또는 새 policy snapshot 계약이 깨졌습니다.
    #[error(transparent)]
    Policy(#[from] PolicyError),
    /// policy JSON 원자 저장 또는 read-back이 실패했습니다.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// fingerprint 또는 plan hash 직렬화가 실패했습니다.
    #[error("보호 설정 hash 직렬화 실패: {0}")]
    Serialize(#[from] serde_json::Error),
    /// plan 생성 뒤 다른 설정이 먼저 적용됐습니다.
    #[error("보호 설정 plan의 현재 fingerprint가 변경됐습니다")]
    StalePlan,
    /// plan hash가 현재 후보와 일치하지 않습니다.
    #[error("보호 설정 plan hash가 일치하지 않습니다")]
    PlanHashMismatch,
    /// 같은 idempotency key가 다른 plan에 사용됐습니다.
    #[error("같은 idempotency key가 다른 보호 설정 plan에 사용됐습니다")]
    IdempotencyConflict,
    /// policy version을 더 증가시킬 수 없습니다.
    #[error("보호 policy version 상한에 도달했습니다")]
    VersionExhausted,
    /// policy 시각 문자열 생성이 실패했습니다.
    #[error("보호 policy 시각 생성 실패: {0}")]
    Time(String),
    /// 원자 write 뒤 읽은 policy가 요청한 값과 다릅니다.
    #[error("보호 policy read-back이 적용 후보와 일치하지 않습니다")]
    ReadBackMismatch,
    /// 보호 설정 sidecar의 schema를 지원하지 않습니다.
    #[error("지원하지 않는 보호 설정 metadata schema입니다: {0}")]
    UnsupportedMetadataSchema(u32),
    /// 보호 설정 sidecar 본문 hash가 일치하지 않습니다.
    #[error("보호 설정 metadata hash가 일치하지 않습니다")]
    MetadataHashMismatch,
    /// policy가 설정 sidecar보다 앞서 있어 안전하게 복원할 수 없습니다.
    #[error(
        "policy version {policy_version}이 설정 metadata version {metadata_version}보다 앞섭니다"
    )]
    MetadataVersionBehind {
        /// Edge policy 파일의 version입니다.
        policy_version: u64,
        /// 보호 설정 sidecar의 version입니다.
        metadata_version: u64,
    },
    /// 같은 version의 policy route 규칙과 설정 sidecar가 일치하지 않습니다.
    #[error("보호 policy route 규칙과 설정 metadata가 일치하지 않습니다")]
    PolicySettingsMismatch,
    /// state가 가리키는 policy version에 대응하는 policy 파일이 없습니다.
    #[error("state policy version {0}에 대응하는 policy 파일이 없습니다")]
    MissingPolicy(u64),
    /// state version이 실제 policy 파일보다 앞서 있어 일관성을 증명할 수 없습니다.
    #[error("state policy version {state_version}이 파일 version {file_version}보다 앞섭니다")]
    StateVersionAhead {
        /// state 파일이 가리키는 version입니다.
        state_version: u64,
        /// 실제 policy 파일의 version입니다.
        file_version: u64,
    },
}

/// Edge가 읽는 단일 policy 파일의 모든 writer를 직렬화합니다.
#[derive(Debug)]
pub(crate) struct ProtectionPolicyManager {
    store: AtomicJsonStore<PolicySnapshot>,
    metadata_store: AtomicJsonStore<PersistedProtection>,
    max_body_bytes: u64,
    max_tracked_clients: usize,
    memory: Mutex<ProtectionMemory>,
    writer: AsyncMutex<()>,
}

impl ProtectionPolicyManager {
    /// 기존 policy에서 설정·version을 복원하거나 기본값으로 시작합니다.
    ///
    /// # Errors
    ///
    /// 기존 policy가 존재하지만 JSON·hash·schema·설정 계약이 깨졌으면 실패합니다.
    pub(crate) fn load(
        path: PathBuf,
        state_policy_version: u64,
        state_mode: GuardMode,
        max_body_bytes: u64,
        max_tracked_clients: usize,
    ) -> Result<Self, ProtectionPolicyError> {
        let metadata_store =
            AtomicJsonStore::<PersistedProtection>::new(path.with_extension("settings.json"));
        let store = AtomicJsonStore::<PolicySnapshot>::new(path);
        let policy = if store.path().exists() {
            let policy = store.read()?;
            policy.validate_at(OffsetDateTime::UNIX_EPOCH)?;
            Some(policy)
        } else {
            None
        };
        let metadata = if metadata_store.path().exists() {
            let metadata = metadata_store.read()?;
            metadata.validate()?;
            Some(metadata)
        } else {
            None
        };
        let current = recover_current(
            &store,
            &metadata_store,
            policy,
            metadata,
            state_policy_version,
            state_mode,
            &StaticLimits {
                max_body_bytes,
                max_tracked_clients,
            },
        )?;
        Ok(Self {
            store,
            metadata_store,
            max_body_bytes,
            max_tracked_clients,
            memory: Mutex::new(ProtectionMemory {
                current,
                completed: VecDeque::with_capacity(COMPLETED_OPERATION_CAPACITY),
            }),
            writer: AsyncMutex::new(()),
        })
    }

    /// 현재 설정과 policy 파일 version을 반환합니다.
    ///
    /// # Errors
    ///
    /// fingerprint JSON 직렬화 실패를 반환합니다.
    pub(crate) fn snapshot(&self) -> Result<ProtectionSnapshot, ProtectionPolicyError> {
        snapshot_of(lock(&self.memory).current)
    }

    /// 후보 설정의 diff와 현재 fingerprint에 묶인 plan hash를 만듭니다.
    ///
    /// # Errors
    ///
    /// 후보 범위·단계 관계 또는 hash 직렬화 실패를 반환합니다.
    pub(crate) fn plan(
        &self,
        settings: ProtectionSettings,
    ) -> Result<ProtectionPlan, ProtectionPolicyError> {
        settings.validate()?;
        plan_from(lock(&self.memory).current, settings)
    }

    /// plan precondition을 확인하고 새 policy를 원자 write·read-back합니다.
    ///
    /// # Errors
    ///
    /// 인증 이후의 설정 검증, stale plan, idempotency, policy 생성·저장·read-back 실패를
    /// 반환합니다.
    pub(crate) async fn apply(
        &self,
        operation_id: &str,
        expected_fingerprint: &str,
        plan_hash: &str,
        settings: ProtectionSettings,
        mode: GuardMode,
    ) -> Result<ProtectionApplyOutcome, ProtectionPolicyError> {
        settings.validate()?;
        let _writer = self.writer.lock().await;
        {
            let memory = lock(&self.memory);
            if let Some(completed) = memory
                .completed
                .iter()
                .find(|entry| entry.operation_id == operation_id)
            {
                if completed.plan_hash != plan_hash {
                    return Err(ProtectionPolicyError::IdempotencyConflict);
                }
                return Ok(ProtectionApplyOutcome {
                    applied: false,
                    snapshot: completed.snapshot.clone(),
                });
            }
        }
        let current = lock(&self.memory).current;
        let plan = plan_from(current, settings)?;
        if plan.current_fingerprint != expected_fingerprint {
            return Err(ProtectionPolicyError::StalePlan);
        }
        if plan.plan_hash != plan_hash {
            return Err(ProtectionPolicyError::PlanHashMismatch);
        }
        if plan.changes.is_empty() {
            let snapshot = snapshot_of(current)?;
            remember(
                &mut lock(&self.memory),
                operation_id,
                plan_hash,
                snapshot.clone(),
            );
            return Ok(ProtectionApplyOutcome {
                applied: false,
                snapshot,
            });
        }
        let next_version = next_version(current.policy_version)?;
        let policy = build_policy_at(
            mode,
            next_version,
            self.max_body_bytes,
            self.max_tracked_clients,
            settings,
            OffsetDateTime::now_utc(),
        )?;
        let next = CurrentProtection {
            settings,
            policy_version: next_version,
        };
        self.write_and_read_back(policy, current, next).await?;
        let snapshot = snapshot_of(next)?;
        let mut memory = lock(&self.memory);
        memory.current = next;
        remember(&mut memory, operation_id, plan_hash, snapshot.clone());
        Ok(ProtectionApplyOutcome {
            applied: true,
            snapshot,
        })
    }

    /// 현재 관리자 설정을 유지한 채 방어 mode의 policy lease를 갱신합니다.
    ///
    /// # Errors
    ///
    /// version, policy 생성·저장 또는 read-back 실패를 반환합니다.
    pub(crate) async fn write_for_state(
        &self,
        mut state: GuardState,
    ) -> Result<GuardState, ProtectionPolicyError> {
        let _writer = self.writer.lock().await;
        let current = lock(&self.memory).current;
        let next_version = next_version(current.policy_version.max(state.policy_version))?;
        let policy = build_policy_at(
            state.current_mode,
            next_version,
            self.max_body_bytes,
            self.max_tracked_clients,
            current.settings,
            OffsetDateTime::now_utc(),
        )?;
        let next = CurrentProtection {
            settings: current.settings,
            policy_version: next_version,
        };
        self.write_and_read_back(policy, current, next).await?;
        lock(&self.memory).current.policy_version = next_version;
        state.policy_version = next_version;
        Ok(state)
    }

    async fn write_and_read_back(
        &self,
        policy: PolicySnapshot,
        previous: CurrentProtection,
        expected: CurrentProtection,
    ) -> Result<(), ProtectionPolicyError> {
        let expected_version = policy.policy_version;
        let expected_hash = policy.content_sha256.clone();
        let expected_metadata = PersistedProtection::new(expected)?;
        let previous_metadata = PersistedProtection::new(previous)?;
        let store = self.store.clone();
        let metadata_store = self.metadata_store.clone();
        let (read_back, metadata_read_back) = tokio::task::spawn_blocking(move || {
            metadata_store.write(&expected_metadata)?;
            if let Err(error) = store.write(&policy) {
                let _ = metadata_store.write(&previous_metadata);
                return Err(error);
            }
            Ok::<_, StoreError>((store.read()?, metadata_store.read()?))
        })
        .await
        .map_err(|error| ProtectionPolicyError::Time(error.to_string()))??;
        read_back.validate_at(OffsetDateTime::now_utc())?;
        metadata_read_back.validate()?;
        if read_back.policy_version != expected_version
            || read_back.content_sha256 != expected_hash
            || metadata_read_back.current() != expected
        {
            return Err(ProtectionPolicyError::ReadBackMismatch);
        }
        Ok(())
    }
}

fn recover_current(
    store: &AtomicJsonStore<PolicySnapshot>,
    metadata_store: &AtomicJsonStore<PersistedProtection>,
    policy: Option<PolicySnapshot>,
    metadata: Option<PersistedProtection>,
    state_policy_version: u64,
    state_mode: GuardMode,
    limits: &StaticLimits,
) -> Result<CurrentProtection, ProtectionPolicyError> {
    let current = match (policy, metadata) {
        (None, None) => {
            if state_policy_version > 0 {
                return Err(ProtectionPolicyError::MissingPolicy(state_policy_version));
            }
            let current = CurrentProtection {
                settings: ProtectionSettings::default(),
                policy_version: 0,
            };
            metadata_store.write(&PersistedProtection::new(current)?)?;
            current
        }
        (Some(policy), None) => {
            let current = CurrentProtection {
                settings: ProtectionSettings::default(),
                policy_version: policy.policy_version,
            };
            ensure_policy_matches_settings(&policy, current.settings)?;
            metadata_store.write(&PersistedProtection::new(current)?)?;
            current
        }
        (None, Some(metadata)) => {
            let current = metadata.current();
            if current.policy_version > 0 {
                write_recovered_policy(store, state_mode, current, limits)?;
            }
            current
        }
        (Some(policy), Some(metadata)) => {
            if policy.policy_version > metadata.policy_version {
                return Err(ProtectionPolicyError::MetadataVersionBehind {
                    policy_version: policy.policy_version,
                    metadata_version: metadata.policy_version,
                });
            }
            let current = metadata.current();
            if current.policy_version > policy.policy_version {
                write_recovered_policy(store, state_mode, current, limits)?;
            } else {
                ensure_policy_matches_settings(&policy, current.settings)?;
            }
            current
        }
    };
    if state_policy_version > current.policy_version {
        return Err(ProtectionPolicyError::StateVersionAhead {
            state_version: state_policy_version,
            file_version: current.policy_version,
        });
    }
    Ok(current)
}

fn write_recovered_policy(
    store: &AtomicJsonStore<PolicySnapshot>,
    mode: GuardMode,
    current: CurrentProtection,
    limits: &StaticLimits,
) -> Result<(), ProtectionPolicyError> {
    let policy = build_policy_at(
        mode,
        current.policy_version,
        limits.max_body_bytes,
        limits.max_tracked_clients,
        current.settings,
        OffsetDateTime::now_utc(),
    )?;
    store.write(&policy)?;
    let read_back = store.read()?;
    read_back.validate_at(OffsetDateTime::now_utc())?;
    if read_back.policy_version != current.policy_version {
        return Err(ProtectionPolicyError::ReadBackMismatch);
    }
    ensure_policy_matches_settings(&read_back, current.settings)
}

fn ensure_policy_matches_settings(
    policy: &PolicySnapshot,
    settings: ProtectionSettings,
) -> Result<(), ProtectionPolicyError> {
    if policy.route_rules != settings.route_rules(policy.mode) {
        return Err(ProtectionPolicyError::PolicySettingsMismatch);
    }
    Ok(())
}

/// 지정 시각과 mode에 맞는 검증·봉인된 Edge policy를 생성합니다.
///
/// # Errors
///
/// 보호 제한, policy hash 또는 RFC3339 시각 생성 실패를 반환합니다.
pub(crate) fn build_policy_at(
    mode: GuardMode,
    policy_version: u64,
    max_body_bytes: u64,
    max_tracked_clients: usize,
    protection_settings: ProtectionSettings,
    now: OffsetDateTime,
) -> Result<PolicySnapshot, ProtectionPolicyError> {
    protection_settings.validate()?;
    let generated_at = now
        .format(&Rfc3339)
        .map_err(|error| ProtectionPolicyError::Time(error.to_string()))?;
    let expires_at = (now + time::Duration::minutes(POLICY_TTL_MINUTES))
        .format(&Rfc3339)
        .map_err(|error| ProtectionPolicyError::Time(error.to_string()))?;
    Ok(PolicySnapshot {
        schema_version: 1,
        policy_version,
        generated_at,
        expires_at,
        mode,
        route_rules: protection_settings.route_rules(mode),
        client_rules: Vec::new(),
        static_limits: StaticLimits {
            max_body_bytes,
            max_tracked_clients,
        },
        content_sha256: String::new(),
    }
    .seal()?)
}

fn plan_from(
    current: CurrentProtection,
    settings: ProtectionSettings,
) -> Result<ProtectionPlan, ProtectionPolicyError> {
    let snapshot = snapshot_of(current)?;
    let next_policy_version = next_version(current.policy_version)?;
    let candidate = serde_json::to_vec(&settings)?;
    let plan_hash = format!(
        "{:x}",
        Sha256::digest([snapshot.fingerprint.as_bytes(), candidate.as_slice()].concat())
    );
    Ok(ProtectionPlan {
        settings,
        current_fingerprint: snapshot.fingerprint,
        plan_hash,
        current_policy_version: current.policy_version,
        next_policy_version,
        changes: changes(current.settings, settings),
    })
}

fn snapshot_of(current: CurrentProtection) -> Result<ProtectionSnapshot, ProtectionPolicyError> {
    let bytes = serde_json::to_vec(&current.settings)?;
    Ok(ProtectionSnapshot {
        settings: current.settings,
        policy_version: current.policy_version,
        fingerprint: format!("{:x}", Sha256::digest(bytes)),
    })
}

fn changes(before: ProtectionSettings, after: ProtectionSettings) -> Vec<ProtectionChange> {
    [
        (
            "watch_strict_requests_per_minute",
            before.watch_strict_requests_per_minute,
            after.watch_strict_requests_per_minute,
        ),
        (
            "local_strict_requests_per_minute",
            before.local_strict_requests_per_minute,
            after.local_strict_requests_per_minute,
        ),
        (
            "local_upload_requests_per_minute",
            before.local_upload_requests_per_minute,
            after.local_upload_requests_per_minute,
        ),
        (
            "emergency_strict_requests_per_minute",
            before.emergency_strict_requests_per_minute,
            after.emergency_strict_requests_per_minute,
        ),
        (
            "emergency_upload_requests_per_minute",
            before.emergency_upload_requests_per_minute,
            after.emergency_upload_requests_per_minute,
        ),
    ]
    .into_iter()
    .filter_map(|(field, before, after)| {
        (before != after).then_some(ProtectionChange {
            field,
            before,
            after,
        })
    })
    .collect()
}

fn next_version(current: u64) -> Result<u64, ProtectionPolicyError> {
    current
        .checked_add(1)
        .ok_or(ProtectionPolicyError::VersionExhausted)
}

fn remember(
    memory: &mut ProtectionMemory,
    operation_id: &str,
    plan_hash: &str,
    snapshot: ProtectionSnapshot,
) {
    if memory.completed.len() == COMPLETED_OPERATION_CAPACITY {
        memory.completed.pop_front();
    }
    memory.completed.push_back(CompletedOperation {
        operation_id: operation_id.to_owned(),
        plan_hash: plan_hash.to_owned(),
        snapshot,
    });
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
#[path = "protection/tests.rs"]
mod tests;
