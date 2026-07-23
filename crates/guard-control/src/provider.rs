//! Cloudflare transaction의 재개 가능한 상태 저장과 production adapter 조립입니다.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use guard_core::GuardConfig;
use guard_provider::cloudflare::{CloudflareBackend, NftOriginProtection};
use guard_provider::{ProviderError, ProviderStage, ProviderTransaction};
use guard_system::{AtomicJsonStore, OriginFirewallPlan, StoreError};
use thiserror::Error;

type Backend = CloudflareBackend<NftOriginProtection>;

/// Provider controller 초기화·실행 실패입니다.
#[derive(Debug, Error)]
pub enum ProviderControllerError {
    /// Cloudflare 또는 nftables adapter 실패입니다.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// transaction 원자 저장 실패입니다.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// origin allowlist plan 실패입니다.
    #[error("origin firewall plan 실패")]
    Firewall,
}

impl ProviderControllerError {
    /// journal·event·transaction에 저장할 비밀 없는 안정 오류 코드입니다.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Provider(error) => error.code(),
            Self::Store(_) => "PROVIDER_STATE_STORE_FAILED",
            Self::Firewall => "PROVIDER_FIREWALL_PLAN_FAILED",
        }
    }
}

/// Cloudflare backend와 원자 transaction state를 소유합니다.
#[derive(Debug)]
pub(crate) struct ProviderController {
    backend: Backend,
    store: AtomicJsonStore<ProviderTransaction>,
    transaction: Option<ProviderTransaction>,
    record_name: String,
    allowed_records: Vec<String>,
    preflight_error: Option<ProviderError>,
    max_dns_ttl_seconds: u32,
}

impl ProviderController {
    /// 활성화된 Cloudflare 설정만 controller로 조립합니다.
    pub(crate) fn from_config(
        config: &GuardConfig,
    ) -> Result<Option<Self>, ProviderControllerError> {
        if !config.cloudflare.enabled {
            return Ok(None);
        }
        let firewall_plan = OriginFirewallPlan::new(config.cloudflare.ip_networks.clone())
            .map_err(|_error| ProviderControllerError::Firewall)?;
        let origin = NftOriginProtection::new(firewall_plan);
        let backend = CloudflareBackend::from_token_file(
            config.cloudflare.zone_id.clone(),
            config.cloudflare.records.clone(),
            &config.cloudflare.token_file,
            origin,
        )?;
        let preflight_error = backend.preflight().err();
        let state_path = provider_state_path(config);
        let store = AtomicJsonStore::new(state_path);
        let transaction = if store.path().exists() {
            Some(store.read()?)
        } else {
            None
        };
        let record_name = config.cloudflare.records[0].name.clone();
        Ok(Some(Self {
            backend,
            store,
            transaction,
            record_name,
            allowed_records: config
                .cloudflare
                .records
                .iter()
                .map(|record| record.name.clone())
                .collect(),
            preflight_error,
            max_dns_ttl_seconds: config.cloudflare.max_dns_ttl_seconds,
        }))
    }

    /// 현재 provider 단계 문자열입니다.
    pub(crate) fn status(&self) -> String {
        if let Some(transaction) = &self.transaction {
            stage_name(transaction.stage).to_owned()
        } else if let Some(error) = &self.preflight_error {
            format!("unavailable:{}", error.code().to_ascii_lowercase())
        } else {
            "ready".to_owned()
        }
    }

    /// 외부 proxy와 origin 보호가 모두 read-back 완료됐는지 반환합니다.
    pub(crate) fn protection_active(&self) -> bool {
        self.transaction
            .as_ref()
            .is_some_and(|transaction| transaction.stage == ProviderStage::Complete)
    }

    /// 재시작 또는 drain 대기 뒤 이어서 진행할 활성화 transaction인지 반환합니다.
    pub(crate) fn activation_pending(&self) -> bool {
        self.transaction
            .as_ref()
            .is_some_and(|transaction| activation_stage_pending(transaction.stage))
    }

    /// 저장된 DNS cache drain deadline Unix 초를 반환합니다.
    pub(crate) fn drain_deadline_unix_seconds(&self) -> Option<u64> {
        self.transaction
            .as_ref()
            .and_then(|transaction| transaction.proxy_drain_deadline_unix_seconds)
    }

    /// 새 transaction을 시작하거나 저장된 단계에서 재개합니다.
    pub(crate) fn enable(
        &mut self,
        operation_id: &str,
    ) -> Result<ProviderStage, ProviderControllerError> {
        let create_new = self.transaction.as_ref().is_none_or(|transaction| {
            transaction.stage == ProviderStage::Restored
                || transaction.record_name != self.record_name
        });
        let preflight_required = create_new
            || self
                .transaction
                .as_ref()
                .is_some_and(|transaction| transaction.stage == ProviderStage::Pending);
        if preflight_required {
            if let Err(error) = self.backend.preflight() {
                self.preflight_error = Some(error.clone());
                return Err(error.into());
            }
            self.preflight_error = None;
        }
        if create_new {
            self.transaction = Some(ProviderTransaction::new(
                operation_id,
                self.record_name.clone(),
                &self.allowed_records,
            )?);
        }
        let transaction = self
            .transaction
            .as_mut()
            .ok_or_else(|| ProviderError::Backend("TRANSACTION_UNAVAILABLE".to_owned()))?;
        loop {
            let result = transaction.enable_step_at(
                &mut self.backend,
                current_unix_seconds(),
                self.max_dns_ttl_seconds,
            );
            if let Err(error) = &result {
                transaction.last_error = Some(error.code().to_owned());
            }
            self.store.write(transaction)?;
            match result? {
                ProviderStage::Complete | ProviderStage::ProxyDrain => {
                    return Ok(transaction.stage);
                }
                ProviderStage::Restored => {
                    return Err(ProviderError::Backend(
                        "RESTORED_TRANSACTION_CANNOT_RESUME".to_owned(),
                    )
                    .into());
                }
                _ => {}
            }
        }
    }

    /// 저장된 snapshot으로 provider와 origin firewall을 복구합니다.
    pub(crate) fn restore(&mut self) -> Result<ProviderStage, ProviderControllerError> {
        let transaction = self
            .transaction
            .as_mut()
            .ok_or(ProviderError::MissingSnapshot)?;
        loop {
            let result = transaction.restore_step(&mut self.backend);
            self.store.write(transaction)?;
            match result? {
                ProviderStage::Restored => return Ok(transaction.stage),
                ProviderStage::RestoreRequested => {}
                _ => {
                    return Err(ProviderError::Backend(
                        "UNEXPECTED_PROVIDER_RESTORE_STAGE".to_owned(),
                    )
                    .into());
                }
            }
        }
    }
}

const fn activation_stage_pending(stage: ProviderStage) -> bool {
    matches!(
        stage,
        ProviderStage::Snapshotted
            | ProviderStage::ProxyRequested
            | ProviderStage::ProxyVerified
            | ProviderStage::ProxyDrain
            | ProviderStage::OriginLockRequested
    )
}

fn stage_name(stage: ProviderStage) -> &'static str {
    match stage {
        ProviderStage::Pending => "pending",
        ProviderStage::Snapshotted => "snapshotted",
        ProviderStage::ProxyRequested => "proxy_requested",
        ProviderStage::ProxyVerified => "proxy_verified",
        ProviderStage::ProxyDrain => "proxy_drain",
        ProviderStage::OriginLockRequested => "origin_lock_requested",
        ProviderStage::Complete => "complete",
        ProviderStage::RestoreRequested => "restore_requested",
        ProviderStage::Restored => "restored",
    }
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn provider_state_path(config: &GuardConfig) -> PathBuf {
    config.storage.database_path.parent().map_or_else(
        || PathBuf::from("provider-transaction.json"),
        |parent| parent.join("provider-transaction.json"),
    )
}

#[cfg(test)]
#[path = "provider/tests.rs"]
mod tests;
