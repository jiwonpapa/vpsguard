//! Cloudflare transaction의 재개 가능한 상태 저장과 production adapter 조립입니다.

use std::path::PathBuf;

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
    #[error("origin firewall plan 실패: {0}")]
    Firewall(String),
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
            .map_err(|error| ProviderControllerError::Firewall(error.to_string()))?;
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

    /// 외부 보호가 완료됐거나 이미 snapshot 복구돼 recovery를 진행할 수 있는지 반환합니다.
    pub(crate) fn recovery_ready(&self) -> bool {
        self.transaction.as_ref().is_some_and(|transaction| {
            transaction.snapshot.is_some()
                && !matches!(
                    transaction.stage,
                    ProviderStage::Pending | ProviderStage::Restored
                )
        })
    }

    /// 새 transaction을 시작하거나 저장된 단계에서 재개합니다.
    pub(crate) fn enable(
        &mut self,
        operation_id: &str,
    ) -> Result<ProviderStage, ProviderControllerError> {
        if let Err(error) = self.backend.preflight() {
            self.preflight_error = Some(error.clone());
            return Err(error.into());
        }
        self.preflight_error = None;
        let create_new = self.transaction.as_ref().is_none_or(|transaction| {
            transaction.stage == ProviderStage::Restored
                || transaction.record_name != self.record_name
        });
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
            let result = transaction.enable_step(&mut self.backend);
            if let Err(error) = &result {
                transaction.last_error = Some(error.to_string());
            }
            self.store.write(transaction)?;
            match result? {
                ProviderStage::Complete => return Ok(transaction.stage),
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

fn stage_name(stage: ProviderStage) -> &'static str {
    match stage {
        ProviderStage::Pending => "pending",
        ProviderStage::Snapshotted => "snapshotted",
        ProviderStage::ProxyRequested => "proxy_requested",
        ProviderStage::ProxyVerified => "proxy_verified",
        ProviderStage::OriginLockRequested => "origin_lock_requested",
        ProviderStage::Complete => "complete",
        ProviderStage::RestoreRequested => "restore_requested",
        ProviderStage::Restored => "restored",
    }
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
