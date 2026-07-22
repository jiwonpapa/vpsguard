//! OPS-003/OPS-004 Nginx ingress 후보의 원자 교체와 자동 rollback driver입니다.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::files::replace_file;
use super::format::{FileRecord, Presence, ServiceRecord};
use super::switch_contract::{
    direction_name, issue, require_regular, validate_service_field, validate_switch_config,
};
use super::switch_snapshot::{self, SWITCH_SCHEMA_VERSION};
use super::{EDGE_SERVICE, IngressStateConfig, IngressStateError, IngressStateStore, io_error};
use crate::{
    AtomicJsonStore, IngressTopology, OperationDriver, OperationIssue, OperationKind,
    OperationPhase, OperationPlan, PhaseReport, SnapshotResource,
};

/// public ingress 전환 방향입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressSwitchDirection {
    /// Nginx public TLS 뒤에 VPSGuard loopback edge를 편입합니다.
    ToEdge,
    /// VPSGuard를 우회하고 Nginx public 후보를 활성화합니다.
    ToNginx,
}

impl IngressSwitchDirection {
    fn operation(self) -> OperationKind {
        match self {
            Self::ToEdge => OperationKind::BypassDisable,
            Self::ToNginx => OperationKind::BypassEnable,
        }
    }
}

/// ingress 후보 전환의 bounded path와 probe 설정입니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressSwitchConfig {
    /// 공통 ingress host·fixture 설정입니다.
    pub state: IngressStateConfig,
    /// 활성 Nginx include logical path입니다.
    pub active_config: PathBuf,
    /// VPSGuard 편입 후보 logical path입니다.
    pub edge_candidate: PathBuf,
    /// Nginx bypass 후보 logical path입니다.
    pub nginx_candidate: PathBuf,
    /// 활성 VPSGuard config logical path입니다.
    pub active_guard_config: PathBuf,
    /// 선택한 release staging directory입니다.
    pub stage_root: Option<PathBuf>,
    /// rollback snapshot root입니다.
    pub backup_root: PathBuf,
    /// fixture public probe 실패 주입입니다.
    pub fixture_probe_failure: bool,
}

impl IngressSwitchConfig {
    /// 운영 기본 경계를 만듭니다.
    #[must_use]
    pub fn production(probe_url: impl Into<String>) -> Self {
        let mut state = IngressStateConfig::production("/var/backups/vps-guard/ingress-switch");
        let probe_url = probe_url.into();
        if !probe_url.is_empty() {
            state.public_probe_url = probe_url;
        }
        Self {
            state,
            active_config: PathBuf::from("/etc/nginx/conf.d/vps-guard-ingress.conf"),
            edge_candidate: PathBuf::from("/etc/vps-guard/nginx/edge-origin.conf"),
            nginx_candidate: PathBuf::from("/etc/vps-guard/nginx/public-bypass.conf"),
            active_guard_config: PathBuf::from("/etc/vps-guard/config.toml"),
            stage_root: None,
            backup_root: PathBuf::from("/var/lib/vps-guard/backups"),
            fixture_probe_failure: false,
        }
    }

    /// OS mutation 없는 fixture 경계를 만듭니다.
    #[must_use]
    pub fn fixture(
        root: impl Into<PathBuf>,
        state_root: impl Into<PathBuf>,
        backup_root: impl Into<PathBuf>,
    ) -> Self {
        let backup_root = backup_root.into();
        Self {
            state: IngressStateConfig::fixture(root, state_root, backup_root.join("snapshots")),
            active_config: PathBuf::from("/etc/nginx/conf.d/vps-guard-ingress.conf"),
            edge_candidate: PathBuf::from("/etc/vps-guard/nginx/edge-origin.conf"),
            nginx_candidate: PathBuf::from("/etc/vps-guard/nginx/public-bypass.conf"),
            active_guard_config: PathBuf::from("/etc/vps-guard/config.toml"),
            stage_root: None,
            backup_root,
            fixture_probe_failure: false,
        }
    }
}

/// 실제 후보 교체·service 전환·probe를 수행하는 driver입니다.
#[derive(Debug)]
pub struct IngressSwitchDriver {
    config: IngressSwitchConfig,
    direction: IngressSwitchDirection,
    store: IngressStateStore,
    rollback_snapshot: Option<PathBuf>,
    checkpoint: AtomicJsonStore<SwitchCheckpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SwitchCheckpoint {
    schema_version: u32,
    direction: String,
    rollback_snapshot: PathBuf,
}

impl IngressSwitchDriver {
    /// 검증 설정, 방향과 process-restart checkpoint를 묶습니다.
    ///
    /// # Errors
    ///
    /// path 계약 또는 기존 checkpoint drift를 반환합니다.
    pub fn new(
        config: IngressSwitchConfig,
        direction: IngressSwitchDirection,
        checkpoint_path: impl Into<PathBuf>,
    ) -> Result<Self, IngressStateError> {
        validate_switch_config(&config)?;
        let checkpoint = AtomicJsonStore::new(checkpoint_path.into());
        let rollback_snapshot = if checkpoint.path().exists() {
            let record: SwitchCheckpoint = checkpoint.read()?;
            if record.schema_version != SWITCH_SCHEMA_VERSION
                || record.direction != direction_name(direction)
            {
                return Err(IngressStateError::Contract(
                    "ingress switch checkpoint가 다른 방향 또는 schema입니다".to_owned(),
                ));
            }
            Some(record.rollback_snapshot)
        } else {
            None
        };
        let store = IngressStateStore::new(config.state.clone());
        Ok(Self {
            config,
            direction,
            store,
            rollback_snapshot,
            checkpoint,
        })
    }

    /// 생성된 rollback snapshot path입니다.
    #[must_use]
    pub fn rollback_snapshot(&self) -> Option<&Path> {
        self.rollback_snapshot.as_deref()
    }

    fn run(&mut self, phase: OperationPhase) -> Result<u64, IngressStateError> {
        match phase {
            OperationPhase::Preflight => self.preflight().map(|()| 0),
            OperationPhase::Snapshot => self.snapshot().map(|()| 0),
            OperationPhase::StageRelease => {
                switch_snapshot::stage_release(&self.config, &self.store, self.direction)
                    .map(|()| 0)
            }
            OperationPhase::ValidateCandidate => self.validate_candidate().map(|()| 0),
            OperationPhase::SwitchIngress => self.switch(),
            OperationPhase::VerifyTarget => self.verify_target().map(|()| 0),
            OperationPhase::Commit => Ok(0),
            other => Err(IngressStateError::Contract(format!(
                "ingress switch driver가 지원하지 않는 단계입니다: {other:?}"
            ))),
        }
    }

    fn preflight(&mut self) -> Result<(), IngressStateError> {
        self.store.validate_runtime_boundary()?;
        let active = self.logical(&self.config.active_config)?;
        let active_guard = self.logical(&self.config.active_guard_config)?;
        require_regular(&active)?;
        require_regular(&active_guard)?;
        if self.config.stage_root.is_none() {
            require_regular(&self.candidate()?)?;
        }
        let edge = self.store.service_state(EDGE_SERVICE)?;
        validate_service_field(&edge.active)?;
        Ok(())
    }

    fn snapshot(&mut self) -> Result<(), IngressStateError> {
        let path = switch_snapshot::create(&self.config, &mut self.store)?;
        self.checkpoint.write(&SwitchCheckpoint {
            schema_version: SWITCH_SCHEMA_VERSION,
            direction: direction_name(self.direction).to_owned(),
            rollback_snapshot: path.clone(),
        })?;
        self.rollback_snapshot = Some(path);
        Ok(())
    }

    fn validate_candidate(&mut self) -> Result<(), IngressStateError> {
        let candidate = self.candidate()?;
        require_regular(&candidate)?;
        if self.config.state.test_root.is_some() {
            return Ok(());
        }
        self.store.validate_nginx_file(&candidate)?;
        if self.direction == IngressSwitchDirection::ToEdge {
            let active_guard = self.logical(&self.config.active_guard_config)?;
            let checked = self.store.runner.run(
                crate::OwnedProgram::VpsGuard,
                &[
                    "check-config".to_owned(),
                    "--config".to_owned(),
                    active_guard.display().to_string(),
                ],
                None,
                &[],
            )?;
            self.store.record_audit(checked.audit);
        }
        Ok(())
    }

    fn switch(&mut self) -> Result<u64, IngressStateError> {
        let started = Instant::now();
        let edge = self.store.service_state(EDGE_SERVICE)?;
        let desired = ServiceRecord {
            unit: EDGE_SERVICE.to_owned(),
            enabled: edge.enabled,
            active: if self.direction == IngressSwitchDirection::ToEdge {
                "active".to_owned()
            } else {
                "inactive".to_owned()
            },
        };
        if self.direction == IngressSwitchDirection::ToEdge {
            self.store.set_service_activity(&desired)?;
            self.wait_edge_ready()?;
        }
        let candidate = self.candidate()?;
        let active = self.logical(&self.config.active_config)?;
        self.store.ensure_safe_parent(&active)?;
        replace_file(
            &candidate,
            &active,
            &FileRecord {
                logical: self.config.active_config.display().to_string(),
                payload: String::new(),
                presence: Presence::Present,
                mode: 0o644,
                uid: None,
                gid: None,
            },
            self.config.state.test_root.is_none(),
        )?;
        self.reload_nginx()?;
        if self.direction == IngressSwitchDirection::ToNginx {
            self.store.set_service_activity(&desired)?;
        }
        self.store
            .set_fixture_topology(self.direction == IngressSwitchDirection::ToEdge)?;
        Ok(started.elapsed().as_millis().try_into().unwrap_or(u64::MAX))
    }

    fn verify_target(&mut self) -> Result<(), IngressStateError> {
        let active = self.logical(&self.config.active_config)?;
        let candidate = self.candidate()?;
        if fs::read(&active).map_err(|source| io_error("read_active", &active, source))?
            != fs::read(&candidate)
                .map_err(|source| io_error("read_candidate", &candidate, source))?
        {
            return Err(IngressStateError::Contract(
                "active ingress가 candidate와 다릅니다".to_owned(),
            ));
        }
        let edge = self.store.service_state(EDGE_SERVICE)?;
        let active_edge = matches!(edge.active.as_str(), "active" | "activating" | "reloading");
        if active_edge != (self.direction == IngressSwitchDirection::ToEdge) {
            return Err(IngressStateError::Contract(
                "edge service가 target 방향과 다릅니다".to_owned(),
            ));
        }
        if self.config.fixture_probe_failure {
            return Err(IngressStateError::Contract(
                "fixture public probe 실패".to_owned(),
            ));
        }
        let header = self.store.public_edge_header()?;
        if header != (self.direction == IngressSwitchDirection::ToEdge) {
            return Err(IngressStateError::Contract(
                "public response header가 target 방향과 다릅니다".to_owned(),
            ));
        }
        Ok(())
    }

    fn rollback_now(&mut self) -> Result<u64, IngressStateError> {
        let snapshot = self.rollback_snapshot.clone().ok_or_else(|| {
            IngressStateError::Contract("ingress rollback snapshot이 없습니다".to_owned())
        })?;
        let edge_service = switch_snapshot::restore(&self.config, &self.store, &snapshot)?;
        let started = Instant::now();
        let active_edge = matches!(
            edge_service.active.as_str(),
            "active" | "activating" | "reloading"
        );
        if active_edge {
            self.store.set_service_activity(&edge_service)?;
            self.wait_edge_ready()?;
        }
        self.reload_nginx()?;
        if !active_edge {
            self.store.set_service_activity(&edge_service)?;
        }
        self.store.set_fixture_topology(matches!(
            edge_service.active.as_str(),
            "active" | "activating" | "reloading"
        ))?;
        Ok(started.elapsed().as_millis().try_into().unwrap_or(u64::MAX))
    }

    fn reload_nginx(&mut self) -> Result<(), IngressStateError> {
        if self.config.state.test_root.is_some() {
            return Ok(());
        }
        let checked =
            self.store
                .runner
                .run(crate::OwnedProgram::Nginx, &["-t".to_owned()], None, &[])?;
        self.store.record_audit(checked.audit);
        let reloaded = self.store.runner.run(
            crate::OwnedProgram::Systemctl,
            &["reload".to_owned(), "nginx.service".to_owned()],
            None,
            &[],
        )?;
        self.store.record_audit(reloaded.audit);
        Ok(())
    }

    fn wait_edge_ready(&mut self) -> Result<(), IngressStateError> {
        if self.config.state.test_root.is_some() {
            return Ok(());
        }
        let output = self.store.runner.run(
            crate::OwnedProgram::Curl,
            &[
                "--fail".to_owned(),
                "--silent".to_owned(),
                "--show-error".to_owned(),
                "--retry".to_owned(),
                "40".to_owned(),
                "--retry-connrefused".to_owned(),
                "--retry-delay".to_owned(),
                "0".to_owned(),
                "--header".to_owned(),
                "Host: www.g7devops.com".to_owned(),
                "http://127.0.0.1:18080/health/live".to_owned(),
            ],
            None,
            &[],
        )?;
        self.store.record_audit(output.audit);
        Ok(())
    }

    fn logical(&self, path: &Path) -> Result<PathBuf, IngressStateError> {
        self.store.logical_path(path.to_str().ok_or_else(|| {
            IngressStateError::Contract("ingress path가 UTF-8이 아닙니다".to_owned())
        })?)
    }

    fn candidate(&self) -> Result<PathBuf, IngressStateError> {
        let logical = match self.direction {
            IngressSwitchDirection::ToEdge => &self.config.edge_candidate,
            IngressSwitchDirection::ToNginx => &self.config.nginx_candidate,
        };
        self.logical(logical)
    }
}

impl OperationDriver for IngressSwitchDriver {
    fn run_phase(
        &mut self,
        plan: &OperationPlan,
        phase: OperationPhase,
        _timeout: Duration,
    ) -> Result<PhaseReport, OperationIssue> {
        if plan.operation != self.direction.operation() {
            return Err(issue(
                "INGRESS_SWITCH_KIND_INVALID",
                "plan 방향이 driver와 다릅니다",
            ));
        }
        let started = Instant::now();
        let interruption = self
            .run(phase)
            .map_err(|error| issue("INGRESS_SWITCH_PHASE_FAILED", &error.to_string()))?;
        Ok(PhaseReport::new(
            phase,
            started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            interruption,
        ))
    }

    fn rollback(
        &mut self,
        _plan: &OperationPlan,
        _timeout: Duration,
    ) -> Result<PhaseReport, OperationIssue> {
        let started = Instant::now();
        let interruption = self
            .rollback_now()
            .map_err(|error| issue("INGRESS_SWITCH_ROLLBACK_FAILED", &error.to_string()))?;
        Ok(PhaseReport::new(
            OperationPhase::Rollback,
            started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            interruption,
        ))
    }
}

/// ingress 후보 전환 plan을 만듭니다.
#[must_use]
pub fn ingress_switch_plan(
    operation_id: &str,
    direction: IngressSwitchDirection,
    config: &IngressSwitchConfig,
) -> OperationPlan {
    let (source, target) = match direction {
        IngressSwitchDirection::ToEdge => (
            IngressTopology::NginxPublic,
            IngressTopology::VpsGuardPublic,
        ),
        IngressSwitchDirection::ToNginx => (
            IngressTopology::VpsGuardPublic,
            IngressTopology::NginxPublic,
        ),
    };
    OperationPlan::new(
        operation_id,
        direction.operation(),
        direction_name(direction),
        source,
        target,
        vec![
            SnapshotResource::IngressFile {
                path: config.active_config.clone(),
            },
            SnapshotResource::OwnedPath {
                path: config.active_guard_config.clone(),
            },
            SnapshotResource::OwnedPath {
                path: config.edge_candidate.clone(),
            },
            SnapshotResource::OwnedPath {
                path: config.nginx_candidate.clone(),
            },
            SnapshotResource::Service {
                unit: EDGE_SERVICE.to_owned(),
            },
            SnapshotResource::ListenerInventory,
        ],
    )
}
