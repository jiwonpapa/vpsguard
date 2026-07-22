//! OPS-011 Apache public TLS 유지형 loopback ingress 전환과 exact rollback입니다.
//!
//! Apache는 public 80/443과 인증서를 계속 소유합니다. Guarded 후보는 요청을
//! loopback Edge로 보내고 Edge는 별도 loopback Apache origin으로 전달합니다.

#[cfg(test)]
mod tests;

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::files::{
    copy_snapshot_file, create_private_dir, create_private_dir_all, remove_file_if_present,
    replace_file, replace_symlink, sync_dir, timestamp, write_checksums, write_private,
};
use super::format::{FileRecord, Presence, ServiceRecord, hash_file, verify_checksums};
use super::{
    APACHE_SERVICE, EDGE_SERVICE, IngressStateConfig, IngressStateError, IngressStateStore,
    io_error,
};
use crate::{
    AtomicJsonStore, IngressTopology, OperationDriver, OperationIssue, OperationKind,
    OperationPhase, OperationPlan, OwnedProgram, PhaseReport, SnapshotResource,
};

const APACHE_INGRESS_SCHEMA_VERSION: u32 = 1;
const ACTIVE_VHOST: &str = "/etc/apache2/sites-available/gnuboard5.conf";
const PUBLIC_LINK: &str = "/etc/apache2/sites-enabled/gnuboard5.conf";
const GUARDED_CANDIDATE: &str = "/etc/vps-guard/apache/gnuboard5-guarded.conf";
const BYPASS_CANDIDATE: &str = "/etc/vps-guard/apache/gnuboard5-bypass.conf";
const ORIGIN_VHOST: &str = "/etc/apache2/sites-available/vpsguard-origin.conf";
const ORIGIN_LINK: &str = "/etc/apache2/sites-enabled/vpsguard-origin.conf";
const ORIGIN_PORTS: &str = "/etc/apache2/conf-available/vpsguard-origin-ports.conf";
const ORIGIN_PORTS_LINK: &str = "/etc/apache2/conf-enabled/vpsguard-origin-ports.conf";
const ACTIVE_GUARD_CONFIG: &str = "/etc/vps-guard/config.toml";
const CERTIFICATE: &str = "/etc/ssl/gnuboard5/gnuboard5.local.pem";
const PUBLIC_LINK_TARGET: &str = "../sites-available/gnuboard5.conf";
const ORIGIN_LINK_TARGET: &str = "../sites-available/vpsguard-origin.conf";
const ORIGIN_PORTS_LINK_TARGET: &str = "../conf-available/vpsguard-origin-ports.conf";
const PROXY_LOAD: &str = "/etc/apache2/mods-enabled/proxy.load";
const PROXY_CONF: &str = "/etc/apache2/mods-enabled/proxy.conf";
const PROXY_HTTP_LOAD: &str = "/etc/apache2/mods-enabled/proxy_http.load";
const REMOTEIP_LOAD: &str = "/etc/apache2/mods-enabled/remoteip.load";
const PROXY_LOAD_SOURCE: &str = "/etc/apache2/mods-available/proxy.load";
const PROXY_CONF_SOURCE: &str = "/etc/apache2/mods-available/proxy.conf";
const PROXY_HTTP_LOAD_SOURCE: &str = "/etc/apache2/mods-available/proxy_http.load";
const REMOTEIP_LOAD_SOURCE: &str = "/etc/apache2/mods-available/remoteip.load";
const PROXY_LOAD_TARGET: &str = "../mods-available/proxy.load";
const PROXY_CONF_TARGET: &str = "../mods-available/proxy.conf";
const PROXY_HTTP_LOAD_TARGET: &str = "../mods-available/proxy_http.load";
const REMOTEIP_LOAD_TARGET: &str = "../mods-available/remoteip.load";

static SNAPSHOT_SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// Apache public request path 전환 방향입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApacheIngressDirection {
    /// Apache public TLS 뒤에 loopback VPSGuard를 편입합니다.
    ToEdge,
    /// VPSGuard를 우회하고 Apache가 application을 직접 제공합니다.
    ToApache,
}

impl ApacheIngressDirection {
    fn operation(self) -> OperationKind {
        match self {
            Self::ToEdge => OperationKind::BypassDisable,
            Self::ToApache => OperationKind::BypassEnable,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::ToEdge => "to-edge",
            Self::ToApache => "to-apache",
        }
    }
}

/// Apache pilot의 bounded path, service와 public probe 설정입니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApacheIngressConfig {
    /// 공통 filesystem·service fixture와 probe 설정입니다.
    pub state: IngressStateConfig,
    /// 현재 활성 public vhost 원본 파일입니다.
    pub active_vhost: PathBuf,
    /// 활성 public vhost symlink입니다.
    pub public_link: PathBuf,
    /// VPSGuard를 경유하는 public vhost 후보입니다.
    pub guarded_candidate: PathBuf,
    /// Apache direct bypass public vhost 후보입니다.
    pub bypass_candidate: PathBuf,
    /// loopback Apache origin vhost입니다.
    pub origin_vhost: PathBuf,
    /// loopback origin enabled symlink입니다.
    pub origin_link: PathBuf,
    /// loopback listener include입니다.
    pub origin_ports: PathBuf,
    /// loopback listener enabled symlink입니다.
    pub origin_ports_link: PathBuf,
    /// 활성 VPSGuard config입니다.
    pub active_guard_config: PathBuf,
    /// fingerprint만 read-back할 public certificate입니다.
    pub certificate: PathBuf,
    /// 개발용 TLS public probe에서만 신뢰할 공개 CA certificate입니다.
    pub probe_ca_certificate: Option<PathBuf>,
    /// 외부 builder가 만든 선택 staging directory입니다.
    pub stage_root: Option<PathBuf>,
    /// snapshot과 transaction의 private root입니다.
    pub backup_root: PathBuf,
    /// fixture public probe 실패 주입입니다.
    pub fixture_probe_failure: bool,
}

impl ApacheIngressConfig {
    /// 실제 gnuboard5 pilot 경계를 만듭니다.
    #[must_use]
    pub fn production(probe_url: impl Into<String>) -> Self {
        let backup_root = PathBuf::from("/var/lib/vps-guard/backups/apache-ingress");
        let mut state = IngressStateConfig::production(backup_root.join("snapshots"));
        state.server_name = "gnuboard5.local".to_owned();
        let probe_url = probe_url.into();
        state.public_probe_url = if probe_url.is_empty() {
            "https://gnuboard5.local/".to_owned()
        } else {
            probe_url
        };
        Self::base(state, backup_root)
    }

    /// OS mutation 없는 격리 fixture 경계를 만듭니다.
    #[must_use]
    pub fn fixture(
        root: impl Into<PathBuf>,
        state_root: impl Into<PathBuf>,
        backup_root: impl Into<PathBuf>,
    ) -> Self {
        let backup_root = backup_root.into();
        let state = IngressStateConfig::fixture(root, state_root, backup_root.join("snapshots"));
        Self::base(state, backup_root)
    }

    fn base(state: IngressStateConfig, backup_root: PathBuf) -> Self {
        let production = state.test_root.is_none();
        Self {
            state,
            active_vhost: PathBuf::from(ACTIVE_VHOST),
            public_link: PathBuf::from(PUBLIC_LINK),
            guarded_candidate: PathBuf::from(GUARDED_CANDIDATE),
            bypass_candidate: PathBuf::from(BYPASS_CANDIDATE),
            origin_vhost: PathBuf::from(ORIGIN_VHOST),
            origin_link: PathBuf::from(ORIGIN_LINK),
            origin_ports: PathBuf::from(ORIGIN_PORTS),
            origin_ports_link: PathBuf::from(ORIGIN_PORTS_LINK),
            active_guard_config: PathBuf::from(ACTIVE_GUARD_CONFIG),
            certificate: PathBuf::from(CERTIFICATE),
            probe_ca_certificate: production
                .then(|| PathBuf::from("/etc/vps-guard/gnuboard5-lab-rootCA.pem")),
            stage_root: None,
            backup_root,
            fixture_probe_failure: false,
        }
    }
}

/// Apache 후보 전환을 operation engine 단계로 수행하는 driver입니다.
#[derive(Debug)]
pub struct ApacheIngressDriver {
    config: ApacheIngressConfig,
    direction: ApacheIngressDirection,
    store: IngressStateStore,
    rollback_snapshot: Option<PathBuf>,
    checkpoint: AtomicJsonStore<ApacheCheckpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ApacheCheckpoint {
    schema_version: u32,
    direction: String,
    rollback_snapshot: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum NodeKind {
    Absent,
    Regular,
    Symlink,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NodeRecord {
    logical: String,
    payload: Option<String>,
    kind: NodeKind,
    mode: u32,
    uid: Option<u32>,
    gid: Option<u32>,
    target: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ApacheSnapshot {
    schema_version: u32,
    machine_id_sha256: String,
    nodes: Vec<NodeRecord>,
    services: Vec<ServiceRecord>,
    public_edge_header: bool,
    certificate_fingerprint: String,
    protected_listeners: BTreeSet<String>,
}

impl ApacheIngressDriver {
    /// 검증 설정, 방향과 process restart checkpoint를 묶습니다.
    ///
    /// # Errors
    ///
    /// path allowlist 또는 기존 checkpoint drift를 반환합니다.
    pub fn new(
        config: ApacheIngressConfig,
        direction: ApacheIngressDirection,
        checkpoint_path: impl Into<PathBuf>,
    ) -> Result<Self, IngressStateError> {
        validate_config(&config)?;
        let checkpoint = AtomicJsonStore::new(checkpoint_path.into());
        let rollback_snapshot = if checkpoint.path().exists() {
            let record: ApacheCheckpoint = checkpoint.read()?;
            if record.schema_version != APACHE_INGRESS_SCHEMA_VERSION
                || record.direction != direction.name()
            {
                return Err(IngressStateError::Contract(
                    "Apache ingress checkpoint가 다른 방향 또는 schema입니다".to_owned(),
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

    /// 생성된 exact rollback snapshot입니다.
    #[must_use]
    pub fn rollback_snapshot(&self) -> Option<&Path> {
        self.rollback_snapshot.as_deref()
    }

    fn run(&mut self, phase: OperationPhase) -> Result<u64, IngressStateError> {
        match phase {
            OperationPhase::Preflight => self.preflight().map(|()| 0),
            OperationPhase::Snapshot => self.snapshot().map(|()| 0),
            OperationPhase::StageRelease => self.stage_release().map(|()| 0),
            OperationPhase::ValidateCandidate => self.validate_candidate().map(|()| 0),
            OperationPhase::SwitchIngress => self.switch(),
            OperationPhase::VerifyTarget => self.verify_target().map(|()| 0),
            OperationPhase::Commit => Ok(0),
            other => Err(IngressStateError::Contract(format!(
                "Apache ingress driver가 지원하지 않는 단계입니다: {other:?}"
            ))),
        }
    }

    fn preflight(&mut self) -> Result<(), IngressStateError> {
        self.store.validate_runtime_boundary()?;
        require_regular(&self.logical(&self.config.active_vhost)?)?;
        self.verify_public_link()?;
        require_regular(&self.logical(&self.config.active_guard_config)?)?;
        require_regular(&self.logical(&self.config.certificate)?)?;
        if let Some(certificate) = &self.config.probe_ca_certificate {
            require_regular(&self.logical(certificate)?)?;
        }
        if self.config.stage_root.is_none() {
            require_regular(&self.candidate()?)?;
        }
        let apache = self.store.service_state(APACHE_SERVICE)?;
        if !matches!(apache.active.as_str(), "active" | "reloading") {
            return Err(IngressStateError::Contract(
                "Apache service가 active가 아닙니다".to_owned(),
            ));
        }
        let _edge = self.store.service_state(EDGE_SERVICE)?;
        Ok(())
    }

    fn snapshot(&mut self) -> Result<(), IngressStateError> {
        let path = self.create_snapshot()?;
        self.checkpoint.write(&ApacheCheckpoint {
            schema_version: APACHE_INGRESS_SCHEMA_VERSION,
            direction: self.direction.name().to_owned(),
            rollback_snapshot: path.clone(),
        })?;
        self.rollback_snapshot = Some(path);
        Ok(())
    }

    fn stage_release(&mut self) -> Result<(), IngressStateError> {
        let Some(stage) = self.config.stage_root.clone() else {
            return Ok(());
        };
        validate_stage(&stage)?;
        for file in staged_files() {
            require_regular(&stage.join(file))?;
        }
        self.install(
            &stage.join("gnuboard5-guarded.conf"),
            &self.config.guarded_candidate,
            0o644,
        )?;
        self.install(
            &stage.join("gnuboard5-bypass.conf"),
            &self.config.bypass_candidate,
            0o644,
        )?;
        self.install(
            &stage.join("vpsguard-origin.conf"),
            &self.config.origin_vhost,
            0o644,
        )?;
        self.install(
            &stage.join("vpsguard-origin-ports.conf"),
            &self.config.origin_ports,
            0o644,
        )?;
        self.install(
            &stage.join("vps-guard.ingress.toml"),
            &self.config.active_guard_config,
            0o640,
        )?;
        let origin_link = self.logical(&self.config.origin_link)?;
        self.store.ensure_safe_parent(&origin_link)?;
        replace_symlink(&origin_link, Path::new(ORIGIN_LINK_TARGET))?;
        let ports_link = self.logical(&self.config.origin_ports_link)?;
        self.store.ensure_safe_parent(&ports_link)?;
        replace_symlink(&ports_link, Path::new(ORIGIN_PORTS_LINK_TARGET))?;
        for (link, target) in proxy_module_links() {
            let link = self.logical(Path::new(link))?;
            self.store.ensure_safe_parent(&link)?;
            replace_symlink(&link, Path::new(target))?;
        }
        Ok(())
    }

    fn validate_candidate(&mut self) -> Result<(), IngressStateError> {
        require_regular(&self.candidate()?)?;
        if self.direction == ApacheIngressDirection::ToEdge {
            require_regular(&self.logical(&self.config.origin_vhost)?)?;
            require_regular(&self.logical(&self.config.origin_ports)?)?;
            require_symlink(&self.logical(&self.config.origin_link)?, ORIGIN_LINK_TARGET)?;
            require_symlink(
                &self.logical(&self.config.origin_ports_link)?,
                ORIGIN_PORTS_LINK_TARGET,
            )?;
            for (link, target) in proxy_module_links() {
                require_symlink(&self.logical(Path::new(link))?, target)?;
            }
            if self.config.state.test_root.is_none() {
                let config = self.logical(&self.config.active_guard_config)?;
                let output = self.store.runner.run(
                    OwnedProgram::VpsGuard,
                    &[
                        "check-config".to_owned(),
                        "--config".to_owned(),
                        config.display().to_string(),
                    ],
                    None,
                    &[],
                )?;
                self.store.record_audit(output.audit);
            }
        }
        Ok(())
    }

    fn switch(&mut self) -> Result<u64, IngressStateError> {
        let started = Instant::now();
        let edge = self.store.service_state(EDGE_SERVICE)?;
        let desired = ServiceRecord {
            unit: EDGE_SERVICE.to_owned(),
            enabled: edge.enabled,
            active: if self.direction == ApacheIngressDirection::ToEdge {
                "active".to_owned()
            } else {
                "inactive".to_owned()
            },
        };
        if self.direction == ApacheIngressDirection::ToEdge {
            self.store.set_service_activity(&desired)?;
            self.wait_edge_ready()?;
        }
        let candidate = self.candidate()?;
        let active = self.logical(&self.config.active_vhost)?;
        self.store.ensure_safe_parent(&active)?;
        replace_file(
            &candidate,
            &active,
            &FileRecord {
                logical: self.config.active_vhost.display().to_string(),
                payload: String::new(),
                presence: Presence::Present,
                mode: 0o644,
                uid: None,
                gid: None,
            },
            self.config.state.test_root.is_none(),
        )?;
        self.reload_apache()?;
        if self.direction == ApacheIngressDirection::ToApache {
            self.store.set_service_activity(&desired)?;
        }
        self.store
            .set_fixture_topology(self.direction == ApacheIngressDirection::ToEdge)?;
        Ok(started.elapsed().as_millis().try_into().unwrap_or(u64::MAX))
    }

    fn verify_target(&mut self) -> Result<(), IngressStateError> {
        if self.config.fixture_probe_failure {
            return Err(IngressStateError::Contract(
                "fixture Apache public probe 실패".to_owned(),
            ));
        }
        let active = self.logical(&self.config.active_vhost)?;
        if fs::read(&active).map_err(|source| io_error("read_apache_active", &active, source))?
            != fs::read(self.candidate()?)
                .map_err(|source| io_error("read_apache_candidate", &active, source))?
        {
            return Err(IngressStateError::Contract(
                "Apache active vhost가 candidate와 다릅니다".to_owned(),
            ));
        }
        self.verify_public_link()?;
        let edge = self.store.service_state(EDGE_SERVICE)?;
        let edge_active = matches!(edge.active.as_str(), "active" | "activating" | "reloading");
        if edge_active != (self.direction == ApacheIngressDirection::ToEdge) {
            return Err(IngressStateError::Contract(
                "edge service가 Apache target 방향과 다릅니다".to_owned(),
            ));
        }
        if self.public_edge_header()? != (self.direction == ApacheIngressDirection::ToEdge) {
            return Err(IngressStateError::Contract(
                "Apache public response header가 target 방향과 다릅니다".to_owned(),
            ));
        }
        self.verify_protected_snapshot()
    }

    fn rollback_now(&mut self) -> Result<u64, IngressStateError> {
        let snapshot = self.rollback_snapshot.clone().ok_or_else(|| {
            IngressStateError::Contract("Apache rollback snapshot이 없습니다".to_owned())
        })?;
        let record = self.restore_snapshot(&snapshot)?;
        let started = Instant::now();
        let edge = record
            .services
            .iter()
            .find(|service| service.unit == EDGE_SERVICE)
            .ok_or_else(|| {
                IngressStateError::Contract("edge service snapshot이 없습니다".to_owned())
            })?
            .clone();
        let edge_active = matches!(edge.active.as_str(), "active" | "activating" | "reloading");
        if edge_active {
            self.store.set_service_activity(&edge)?;
            self.wait_edge_ready()?;
        }
        self.reload_apache()?;
        if !edge_active {
            self.store.set_service_activity(&edge)?;
        }
        self.store.set_fixture_topology(record.public_edge_header)?;
        self.verify_snapshot_protections(&record)?;
        Ok(started.elapsed().as_millis().try_into().unwrap_or(u64::MAX))
    }

    fn create_snapshot(&mut self) -> Result<PathBuf, IngressStateError> {
        create_private_dir_all(&self.config.backup_root)?;
        let sequence = SNAPSHOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = self.config.backup_root.join(format!(
            "apache-{}-{}{:06}",
            timestamp(),
            std::process::id(),
            sequence % 1_000_000
        ));
        create_private_dir(&path)?;
        let mut nodes = Vec::new();
        for (index, logical) in self.snapshot_paths().iter().enumerate() {
            nodes.push(self.snapshot_node(logical, &path, index)?);
        }
        let record = ApacheSnapshot {
            schema_version: APACHE_INGRESS_SCHEMA_VERSION,
            machine_id_sha256: self.store.machine_id_hash()?,
            nodes,
            services: vec![
                self.store.service_state(APACHE_SERVICE)?,
                self.store.service_state(EDGE_SERVICE)?,
            ],
            public_edge_header: self.public_edge_header()?,
            certificate_fingerprint: self.certificate_fingerprint()?,
            protected_listeners: self.store.protected_listeners()?,
        };
        write_private(
            &path.join("manifest.json"),
            &serde_json::to_vec_pretty(&record)?,
        )?;
        write_checksums(&path)?;
        sync_dir(&path)?;
        Ok(path)
    }

    fn snapshot_node(
        &self,
        logical: &Path,
        snapshot: &Path,
        index: usize,
    ) -> Result<NodeRecord, IngressStateError> {
        let source = self.logical(logical)?;
        let metadata = match fs::symlink_metadata(&source) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(source_error) => {
                return Err(io_error("apache_snapshot_metadata", &source, source_error));
            }
        };
        let Some(metadata) = metadata else {
            return Ok(NodeRecord {
                logical: logical.display().to_string(),
                payload: None,
                kind: NodeKind::Absent,
                mode: 0,
                uid: None,
                gid: None,
                target: None,
            });
        };
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(&source)
                .map_err(|error| io_error("apache_snapshot_read_link", &source, error))?;
            return Ok(NodeRecord {
                logical: logical.display().to_string(),
                payload: None,
                kind: NodeKind::Symlink,
                mode: metadata.mode() & 0o7777,
                uid: Some(metadata.uid()),
                gid: Some(metadata.gid()),
                target: Some(target),
            });
        }
        if !metadata.is_file() {
            return Err(IngressStateError::Contract(format!(
                "Apache snapshot 대상이 regular file 또는 symlink가 아닙니다: {}",
                source.display()
            )));
        }
        let payload = format!("node-{index:02}.bin");
        copy_snapshot_file(&source, &snapshot.join(&payload), &metadata)?;
        Ok(NodeRecord {
            logical: logical.display().to_string(),
            payload: Some(payload),
            kind: NodeKind::Regular,
            mode: metadata.mode() & 0o7777,
            uid: Some(metadata.uid()),
            gid: Some(metadata.gid()),
            target: None,
        })
    }

    fn restore_snapshot(&self, snapshot: &Path) -> Result<ApacheSnapshot, IngressStateError> {
        let record = self.load_snapshot(snapshot)?;
        for node in &record.nodes {
            let logical = Path::new(&node.logical);
            let destination = self.logical(logical)?;
            self.store.ensure_safe_parent(&destination)?;
            match node.kind {
                NodeKind::Absent => remove_file_if_present(&destination)?,
                NodeKind::Symlink => replace_symlink(
                    &destination,
                    node.target.as_deref().ok_or_else(|| {
                        IngressStateError::Contract("Apache symlink target이 없습니다".to_owned())
                    })?,
                )?,
                NodeKind::Regular => {
                    let payload = node.payload.as_deref().ok_or_else(|| {
                        IngressStateError::Contract("Apache file payload가 없습니다".to_owned())
                    })?;
                    replace_file(
                        &snapshot.join(payload),
                        &destination,
                        &FileRecord {
                            logical: node.logical.clone(),
                            payload: payload.to_owned(),
                            presence: Presence::Present,
                            mode: node.mode,
                            uid: node.uid,
                            gid: node.gid,
                        },
                        self.config.state.test_root.is_none(),
                    )?;
                }
            }
        }
        Ok(record)
    }

    fn load_snapshot(&self, snapshot: &Path) -> Result<ApacheSnapshot, IngressStateError> {
        let name = snapshot.file_name().and_then(|value| value.to_str());
        if snapshot.parent() != Some(self.config.backup_root.as_path())
            || name.is_none_or(|value| !value.starts_with("apache-"))
        {
            return Err(IngressStateError::Contract(
                "Apache snapshot이 bounded root의 direct child가 아닙니다".to_owned(),
            ));
        }
        verify_checksums(snapshot)?;
        let record: ApacheSnapshot = serde_json::from_slice(
            &fs::read(snapshot.join("manifest.json"))
                .map_err(|error| io_error("read_apache_manifest", snapshot, error))?,
        )?;
        if record.schema_version != APACHE_INGRESS_SCHEMA_VERSION
            || record.machine_id_sha256 != self.store.machine_id_hash()?
            || record.nodes.len() != self.snapshot_paths().len()
        {
            return Err(IngressStateError::Contract(
                "Apache snapshot schema, machine 또는 node 수가 다릅니다".to_owned(),
            ));
        }
        let expected: BTreeSet<_> = self
            .snapshot_paths()
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        let actual: BTreeSet<_> = record
            .nodes
            .iter()
            .map(|node| node.logical.clone())
            .collect();
        if expected != actual || record.services.len() != 2 {
            return Err(IngressStateError::Contract(
                "Apache snapshot inventory가 config와 다릅니다".to_owned(),
            ));
        }
        Ok(record)
    }

    fn verify_protected_snapshot(&mut self) -> Result<(), IngressStateError> {
        let snapshot = self.rollback_snapshot.clone().ok_or_else(|| {
            IngressStateError::Contract("Apache 보호 경계 snapshot이 없습니다".to_owned())
        })?;
        let record = self.load_snapshot(&snapshot)?;
        self.verify_snapshot_protections(&record)
    }

    fn verify_snapshot_protections(
        &mut self,
        record: &ApacheSnapshot,
    ) -> Result<(), IngressStateError> {
        if self.certificate_fingerprint()? != record.certificate_fingerprint {
            return Err(IngressStateError::Contract(
                "Apache 전환 전후 certificate fingerprint가 다릅니다".to_owned(),
            ));
        }
        if self.store.protected_listeners()? != record.protected_listeners {
            return Err(IngressStateError::Contract(
                "Apache 전환 전후 SSH 또는 비-web listener가 다릅니다".to_owned(),
            ));
        }
        Ok(())
    }

    fn install(&self, source: &Path, logical: &Path, mode: u32) -> Result<(), IngressStateError> {
        require_regular(source)?;
        let destination = self.logical(logical)?;
        self.store.ensure_safe_parent(&destination)?;
        replace_file(
            source,
            &destination,
            &FileRecord {
                logical: logical.display().to_string(),
                payload: String::new(),
                presence: Presence::Present,
                mode,
                uid: None,
                gid: None,
            },
            self.config.state.test_root.is_none(),
        )
    }

    fn reload_apache(&mut self) -> Result<(), IngressStateError> {
        if self.config.state.test_root.is_some() {
            return Ok(());
        }
        let checked = self.store.runner.run(
            OwnedProgram::Apache2ctl,
            &["configtest".to_owned()],
            None,
            &[],
        )?;
        self.store.record_audit(checked.audit);
        let reloaded = self.store.runner.run(
            OwnedProgram::Systemctl,
            &["reload".to_owned(), APACHE_SERVICE.to_owned()],
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
            OwnedProgram::Curl,
            &[
                "--fail".to_owned(),
                "--silent".to_owned(),
                "--show-error".to_owned(),
                "--retry".to_owned(),
                "40".to_owned(),
                "--retry-connrefused".to_owned(),
                "--retry-delay".to_owned(),
                "0".to_owned(),
                "--retry-max-time".to_owned(),
                "5".to_owned(),
                "--max-time".to_owned(),
                "5".to_owned(),
                "--header".to_owned(),
                format!("Host: {}", self.config.state.server_name),
                "http://127.0.0.1:18080/health/live".to_owned(),
            ],
            None,
            &[],
        )?;
        self.store.record_audit(output.audit);
        Ok(())
    }

    fn public_edge_header(&mut self) -> Result<bool, IngressStateError> {
        if self.config.state.test_root.is_some() {
            return self.store.public_edge_header();
        }
        let mut arguments = vec![
            "--fail".to_owned(),
            "--silent".to_owned(),
            "--show-error".to_owned(),
            "--max-time".to_owned(),
            "15".to_owned(),
        ];
        if let Some(certificate) = &self.config.probe_ca_certificate {
            arguments.extend([
                "--cacert".to_owned(),
                self.logical(certificate)?.display().to_string(),
            ]);
        }
        arguments.extend([
            "--resolve".to_owned(),
            format!("{}:443:127.0.0.1", self.config.state.server_name),
            "--dump-header".to_owned(),
            "-".to_owned(),
            "--output".to_owned(),
            "/dev/null".to_owned(),
            self.config.state.public_probe_url.clone(),
        ]);
        let output = self
            .store
            .runner
            .run(OwnedProgram::Curl, &arguments, None, &[])?;
        let present = output.stdout.lines().any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case("x-vps-guard")
                    && value.trim().eq_ignore_ascii_case("guard-edge")
            })
        });
        self.store.record_audit(output.audit);
        Ok(present)
    }

    fn certificate_fingerprint(&mut self) -> Result<String, IngressStateError> {
        let certificate = self.logical(&self.config.certificate)?;
        if self.config.state.test_root.is_some() {
            return hash_file(&certificate);
        }
        let output = self.store.runner.run(
            OwnedProgram::Openssl,
            &[
                "x509".to_owned(),
                "-in".to_owned(),
                certificate.display().to_string(),
                "-noout".to_owned(),
                "-fingerprint".to_owned(),
                "-sha256".to_owned(),
            ],
            None,
            &[],
        )?;
        let fingerprint = output
            .stdout
            .lines()
            .next()
            .map(str::trim)
            .unwrap_or_default();
        if fingerprint.is_empty() || fingerprint.len() > 256 {
            return Err(IngressStateError::Contract(
                "Apache certificate fingerprint가 비었거나 과대합니다".to_owned(),
            ));
        }
        let value = fingerprint.to_owned();
        self.store.record_audit(output.audit);
        Ok(value)
    }

    fn verify_public_link(&self) -> Result<(), IngressStateError> {
        require_symlink(&self.logical(&self.config.public_link)?, PUBLIC_LINK_TARGET)
    }

    fn candidate(&self) -> Result<PathBuf, IngressStateError> {
        self.logical(match self.direction {
            ApacheIngressDirection::ToEdge => &self.config.guarded_candidate,
            ApacheIngressDirection::ToApache => &self.config.bypass_candidate,
        })
    }

    fn logical(&self, path: &Path) -> Result<PathBuf, IngressStateError> {
        self.store.logical_path(path.to_str().ok_or_else(|| {
            IngressStateError::Contract("Apache ingress path가 UTF-8이 아닙니다".to_owned())
        })?)
    }

    fn snapshot_paths(&self) -> Vec<PathBuf> {
        let mut paths = vec![
            self.config.active_vhost.clone(),
            self.config.public_link.clone(),
            self.config.guarded_candidate.clone(),
            self.config.bypass_candidate.clone(),
            self.config.origin_vhost.clone(),
            self.config.origin_link.clone(),
            self.config.origin_ports.clone(),
            self.config.origin_ports_link.clone(),
            self.config.active_guard_config.clone(),
            PathBuf::from(PROXY_LOAD),
            PathBuf::from(PROXY_CONF),
            PathBuf::from(PROXY_HTTP_LOAD),
            PathBuf::from(REMOTEIP_LOAD),
        ];
        if let Some(certificate) = &self.config.probe_ca_certificate {
            paths.push(certificate.clone());
        }
        paths
    }
}

impl OperationDriver for ApacheIngressDriver {
    fn run_phase(
        &mut self,
        plan: &OperationPlan,
        phase: OperationPhase,
        _timeout: Duration,
    ) -> Result<PhaseReport, OperationIssue> {
        if plan.operation != self.direction.operation() {
            return Err(issue(
                "APACHE_INGRESS_KIND_INVALID",
                "plan 방향이 Apache driver와 다릅니다",
            ));
        }
        let started = Instant::now();
        let interruption = self
            .run(phase)
            .map_err(|error| issue("APACHE_INGRESS_PHASE_FAILED", &error.to_string()))?;
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
            .map_err(|error| issue("APACHE_INGRESS_ROLLBACK_FAILED", &error.to_string()))?;
        Ok(PhaseReport::new(
            OperationPhase::Rollback,
            started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            interruption,
        ))
    }
}

/// Apache pilot 전환 plan을 만듭니다.
#[must_use]
pub fn apache_ingress_plan(
    operation_id: &str,
    direction: ApacheIngressDirection,
    config: &ApacheIngressConfig,
) -> OperationPlan {
    let (source, target) = match direction {
        ApacheIngressDirection::ToEdge => (
            IngressTopology::ApachePublic,
            IngressTopology::ApacheGuarded,
        ),
        ApacheIngressDirection::ToApache => (
            IngressTopology::ApacheGuarded,
            IngressTopology::ApachePublic,
        ),
    };
    let mut resources = vec![
        SnapshotResource::ApacheIngressFile {
            path: config.active_vhost.clone(),
        },
        SnapshotResource::ApacheIngressSymlink {
            path: config.public_link.clone(),
        },
        SnapshotResource::ApacheIngressFile {
            path: config.origin_vhost.clone(),
        },
        SnapshotResource::ApacheIngressSymlink {
            path: config.origin_link.clone(),
        },
        SnapshotResource::ApacheIngressFile {
            path: config.origin_ports.clone(),
        },
        SnapshotResource::ApacheIngressSymlink {
            path: config.origin_ports_link.clone(),
        },
        SnapshotResource::ApacheIngressSymlink {
            path: PathBuf::from(PROXY_LOAD),
        },
        SnapshotResource::ApacheIngressSymlink {
            path: PathBuf::from(PROXY_CONF),
        },
        SnapshotResource::ApacheIngressSymlink {
            path: PathBuf::from(PROXY_HTTP_LOAD),
        },
        SnapshotResource::ApacheIngressSymlink {
            path: PathBuf::from(REMOTEIP_LOAD),
        },
        SnapshotResource::OwnedPath {
            path: config.active_guard_config.clone(),
        },
        SnapshotResource::OwnedPath {
            path: config.guarded_candidate.clone(),
        },
        SnapshotResource::OwnedPath {
            path: config.bypass_candidate.clone(),
        },
        SnapshotResource::Service {
            unit: APACHE_SERVICE.to_owned(),
        },
        SnapshotResource::Service {
            unit: EDGE_SERVICE.to_owned(),
        },
        SnapshotResource::CertificateFingerprint {
            path: config.certificate.clone(),
        },
        SnapshotResource::ListenerInventory,
    ];
    if let Some(certificate) = &config.probe_ca_certificate {
        resources.push(SnapshotResource::OwnedPath {
            path: certificate.clone(),
        });
    }
    OperationPlan::new(
        operation_id,
        direction.operation(),
        direction.name(),
        source,
        target,
        resources,
    )
}

fn validate_config(config: &ApacheIngressConfig) -> Result<(), IngressStateError> {
    for path in [
        &config.active_vhost,
        &config.public_link,
        &config.guarded_candidate,
        &config.bypass_candidate,
        &config.origin_vhost,
        &config.origin_link,
        &config.origin_ports,
        &config.origin_ports_link,
        &config.active_guard_config,
        &config.certificate,
        &config.backup_root,
    ] {
        validate_absolute(path)?;
    }
    if let Some(certificate) = &config.probe_ca_certificate {
        validate_absolute(certificate)?;
        if !certificate.starts_with("/etc/vps-guard/") {
            return Err(IngressStateError::Contract(
                "Apache probe CA path가 allowlist 밖입니다".to_owned(),
            ));
        }
    }
    if !config
        .active_vhost
        .starts_with("/etc/apache2/sites-available/")
        || !config
            .public_link
            .starts_with("/etc/apache2/sites-enabled/")
        || !config
            .guarded_candidate
            .starts_with("/etc/vps-guard/apache/")
        || !config
            .bypass_candidate
            .starts_with("/etc/vps-guard/apache/")
        || !config
            .origin_vhost
            .starts_with("/etc/apache2/sites-available/")
        || !config
            .origin_link
            .starts_with("/etc/apache2/sites-enabled/")
        || !config
            .origin_ports
            .starts_with("/etc/apache2/conf-available/")
        || !config
            .origin_ports_link
            .starts_with("/etc/apache2/conf-enabled/")
        || config.active_guard_config != Path::new(ACTIVE_GUARD_CONFIG)
        || !(config.certificate.starts_with("/etc/ssl/")
            || config.certificate.starts_with("/etc/letsencrypt/live/"))
    {
        return Err(IngressStateError::Contract(
            "Apache ingress path가 allowlist 밖입니다".to_owned(),
        ));
    }
    if !config.state.public_probe_url.starts_with("https://") {
        return Err(IngressStateError::Contract(
            "Apache public probe URL은 HTTPS여야 합니다".to_owned(),
        ));
    }
    if let Some(stage) = &config.stage_root {
        validate_stage(stage)?;
    }
    if config.state.test_root.is_none() {
        for source in [
            PROXY_LOAD_SOURCE,
            PROXY_CONF_SOURCE,
            PROXY_HTTP_LOAD_SOURCE,
            REMOTEIP_LOAD_SOURCE,
        ] {
            require_regular(Path::new(source))?;
        }
    }
    Ok(())
}

fn validate_stage(stage: &Path) -> Result<(), IngressStateError> {
    let text = stage.to_string_lossy();
    let suffix = text.strip_prefix("/tmp/vpsguard-apache.").ok_or_else(|| {
        IngressStateError::Contract("Apache stage path가 allowlist 밖입니다".to_owned())
    })?;
    if suffix.is_empty()
        || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
        || stage.parent() != Some(Path::new("/tmp"))
    {
        return Err(IngressStateError::Contract(
            "Apache stage path 형식이 잘못됐습니다".to_owned(),
        ));
    }
    let metadata = fs::symlink_metadata(stage)
        .map_err(|error| io_error("apache_stage_metadata", stage, error))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(IngressStateError::Contract(
            "Apache stage가 실제 directory가 아닙니다".to_owned(),
        ));
    }
    Ok(())
}

fn validate_absolute(path: &Path) -> Result<(), IngressStateError> {
    if path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        Ok(())
    } else {
        Err(IngressStateError::Contract(format!(
            "Apache path가 절대 정규 경로가 아닙니다: {}",
            path.display()
        )))
    }
}

fn require_regular(path: &Path) -> Result<(), IngressStateError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("apache_candidate_metadata", path, error))?;
    if metadata.is_file() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(IngressStateError::Contract(format!(
            "Apache candidate가 regular file이 아닙니다: {}",
            path.display()
        )))
    }
}

fn require_symlink(path: &Path, expected: &str) -> Result<(), IngressStateError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("apache_symlink_metadata", path, error))?;
    if !metadata.file_type().is_symlink() {
        return Err(IngressStateError::Contract(format!(
            "Apache enabled path가 symlink가 아닙니다: {}",
            path.display()
        )));
    }
    let target = fs::read_link(path).map_err(|error| io_error("apache_read_link", path, error))?;
    if target == Path::new(expected) {
        Ok(())
    } else {
        Err(IngressStateError::Contract(format!(
            "Apache symlink target이 승인값과 다릅니다: path={}, target={}",
            path.display(),
            target.display()
        )))
    }
}

fn staged_files() -> [&'static str; 5] {
    [
        "gnuboard5-guarded.conf",
        "gnuboard5-bypass.conf",
        "vpsguard-origin.conf",
        "vpsguard-origin-ports.conf",
        "vps-guard.ingress.toml",
    ]
}

fn proxy_module_links() -> [(&'static str, &'static str); 4] {
    [
        (PROXY_LOAD, PROXY_LOAD_TARGET),
        (PROXY_CONF, PROXY_CONF_TARGET),
        (PROXY_HTTP_LOAD, PROXY_HTTP_LOAD_TARGET),
        (REMOTEIP_LOAD, REMOTEIP_LOAD_TARGET),
    ]
}

fn issue(code: &str, cause: &str) -> OperationIssue {
    OperationIssue {
        code: code.to_owned(),
        problem: "Apache ingress 후보 전환을 완료하지 못했습니다.".to_owned(),
        cause: cause.to_owned(),
        impact: "이전 Apache vhost, symlink와 service 상태로 자동 복구합니다.".to_owned(),
        next_action: "operation state와 Apache configtest, public probe를 확인하십시오.".to_owned(),
    }
}
