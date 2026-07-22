//! 검증된 direct TLS staging directory를 immutable ingress snapshot으로 변환합니다.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use super::files::{
    copy_snapshot_file, create_private_dir, create_private_dir_all, sync_dir, timestamp,
    write_checksums, write_private,
};
use super::format::{FileRecord, IngressManifest, Presence};
use super::{
    ACTIVE_CONFIG, FILE_SPECS, INGRESS_SNAPSHOT_SCHEMA_VERSION, IngressStateError,
    IngressStateStore, io_error,
};

static CANDIDATE_SEQUENCE: AtomicU32 = AtomicU32::new(0);
const STAGED_FILES: [&str; 5] = [
    "origin-only.conf",
    "direct.toml",
    "edge-tls.conf",
    "certbot-deploy-hook",
    "g7-certbot-deploy-hook",
];
const TARGET_MODES: [u32; 5] = [0o644, 0o640, 0o644, 0o755, 0o755];

impl IngressStateStore {
    /// direct TLS staging 파일을 검증하고 적용 가능한 target snapshot으로 확정합니다.
    ///
    /// # Errors
    ///
    /// stage path, required file, metadata 또는 snapshot commit 실패를 반환합니다.
    pub fn create_direct_candidate_snapshot(
        &mut self,
        stage: &Path,
    ) -> Result<PathBuf, IngressStateError> {
        self.validate_runtime_boundary()?;
        validate_stage(stage)?;
        create_private_dir_all(&self.config.snapshot_root)?;
        let sequence = CANDIDATE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let suffix = format!("{}{:06}", std::process::id(), sequence % 1_000_000);
        let stamp = timestamp();
        let final_path = self
            .config
            .snapshot_root
            .join(format!("direct-{stamp}-{suffix}-direct"));
        let pending = self
            .config
            .snapshot_root
            .join(format!(".candidate-{stamp}-{suffix}"));
        if final_path.exists() || pending.exists() {
            return Err(IngressStateError::Contract(
                "candidate snapshot path가 이미 존재합니다".to_owned(),
            ));
        }
        create_private_dir(&pending)?;
        if let Err(error) = self.populate_candidate(stage, &pending) {
            let _ignored = fs::remove_dir_all(&pending);
            return Err(error);
        }
        sync_dir(&pending)?;
        fs::rename(&pending, &final_path)
            .map_err(|source| io_error("commit_candidate_snapshot", &final_path, source))?;
        sync_dir(&self.config.snapshot_root)?;
        Ok(final_path)
    }

    fn populate_candidate(
        &mut self,
        stage: &Path,
        snapshot: &Path,
    ) -> Result<(), IngressStateError> {
        let mut files = Vec::new();
        for (index, spec) in FILE_SPECS.iter().enumerate() {
            let source = stage.join(STAGED_FILES[index]);
            let metadata = fs::symlink_metadata(&source)
                .map_err(|error| io_error("candidate_metadata", &source, error))?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(IngressStateError::Contract(format!(
                    "staged candidate가 regular file이 아닙니다: {}",
                    source.display()
                )));
            }
            copy_snapshot_file(&source, &snapshot.join(spec.payload), &metadata)?;
            let current = fs::metadata(self.logical_path(spec.logical)?).ok();
            let (uid, gid) = if self.config.test_root.is_some() {
                (None, None)
            } else {
                let gid = if spec.logical == ACTIVE_CONFIG {
                    current.as_ref().map_or(0, MetadataExt::gid)
                } else {
                    0
                };
                (Some(0), Some(gid))
            };
            files.push(FileRecord {
                logical: spec.logical.to_owned(),
                payload: spec.payload.to_owned(),
                presence: Presence::Present,
                mode: TARGET_MODES[index],
                uid,
                gid,
            });
        }
        let mut edge = self.service_state(super::EDGE_SERVICE)?;
        edge.active = "active".to_owned();
        let mut nginx = self.service_state(super::NGINX_SERVICE)?;
        nginx.active = "active".to_owned();
        let manifest = IngressManifest {
            schema_version: INGRESS_SNAPSHOT_SCHEMA_VERSION,
            machine_id_sha256: self.machine_id_hash()?,
            label: "direct".to_owned(),
            files,
            default_deny: Presence::Absent,
            default_deny_target: String::new(),
            services: vec![edge, nginx],
            edge_public: true,
            public_edge_header: true,
            certificate_fingerprint: self.certificate_fingerprint()?,
            protected_listeners: Some(self.protected_listeners()?),
        };
        write_private(
            &snapshot.join("manifest.json"),
            &serde_json::to_vec_pretty(&manifest)?,
        )?;
        write_checksums(snapshot)
    }
}

fn validate_stage(stage: &Path) -> Result<(), IngressStateError> {
    let text = stage.to_string_lossy();
    let suffix = text.strip_prefix("/tmp/vpsguard-direct.").ok_or_else(|| {
        IngressStateError::Contract("direct stage path가 allowlist 밖입니다".to_owned())
    })?;
    if suffix.is_empty()
        || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
        || stage.parent() != Some(Path::new("/tmp"))
    {
        return Err(IngressStateError::Contract(
            "direct stage path 형식이 잘못됐습니다".to_owned(),
        ));
    }
    let metadata =
        fs::symlink_metadata(stage).map_err(|source| io_error("stage_metadata", stage, source))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(IngressStateError::Contract(
            "direct stage가 실제 directory가 아닙니다".to_owned(),
        ));
    }
    Ok(())
}
