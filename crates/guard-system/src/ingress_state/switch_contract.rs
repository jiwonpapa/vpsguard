//! Ingress switch path, state와 구조화 오류 계약입니다.

use std::fs;
use std::path::{Component, Path};

use super::switch::{IngressSwitchConfig, IngressSwitchDirection};
use super::{IngressStateError, io_error};
use crate::OperationIssue;

pub(super) fn validate_switch_config(
    config: &IngressSwitchConfig,
) -> Result<(), IngressStateError> {
    for path in [
        &config.active_config,
        &config.edge_candidate,
        &config.nginx_candidate,
        &config.active_guard_config,
        &config.backup_root,
    ] {
        if !path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        {
            return Err(IngressStateError::Contract(format!(
                "ingress switch path가 절대 정규 경로가 아닙니다: {}",
                path.display()
            )));
        }
    }
    if !config.active_config.starts_with("/etc/nginx/")
        || !config.edge_candidate.starts_with("/etc/vps-guard/nginx/")
        || !config.nginx_candidate.starts_with("/etc/vps-guard/nginx/")
        || config.active_guard_config != Path::new("/etc/vps-guard/config.toml")
    {
        return Err(IngressStateError::Contract(
            "ingress switch path가 allowlist 밖입니다".to_owned(),
        ));
    }
    if !config.state.public_probe_url.starts_with("https://") {
        return Err(IngressStateError::Contract(
            "public probe URL은 HTTPS여야 합니다".to_owned(),
        ));
    }
    if let Some(stage) = &config.stage_root {
        validate_stage(stage)?;
        for file in [
            "g7devops-edge.conf",
            "g7devops-bypass.conf",
            "vps-guard.ingress.toml",
        ] {
            require_regular(&stage.join(file))?;
        }
    }
    Ok(())
}

fn validate_stage(stage: &Path) -> Result<(), IngressStateError> {
    let text = stage.to_string_lossy();
    let suffix = text.strip_prefix("/tmp/vpsguard-cutover.").ok_or_else(|| {
        IngressStateError::Contract("cutover stage path가 allowlist 밖입니다".to_owned())
    })?;
    if suffix.is_empty()
        || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
        || stage.parent() != Some(Path::new("/tmp"))
    {
        return Err(IngressStateError::Contract(
            "cutover stage path 형식이 잘못됐습니다".to_owned(),
        ));
    }
    let metadata = fs::symlink_metadata(stage)
        .map_err(|source| io_error("switch_stage_metadata", stage, source))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(IngressStateError::Contract(
            "cutover stage가 실제 directory가 아닙니다".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn require_regular(path: &Path) -> Result<(), IngressStateError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("candidate_metadata", path, source))?;
    if metadata.is_file() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(IngressStateError::Contract(format!(
            "candidate가 regular file이 아닙니다: {}",
            path.display()
        )))
    }
}

pub(super) fn validate_service_field(value: &str) -> Result<(), IngressStateError> {
    if value.is_empty() || value.len() > 64 || value.contains(['\n', '\r', '\0']) {
        Err(IngressStateError::Contract(
            "service state field가 잘못됐습니다".to_owned(),
        ))
    } else {
        Ok(())
    }
}

pub(super) fn direction_name(direction: IngressSwitchDirection) -> &'static str {
    match direction {
        IngressSwitchDirection::ToEdge => "to-edge",
        IngressSwitchDirection::ToNginx => "to-nginx",
    }
}

pub(super) fn issue(code: &str, cause: &str) -> OperationIssue {
    OperationIssue {
        code: code.to_owned(),
        problem: "public ingress 후보 전환을 완료하지 못했습니다.".to_owned(),
        cause: cause.to_owned(),
        impact: "이전 active ingress와 edge service 상태로 자동 복구합니다.".to_owned(),
        next_action: "operation state와 Nginx 검사·public probe 결과를 확인하십시오.".to_owned(),
    }
}
