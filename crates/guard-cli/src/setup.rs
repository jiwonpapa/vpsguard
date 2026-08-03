//! OPS-012 Nginx·Apache 공통 설치 점검 CLI를 제공합니다.

use std::env;
use std::path::PathBuf;

use clap::Args;
use guard_system::{
    ApacheIngressConfig, ApacheIngressDirection, ApacheIngressDriver, IngressSwitchConfig,
    IngressSwitchDirection, IngressSwitchDriver, OperationEngineError, SetupCompatibility,
    SiteSetupError, SiteSetupManifest, SiteSetupReport, WebServerKind, apache_ingress_plan,
    build_apache_site_candidates, build_nginx_site_candidates, execute_operation,
    ingress_switch_plan, inspect_site_setup, remove_apache_candidate_stage,
    remove_nginx_candidate_stage, write_apache_candidate_stage, write_nginx_candidate_stage,
};
use thiserror::Error;

/// `vps-guard setup` 인자입니다.
#[derive(Debug, Args)]
pub(crate) struct SetupArgs {
    /// 자동화용 전체 JSON report를 출력합니다.
    #[arg(long)]
    json: bool,
    /// 지원 가능한 exactly-one site를 snapshot·검증·자동 rollback transaction으로 편입합니다.
    #[arg(long)]
    apply: bool,
}

/// 설치 점검 CLI 실패입니다.
#[derive(Debug, Error)]
pub(crate) enum SetupCliError {
    /// typed host 탐지 실패입니다.
    #[error(transparent)]
    Inspect(#[from] SiteSetupError),
    /// report JSON 직렬화 실패입니다.
    #[error("site setup JSON 실패: {0}")]
    Json(#[from] serde_json::Error),
    /// Apache ingress 경계 실패입니다.
    #[error(transparent)]
    Ingress(#[from] guard_system::IngressStateError),
    /// typed operation과 자동 rollback 실패입니다.
    #[error(transparent)]
    Operation(#[from] OperationEngineError),
}

/// 기존 ingress를 변경하지 않고 설치 가능성과 계획을 출력합니다.
///
/// # Errors
///
/// host 탐지 또는 JSON 직렬화 실패를 반환합니다.
pub(crate) fn execute(args: SetupArgs) -> Result<String, SetupCliError> {
    let root = env::var_os("VPS_GUARD_TEST_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"));
    let report = inspect_site_setup(&root)?;
    if args.apply {
        return apply(&root, &report);
    }
    if args.json {
        serde_json::to_string_pretty(&report).map_err(SetupCliError::Json)
    } else {
        Ok(format_report(&report))
    }
}

fn apply(root: &std::path::Path, report: &SiteSetupReport) -> Result<String, SetupCliError> {
    let site = report.supported_site()?;
    match site.web_server {
        WebServerKind::Apache => apply_apache(root, site),
        WebServerKind::Nginx => apply_nginx(root, site),
    }
}

fn apply_apache(root: &std::path::Path, site: &SiteSetupManifest) -> Result<String, SetupCliError> {
    let candidates = build_apache_site_candidates(root, site)?;
    let stage_parent = stage_parent(root);
    let stage = write_apache_candidate_stage(&stage_parent, &candidates)?;
    let result = (|| {
        let mut config = ApacheIngressConfig::for_site(site, "")?;
        if root != std::path::Path::new("/") {
            let backup_root = env::var_os("VPS_GUARD_APACHE_BACKUP_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| root.join("var/lib/vps-guard/backups/apache-ingress"));
            let state_root = env::var_os("VPS_GUARD_FAKE_STATE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| root.join("run/vps-guard/setup-state"));
            let server_name = config.state.server_name.clone();
            let public_probe_url = config.state.public_probe_url.clone();
            config.state = guard_system::IngressStateConfig::fixture(
                root,
                state_root,
                backup_root.join("snapshots"),
            );
            config.state.server_name = server_name;
            config.state.public_probe_url = public_probe_url;
            config.backup_root = backup_root;
        }
        config.stage_root = Some(stage.clone());
        let operation_id = format!("setup-apache-{}", std::process::id());
        let plan = apache_ingress_plan(&operation_id, ApacheIngressDirection::ToEdge, &config);
        let transaction = config.backup_root.join("transactions").join(&operation_id);
        let lock = if root == std::path::Path::new("/") {
            PathBuf::from("/run/vps-guard/operation.lock")
        } else {
            config.backup_root.join("operation.lock")
        };
        let mut driver = ApacheIngressDriver::new(
            config,
            ApacheIngressDirection::ToEdge,
            transaction.join("rollback.json"),
        )?;
        let state = execute_operation(&plan, transaction.join("state.json"), lock, &mut driver)?;
        let rollback = driver
            .rollback_snapshot()
            .map_or_else(|| "none".to_owned(), |path| path.display().to_string());
        Ok(format!(
            "VPSGuard 설치 적용: 성공\n웹서버: Apache\n사이트: {}\ntransaction: {:?}\nrollback: {}\n다음 확인: 공개 HTTPS, 로그인, 업로드와 WebSocket",
            site.server_name, state.status, rollback
        ))
    })();
    let cleanup = remove_apache_candidate_stage(&stage);
    match (result, cleanup) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(SetupCliError::Inspect(error)),
    }
}

fn apply_nginx(root: &std::path::Path, site: &SiteSetupManifest) -> Result<String, SetupCliError> {
    let candidates = build_nginx_site_candidates(root, site)?;
    let stage = write_nginx_candidate_stage(&stage_parent(root), &candidates)?;
    let result = (|| {
        let mut config = IngressSwitchConfig::for_site(site, "")?;
        if root != std::path::Path::new("/") {
            let backup_root = env::var_os("VPS_GUARD_NGINX_BACKUP_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| root.join("var/lib/vps-guard/backups/nginx-ingress"));
            let state_root = env::var_os("VPS_GUARD_FAKE_STATE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| root.join("run/vps-guard/setup-state"));
            let server_name = config.state.server_name.clone();
            let public_probe_url = config.state.public_probe_url.clone();
            config.state = guard_system::IngressStateConfig::fixture(
                root,
                state_root,
                backup_root.join("snapshots"),
            );
            config.state.server_name = server_name;
            config.state.public_probe_url = public_probe_url;
            config.backup_root = backup_root;
        }
        config.stage_root = Some(stage.clone());
        let operation_id = format!("setup-nginx-{}", std::process::id());
        let plan = ingress_switch_plan(&operation_id, IngressSwitchDirection::ToEdge, &config);
        let transaction = config.backup_root.join("transactions").join(&operation_id);
        let lock = if root == std::path::Path::new("/") {
            PathBuf::from("/run/vps-guard/operation.lock")
        } else {
            config.backup_root.join("operation.lock")
        };
        let mut driver = IngressSwitchDriver::new(
            config,
            IngressSwitchDirection::ToEdge,
            transaction.join("rollback.json"),
        )?;
        let state = execute_operation(&plan, transaction.join("state.json"), lock, &mut driver)?;
        let rollback = driver
            .rollback_snapshot()
            .map_or_else(|| "none".to_owned(), |path| path.display().to_string());
        Ok(format!(
            "VPSGuard 설치 적용: 성공\n웹서버: Nginx\n사이트: {}\ntransaction: {:?}\nrollback: {}\n다음 확인: 공개 HTTPS, 로그인, 업로드와 WebSocket",
            site.server_name, state.status, rollback
        ))
    })();
    let cleanup = remove_nginx_candidate_stage(&stage);
    match (result, cleanup) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(SetupCliError::Inspect(error)),
    }
}

fn stage_parent(root: &std::path::Path) -> PathBuf {
    env::var_os("VPS_GUARD_SETUP_STAGE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            if root == std::path::Path::new("/") {
                PathBuf::from("/run/vps-guard")
            } else {
                root.join("run/vps-guard")
            }
        })
}

fn format_report(report: &SiteSetupReport) -> String {
    let status = match report.compatibility {
        SetupCompatibility::Supported => "자동 준비 가능",
        SetupCompatibility::ManualReview => "수동 검토 필요",
        SetupCompatibility::Rejected => "자동 준비 거부",
    };
    let mut lines = vec![
        format!(
            "VPSGuard 설치 점검: {status} ({} {})",
            report.operating_system, report.operating_system_version
        ),
        format!("변경 수행: {}건", report.mutations_performed),
    ];
    if let Some(site) = &report.site {
        lines.extend([
            format!(
                "웹서버: {}",
                match site.web_server {
                    WebServerKind::Nginx => "Nginx",
                    WebServerKind::Apache => "Apache",
                }
            ),
            format!("사이트: {}", site.server_name),
            format!("설정: {}", site.active_config.display()),
            format!("원본: {}", site.document_root.display()),
            "적용 순서: snapshot -> loopback origin -> 후보 검사 -> 전환 -> 공개 read-back"
                .to_owned(),
            "현재 명령은 점검만 수행했습니다. public ingress와 인증서는 변경하지 않았습니다."
                .to_owned(),
        ]);
    }
    for issue in &report.issues {
        lines.extend([
            format!("문제: {}", issue.problem),
            format!("원인: {}", issue.cause),
            format!("영향: {}", issue.impact),
            format!("다음 조치: {}", issue.next_action),
        ]);
    }
    lines.join("\n")
}
