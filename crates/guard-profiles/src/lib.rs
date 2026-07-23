//! PHP, GnuBoard 5·7과 WordPress의 경로 정규화·자원 비용 profile을 소유합니다.

use serde::{Deserialize, Serialize};

/// 지원하는 애플리케이션 profile입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ApplicationProfile {
    /// 범용 PHP entrypoint profile입니다.
    Php,
    /// GnuBoard 5 legacy PHP route profile입니다.
    #[serde(rename = "gnuboard5", alias = "gnuboard")]
    Gnuboard5,
    /// GnuBoard 7 Laravel API·SPA route profile입니다.
    Gnuboard7,
    /// WordPress 계열입니다.
    Wordpress,
}

/// route의 기능·비용 분류입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteKind {
    /// 정적 asset입니다.
    Static,
    /// 일반 공개 페이지입니다.
    Public,
    /// 게시판 목록·상세입니다.
    Board,
    /// 검색입니다.
    Search,
    /// 로그인·가입·비밀번호입니다.
    Authentication,
    /// 글·댓글 작성입니다.
    Write,
    /// 업로드·다운로드·이미지 처리입니다.
    Media,
    /// request body를 받는 업로드 경로입니다.
    Upload,
    /// app별 의미를 알 수 없는 PHP entrypoint입니다.
    Dynamic,
    /// 관리자 기능입니다.
    Admin,
    /// API 또는 feed입니다.
    Api,
    /// XML-RPC처럼 인증·증폭 공격에 자주 쓰이는 원격 호출 entrypoint입니다.
    RemoteProcedure,
}

/// 정규화 route와 초기 비용입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteProfile {
    /// query를 제거하고 cardinality를 제한한 route key입니다.
    pub normalized_route: String,
    /// 기능 분류입니다.
    pub kind: RouteKind,
    /// 설명 가능한 초기 비용 1..=15입니다.
    pub base_cost: u8,
}

/// app별 기본 response 보안 overlay입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplicationSecurityProfile {
    /// report-only로 시작하는 기본 Content Security Policy입니다.
    pub csp_policy: &'static str,
}

const LEGACY_CSP: &str = "default-src 'self' https: data: blob:; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; form-action 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; connect-src 'self' https: ws: wss:";
const GNUBOARD7_CSP: &str = "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' ws: wss:; media-src 'self' blob:";

/// 범용 core에 합성할 app별 기본 보안 overlay를 반환합니다.
#[must_use]
pub const fn security_profile(profile: ApplicationProfile) -> ApplicationSecurityProfile {
    ApplicationSecurityProfile {
        csp_policy: match profile {
            ApplicationProfile::Gnuboard7 => GNUBOARD7_CSP,
            ApplicationProfile::Php
            | ApplicationProfile::Gnuboard5
            | ApplicationProfile::Wordpress => LEGACY_CSP,
        },
    }
}

/// 지정 profile로 경로를 정규화하고 비용을 분류합니다.
#[must_use]
pub fn classify(profile: ApplicationProfile, raw_target: &str) -> RouteProfile {
    let path = raw_target.split('?').next().unwrap_or("/");
    let normalized = normalize_route(path);
    let kind = match profile {
        ApplicationProfile::Php => classify_php(path),
        ApplicationProfile::Gnuboard5 => classify_gnuboard5(path),
        ApplicationProfile::Gnuboard7 => classify_gnuboard7(path),
        ApplicationProfile::Wordpress => classify_wordpress(path),
    };
    RouteProfile {
        normalized_route: normalized,
        kind,
        base_cost: base_cost(kind),
    }
}

/// query·고유 식별자·고entropy segment를 제거한 bounded route key를 만듭니다.
///
/// profile을 사용하지 않는 범용 HTTP mode도 이 함수를 사용해 SQLite와 메모리
/// cardinality가 공격자가 만든 path에 비례해 증가하지 않도록 해야 합니다.
#[must_use]
pub fn normalize_route(raw_target: &str) -> String {
    const MAX_SEGMENTS: usize = 16;
    const MAX_ROUTE_BYTES: usize = 256;
    let path = raw_target.split('?').next().unwrap_or("/");
    let mut normalized = String::new();
    let mut truncated = false;
    for (index, segment) in path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .enumerate()
    {
        if index == MAX_SEGMENTS {
            truncated = true;
            break;
        }
        let bounded = normalize_segment(segment);
        if normalized
            .len()
            .saturating_add(1)
            .saturating_add(bounded.len())
            > MAX_ROUTE_BYTES.saturating_sub("/:other".len())
        {
            truncated = true;
            break;
        }
        normalized.push('/');
        normalized.push_str(bounded);
    }
    if truncated {
        normalized.push_str("/:other");
    }
    if normalized.is_empty() {
        "/".to_owned()
    } else {
        normalized
    }
}

fn classify_php(path: &str) -> RouteKind {
    if is_static(path) {
        RouteKind::Static
    } else if contains_any(path, &["/admin", "admin.php"]) {
        RouteKind::Admin
    } else if contains_any(path, &["login", "register", "password", "auth"]) {
        RouteKind::Authentication
    } else if path.contains("search") {
        RouteKind::Search
    } else if contains_any(path, &["write", "comment", "create", "update"]) {
        RouteKind::Write
    } else if contains_any(path, &["upload", "attachment", "avatar"]) {
        RouteKind::Upload
    } else if contains_any(path, &["download", "/file", "/media"]) {
        RouteKind::Media
    } else if path.ends_with("/xmlrpc.php") || path == "/xmlrpc.php" {
        RouteKind::RemoteProcedure
    } else if path.starts_with("/api/") {
        RouteKind::Api
    } else if path.to_ascii_lowercase().ends_with(".php") {
        RouteKind::Dynamic
    } else {
        RouteKind::Public
    }
}

fn classify_gnuboard5(path: &str) -> RouteKind {
    if is_static(path) {
        RouteKind::Static
    } else if path == "/adm" || path.starts_with("/adm/") {
        RouteKind::Admin
    } else if path.starts_with("/api/") {
        RouteKind::Api
    } else if path.contains("search.php") {
        RouteKind::Search
    } else if contains_any(
        path,
        &["login.php", "register", "password", "member_confirm"],
    ) {
        RouteKind::Authentication
    } else if contains_any(path, &["write", "comment", "delete", "move_update"]) {
        RouteKind::Write
    } else if contains_any(path, &["upload", "ajax.file", "file_form"]) {
        RouteKind::Upload
    } else if contains_any(path, &["download.php", "/data/file/"]) {
        RouteKind::Media
    } else if path.starts_with("/bbs/") {
        RouteKind::Board
    } else if path.to_ascii_lowercase().ends_with(".php") {
        RouteKind::Dynamic
    } else {
        RouteKind::Public
    }
}

fn classify_gnuboard7(path: &str) -> RouteKind {
    if is_static(path) {
        RouteKind::Static
    } else if path == "/admin"
        || path.starts_with("/admin/")
        || path == "/api/admin"
        || path.starts_with("/api/admin/")
        || path == "/api/auth/admin"
        || path.starts_with("/api/auth/admin/")
    {
        RouteKind::Admin
    } else if path == "/login"
        || path == "/register"
        || path.starts_with("/forgot-password")
        || path.starts_with("/reset-password")
        || path.starts_with("/api/auth/")
        || path.starts_with("/api/user/auth/")
        || path.starts_with("/api/me/verify-password")
        || path.starts_with("/api/me/password")
        || path.starts_with("/api/identity/")
        || path == "/api/broadcasting/auth"
    {
        RouteKind::Authentication
    } else if path == "/search" || path.starts_with("/api/search") {
        RouteKind::Search
    } else if contains_any(path, &["/avatar", "/upload", "/attachments"]) {
        RouteKind::Upload
    } else if contains_any(path, &["/posts", "/comments", "/write"]) {
        RouteKind::Write
    } else if path.starts_with("/api/attachment/") {
        RouteKind::Media
    } else if path.starts_with("/api/") {
        RouteKind::Api
    } else if path.to_ascii_lowercase().ends_with(".php") {
        RouteKind::Dynamic
    } else {
        RouteKind::Public
    }
}

fn classify_wordpress(path: &str) -> RouteKind {
    if is_static(path) || path.starts_with("/wp-content/") || path.starts_with("/wp-includes/") {
        RouteKind::Static
    } else if path == "/wp-admin" || path.starts_with("/wp-admin/") {
        RouteKind::Admin
    } else if path == "/wp-login.php" || path.contains("lostpassword") {
        RouteKind::Authentication
    } else if path == "/xmlrpc.php" {
        RouteKind::RemoteProcedure
    } else if path.starts_with("/wp-json/") || path.ends_with("/feed/") {
        RouteKind::Api
    } else if path.contains("/search/") {
        RouteKind::Search
    } else if path.contains("upload") {
        RouteKind::Upload
    } else {
        RouteKind::Public
    }
}

fn base_cost(kind: RouteKind) -> u8 {
    match kind {
        RouteKind::Static => 1,
        RouteKind::Public => 2,
        RouteKind::Board => 4,
        RouteKind::Search => 10,
        RouteKind::Authentication => 12,
        RouteKind::Write => 12,
        RouteKind::Media => 15,
        RouteKind::Upload => 15,
        RouteKind::Dynamic => 6,
        RouteKind::Admin => 12,
        RouteKind::Api => 8,
        RouteKind::RemoteProcedure => 15,
    }
}

fn contains_any(path: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| path.contains(needle))
}

fn is_static(path: &str) -> bool {
    let extension = path.rsplit_once('.').map(|(_, extension)| extension);
    extension.is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "css"
                | "js"
                | "jpg"
                | "jpeg"
                | "png"
                | "gif"
                | "webp"
                | "svg"
                | "ico"
                | "woff"
                | "woff2"
        )
    })
}

fn normalize_segment(segment: &str) -> &str {
    if segment.bytes().all(|byte| byte.is_ascii_digit()) || is_uuid(segment) {
        ":id"
    } else if segment.contains('@') || opaque_token(segment) {
        ":opaque"
    } else {
        segment
    }
}

fn opaque_token(segment: &str) -> bool {
    const MAX_VISIBLE_SEGMENT_BYTES: usize = 64;
    if segment.len() > MAX_VISIBLE_SEGMENT_BYTES {
        return true;
    }
    let all_hex = segment.len() >= 16 && segment.bytes().all(|byte| byte.is_ascii_hexdigit());
    let token_like = segment.len() >= 32
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'=' | b'%'));
    all_hex || token_like
}

fn is_uuid(segment: &str) -> bool {
    segment.len() == 36
        && segment.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
