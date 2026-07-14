//! GnuBoard와 WordPress의 경로 정규화와 자원 비용 profile을 소유합니다.

use serde::{Deserialize, Serialize};

/// 지원하는 애플리케이션 profile입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ApplicationProfile {
    /// GnuBoard 5/7 계열입니다.
    Gnuboard,
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
    /// 관리자 기능입니다.
    Admin,
    /// API 또는 feed입니다.
    Api,
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

/// 지정 profile로 경로를 정규화하고 비용을 분류합니다.
#[must_use]
pub fn classify(profile: ApplicationProfile, raw_target: &str) -> RouteProfile {
    let path = raw_target.split('?').next().unwrap_or("/");
    let normalized = normalize_segments(path);
    let kind = match profile {
        ApplicationProfile::Gnuboard => classify_gnuboard(path),
        ApplicationProfile::Wordpress => classify_wordpress(path),
    };
    RouteProfile {
        normalized_route: normalized,
        kind,
        base_cost: base_cost(kind),
    }
}

fn classify_gnuboard(path: &str) -> RouteKind {
    if is_static(path) {
        RouteKind::Static
    } else if path.starts_with("/adm/") {
        RouteKind::Admin
    } else if path.contains("search.php") {
        RouteKind::Search
    } else if path.contains("login.php") || path.contains("register") || path.contains("password") {
        RouteKind::Authentication
    } else if path.contains("write") || path.contains("comment") {
        RouteKind::Write
    } else if path.contains("download.php") || path.contains("file") || path.contains("upload") {
        RouteKind::Media
    } else if path.starts_with("/api/") {
        RouteKind::Api
    } else if path.starts_with("/bbs/") {
        RouteKind::Board
    } else {
        RouteKind::Public
    }
}

fn classify_wordpress(path: &str) -> RouteKind {
    if is_static(path) || path.starts_with("/wp-content/") || path.starts_with("/wp-includes/") {
        RouteKind::Static
    } else if path.starts_with("/wp-admin/") {
        RouteKind::Admin
    } else if path == "/wp-login.php" || path.contains("lostpassword") {
        RouteKind::Authentication
    } else if path == "/xmlrpc.php" || path.starts_with("/wp-json/") || path.ends_with("/feed/") {
        RouteKind::Api
    } else if path.contains("/search/") {
        RouteKind::Search
    } else if path.contains("upload") {
        RouteKind::Media
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
        RouteKind::Admin => 12,
        RouteKind::Api => 8,
    }
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

fn normalize_segments(path: &str) -> String {
    let normalized = path
        .split('/')
        .map(|segment| {
            if !segment.is_empty()
                && (segment.bytes().all(|byte| byte.is_ascii_digit()) || is_uuid(segment))
            {
                ":id"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    if normalized.is_empty() {
        "/".to_owned()
    } else {
        normalized
    }
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
