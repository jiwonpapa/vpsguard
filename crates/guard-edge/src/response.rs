//! Edge가 upstream 없이 직접 반환하는 작은 HTTP 응답을 생성합니다.

use bytes::Bytes;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;

const EDGE_HEADER: &str = "x-vps-guard";
const REQUEST_ID_HEADER: &str = "x-request-id";

pub(crate) fn add_common_headers(
    response: &mut ResponseHeader,
    request_id: &str,
) -> pingora_core::Result<()> {
    response.insert_header(EDGE_HEADER, "guard-edge")?;
    response.insert_header(REQUEST_ID_HEADER, request_id)?;
    Ok(())
}

pub(crate) async fn respond_text(
    session: &mut Session,
    status: u16,
    body: &'static [u8],
    request_id: &str,
    retry_after_seconds: Option<u64>,
) -> pingora_core::Result<()> {
    let mut response = ResponseHeader::build(status, Some(5))?;
    response.insert_header("content-type", "text/plain; charset=utf-8")?;
    response.insert_header("content-length", body.len().to_string())?;
    if let Some(seconds) = retry_after_seconds {
        response.insert_header("retry-after", seconds.to_string())?;
    }
    add_common_headers(&mut response, request_id)?;
    session
        .write_response_header(Box::new(response), false)
        .await?;
    session
        .write_response_body(Some(Bytes::from_static(body)), true)
        .await
}

pub(crate) async fn respond_text_with_headers(
    session: &mut Session,
    status: u16,
    body: &'static [u8],
    request_id: &str,
    headers: &[(&'static str, String)],
) -> pingora_core::Result<()> {
    let mut response = ResponseHeader::build(status, Some(5 + headers.len()))?;
    response.insert_header("content-type", "text/plain; charset=utf-8")?;
    response.insert_header("content-length", body.len().to_string())?;
    for (name, value) in headers {
        response.insert_header(*name, value)?;
    }
    add_common_headers(&mut response, request_id)?;
    session
        .write_response_header(Box::new(response), false)
        .await?;
    session
        .write_response_body(Some(Bytes::from_static(body)), true)
        .await
}

pub(crate) async fn respond_redirect(
    session: &mut Session,
    location: &str,
    request_id: &str,
) -> pingora_core::Result<()> {
    let mut response = ResponseHeader::build(308, Some(4))?;
    response.insert_header("location", location)?;
    response.insert_header("content-length", "0")?;
    add_common_headers(&mut response, request_id)?;
    session
        .write_response_header(Box::new(response), true)
        .await
}
