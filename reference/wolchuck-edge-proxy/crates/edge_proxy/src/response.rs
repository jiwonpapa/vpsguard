use bytes::Bytes;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;

pub(crate) fn add_common_response_headers(
    response: &mut ResponseHeader,
    request_id_header: &str,
    request_id: &str,
) -> pingora_core::Result<()> {
    response.insert_header("x-edge-proxy", "pingora-poc")?;
    response.insert_header(request_id_header.to_string(), request_id)?;
    Ok(())
}

pub(crate) async fn respond_plain_text(
    session: &mut Session,
    status: u16,
    body: &'static [u8],
    request_id_header: &str,
    request_id: &str,
) -> pingora_core::Result<()> {
    let mut response = ResponseHeader::build(status, Some(4))?;
    response.insert_header("content-type", "text/plain; charset=utf-8")?;
    response.insert_header("content-length", body.len().to_string())?;
    add_common_response_headers(&mut response, request_id_header, request_id)?;

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
    request_id_header: &str,
    request_id: &str,
) -> pingora_core::Result<()> {
    let mut response = ResponseHeader::build(308, Some(4))?;
    response.insert_header("location", location)?;
    response.insert_header("content-length", "0")?;
    add_common_response_headers(&mut response, request_id_header, request_id)?;
    session
        .write_response_header(Box::new(response), true)
        .await
}
