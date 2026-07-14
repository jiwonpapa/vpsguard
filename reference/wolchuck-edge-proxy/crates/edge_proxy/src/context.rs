use std::net::IpAddr;
use std::time::Instant;

#[derive(Debug)]
pub(crate) struct RequestCtx {
    pub(crate) request_id: String,
    pub(crate) started_at: Instant,
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) target: String,
    pub(crate) host: Option<String>,
    pub(crate) direct_client_ip: Option<IpAddr>,
    pub(crate) effective_client_ip: Option<IpAddr>,
    pub(crate) forwarded_headers_trusted: bool,
    pub(crate) request_body_bytes_seen: u64,
}

impl RequestCtx {
    pub(crate) fn new() -> Self {
        Self {
            request_id: String::new(),
            started_at: Instant::now(),
            method: String::new(),
            path: String::new(),
            target: String::new(),
            host: None,
            direct_client_ip: None,
            effective_client_ip: None,
            forwarded_headers_trusted: false,
            request_body_bytes_seen: 0,
        }
    }
}
