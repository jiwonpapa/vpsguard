//! PHP-FPM status transport와 장애 분리 계약을 검증합니다.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use guard_agent::CollectorState;
use guard_agent::services::{
    ServiceProbe, ServiceSemanticSnapshot, ServiceTarget, ServiceTargets, collect_services,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn combines_php_semantics_with_its_allowlisted_cgroup()
-> Result<(), Box<dyn std::error::Error>> {
    let body = "accepted conn: 100\nlisten queue: 2\nmax listen queue: 4\nlisten queue len: 128\nidle processes: 3\nactive processes: 2\ntotal processes: 5\nmax active processes: 4\nmax children reached: 1\nslow requests: 2\n";
    let (status_url, server) = spawn_http_response("200 OK", body).await?;
    let root = tempfile::tempdir()?;
    write_cgroup_fixture(root.path(), "system.slice/php8.3-fpm.service")?;
    let targets = ServiceTargets::new(
        root.path().to_path_buf(),
        vec![ServiceTarget {
            name: "php_fpm".to_owned(),
            unit: Some("php8.3-fpm.service".to_owned()),
            cgroup_path: Some(PathBuf::from("system.slice/php8.3-fpm.service")),
            probe: ServiceProbe::PhpFpm { status_url },
        }],
        Duration::from_secs(1),
    )?;

    let health = collect_services(&targets).await;
    server.await??;

    assert_eq!(health.len(), 1);
    assert_eq!(health[0].state, CollectorState::Live);
    assert_eq!(
        health[0]
            .resources
            .as_ref()
            .map(|resource| resource.memory_current_bytes),
        Some(4_096)
    );
    assert!(matches!(
        health[0].semantic,
        Some(ServiceSemanticSnapshot::PhpFpm {
            listen_queue: 2,
            max_children_reached: 1,
            ..
        })
    ));
    Ok(())
}

#[tokio::test]
async fn reports_status_endpoint_failure_separately() -> Result<(), Box<dyn std::error::Error>> {
    let (status_url, server) = spawn_http_response("503 Service Unavailable", "down\n").await?;
    let root = tempfile::tempdir()?;
    let targets = ServiceTargets::new(
        root.path().to_path_buf(),
        vec![ServiceTarget {
            name: "php_fpm".to_owned(),
            unit: None,
            cgroup_path: None,
            probe: ServiceProbe::PhpFpm { status_url },
        }],
        Duration::from_secs(1),
    )?;

    let health = collect_services(&targets).await;
    server.await??;

    assert_eq!(health[0].state, CollectorState::Error);
    assert_eq!(health[0].resource_state, None);
    assert_eq!(health[0].semantic_state, Some(CollectorState::Error));
    assert_eq!(
        health[0].semantic_error_code.as_deref(),
        Some("UNHEALTHY_RESPONSE")
    );
    Ok(())
}

async fn spawn_http_response(
    status: &'static str,
    body: &'static str,
) -> Result<(String, tokio::task::JoinHandle<std::io::Result<()>>), std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await?;
        let mut request = [0_u8; 1_024];
        let _bytes_read = stream.read(&mut request).await?;
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await?;
        Ok(())
    });
    Ok((format!("http://{address}/fpm-status"), server))
}

fn write_cgroup_fixture(root: &std::path::Path, relative: &str) -> std::io::Result<()> {
    let unit = root.join(relative);
    fs::create_dir_all(&unit)?;
    fs::write(
        unit.join("cpu.stat"),
        "usage_usec 1000\nuser_usec 700\nsystem_usec 300\nnr_periods 9\nnr_throttled 2\nthrottled_usec 50\n",
    )?;
    fs::write(unit.join("memory.current"), "4096\n")?;
    fs::write(
        unit.join("memory.events"),
        "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
    )?;
    fs::write(
        unit.join("io.stat"),
        "8:0 rbytes=100 wbytes=200 rios=1 wios=2\n",
    )?;
    fs::write(unit.join("cgroup.procs"), "100\n101\n")?;
    fs::write(unit.join("pids.current"), "5\n")?;
    Ok(())
}
