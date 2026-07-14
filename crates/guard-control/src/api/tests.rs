//! control API authorization과 idempotency 회귀 테스트입니다.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use guard_core::{GuardMode, GuardState};
use guard_system::AtomicJsonStore;
use tokio::sync::{RwLock, broadcast};
use tower::ServiceExt;

use super::{AppState, router};
use crate::auth::SessionStore;
use crate::storage::SqliteStore;
use crate::telemetry::TrafficAggregator;

fn app(path: &std::path::Path) -> Result<Arc<AppState>, Box<dyn std::error::Error>> {
    let (events, _) = broadcast::channel(32);
    Ok(Arc::new(AppState {
        state: RwLock::new(GuardState::normal("2026-07-14T00:00:00Z")),
        state_store: AtomicJsonStore::new(path),
        traffic: Mutex::new(TrafficAggregator::new(10)),
        os_snapshot: RwLock::new(None),
        service_health: RwLock::new(Vec::new()),
        action_token: "test-token".to_owned(),
        completed_actions: Mutex::new(VecDeque::new()),
        storage: Arc::new(SqliteStore::in_memory()?),
        events,
        sessions: SessionStore::new(),
    }))
}

#[tokio::test]
async fn mutation_requires_action_token() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let response = router(app(&directory.path().join("state.json"))?)
        .oneshot(
            Request::post("/api/v1/actions/manual-hold")
                .header("idempotency-key", "operation-1")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn duplicate_action_is_not_applied_twice() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app(&directory.path().join("state.json"))?;
    let request = || {
        Request::post("/api/v1/actions/manual-hold")
            .header("idempotency-key", "operation-1")
            .header("x-vpsguard-token", "test-token")
            .body(Body::empty())
    };
    let first = router(Arc::clone(&state)).oneshot(request()?).await?;
    let second = router(Arc::clone(&state)).oneshot(request()?).await?;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(state.state.read().await.current_mode, GuardMode::ManualHold);
    assert_eq!(
        state
            .completed_actions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len(),
        1
    );
    Ok(())
}
