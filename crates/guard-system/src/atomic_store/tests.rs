//! 원자 JSON 저장소 회귀 테스트입니다.

use serde::{Deserialize, Serialize};

use super::AtomicJsonStore;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Fixture {
    version: u64,
}

#[test]
fn replaces_complete_json() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = AtomicJsonStore::<Fixture>::new(directory.path().join("state.json"));
    store.write(&Fixture { version: 1 })?;
    store.write(&Fixture { version: 2 })?;
    assert_eq!(store.read()?, Fixture { version: 2 });
    Ok(())
}

#[test]
fn corrupt_json_is_not_treated_as_state() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.json");
    std::fs::write(&path, b"{broken")?;
    let store = AtomicJsonStore::<Fixture>::new(path);
    assert!(store.read().is_err());
    Ok(())
}
