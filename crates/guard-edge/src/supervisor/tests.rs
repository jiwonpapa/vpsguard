//! Edge supervisor worker 실행 인자와 reload 중복 방지 회귀 테스트입니다.

use std::ffi::OsString;

use super::WorkerLaunch;

#[test]
fn worker_launch_arguments_keep_supervisor_out_of_children() {
    assert_eq!(
        WorkerLaunch::Initial.arguments(),
        vec![OsString::from("--worker")]
    );
    assert_eq!(
        WorkerLaunch::Preflight { tls_reload: false }.arguments(),
        vec![OsString::from("--worker"), OsString::from("--test")]
    );
    assert_eq!(
        WorkerLaunch::Preflight { tls_reload: true }.arguments(),
        vec![
            OsString::from("--worker"),
            OsString::from("--test"),
            OsString::from("--tls-reload")
        ]
    );
    assert_eq!(
        WorkerLaunch::Upgrade.arguments(),
        vec![
            OsString::from("--worker"),
            OsString::from("--upgrade"),
            OsString::from("--tls-reload")
        ]
    );
}
