# Wolchuck Edge Proxy Reference Source

이 디렉터리는 VPSGuard `guard-edge` 구현을 위한 월척 Pingora edge proxy 기준본입니다.
현재 VPSGuard workspace에 연결된 실행 코드가 아니며, 원본 경로와 내용을 보존한 참조 사본입니다.

## 출처

- 원본 저장소: `https://github.com/jiwonpapa/rust-middleware.git`
- 기준 커밋: `29448031235634d3444103a22a2db7b2ccd0ab39`
- 제거 커밋: `87c0f0e61d5eb5a030fe4a70cdc40d3063cff135`
- 복구일: `2026-07-14`

## 복구 범위

- `crates/edge_proxy`
- `crates/edge_proxy_contract`
- `crates/common/src/config/model/edge_proxy_config.rs`
- `configs/edge_proxy.yaml`
- `configs.staging/edge_proxy.yaml`
- `scripts/systemd/edge_proxy.service.template`
- `specs/edge_proxy`
- `specs/edge_proxy_contract`

## 사용 경계

- 월척 도메인, 포트, 경로와 운영 설정은 VPSGuard 코드로 이관하기 전에 제거합니다.
- 이 사본은 원본 workspace 의존성을 그대로 가지므로 독립 빌드를 보장하지 않습니다.
- VPSGuard 구현은 `EDGE-*` 요구사항과 `specs/product/08-implementation-backlog.md`의 배치 1을 따라 별도 crate로 진행합니다.
- 원본 저장소에서 별도 루트 라이선스 파일이 확인되지 않았으므로 외부 배포 전 소유권과 라이선스 표기를 확정합니다.
