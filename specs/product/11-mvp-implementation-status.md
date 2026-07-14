---
title: VPSGuard pre-MVP Status
status: active
doc_type: implementation-status
source_of_truth: true
spec_version: 1
last_reviewed: 2026-07-14
---

# pre-MVP 구현 현황

## 판정

현재 상태는 **pre-MVP 개발용 수직 슬라이스**입니다. 기본 Rust 단위 테스트와 loopback smoke는 재현되지만, 요구사항별 자동 증거·실제 VPS 장애 주입·Cloudflare test zone·public 80/443·rollback 인증이 남아 있습니다. 코드가 존재하는 항목을 완료로 간주하지 않으며 현재 단계는 [`verification-status.tsv`](verification-status.tsv)의 `PLANNED`, `CODE_ONLY`, `AUTO_PASS`, `VPS_PASS`로 판정합니다.

## 코드 및 자동 검증 현황

| 영역 | 구현 | 주요 증거 |
|---|---|---|
| `EDGE-003`, `EDGE-004`, `EDGE-006`, `EDGE-007` | streaming loopback proxy, trusted forwarded chain, 경로별 body·timeout, control 비의존 | `scripts/integration-gate.sh`, edge policy tests |
| `EDGE-010`~`EDGE-012` | live/ready 분리, query·body 로그 제외, bounded limiter | edge unit·integration tests |
| `EDGE-008`, `EDGE-009` | policy hash·TTL·version 검증, last-known-good 원자 hot reload | `policy_runtime` tests |
| `OBS-001`, `OBS-005`, `OBS-006`, `OBS-008` | status·latency·bytes·upstream connection·client·route aggregate, SQLite WAL·retention, non-blocking datagram | telemetry·storage·loopback integration tests |
| `OBS-002`, `OBS-003` | Linux `/proc`, Nginx/PHP HTTP, MySQL TCP, Redis PING와 collector health | agent tests, control resource API |
| `DET-001`, `DET-005`, `DET-007`, `DET-010` | trust·bot·cost 분리, reason code, spike 히스테리시스, 결손 confidence | core detection·state tests |
| `DET-002` | GnuBoard·WordPress 초기 route 비용 profile | profile tests |
| `ACT-001`~`ACT-005` | client·route 제한, 429, signed clearance, 기능별 정책, TTL client rule | edge limiter·challenge·policy tests |
| `ACT-006`~`ACT-012` 코드 | 단계별 checkpoint, Cloudflare read-back, 외부 `cf-ray`, nftables 80/443 원본 잠금, 자동 전환·역순 복구·명령 잠금·감사·idempotency | provider/system/control tests |
| `TLS-001` 일부 | 단일 certificate chain의 key·유효기간·SAN 검사 | TLS unit tests |
| `TLS-002`, `TLS-005` 하네스 | cert/key deploy preflight, update·uninstall 인증서 보존 | Certbot hook, ops plan |
| `UI-001`~`UI-004`, `UI-007`, `UI-009`, `UI-011`, `UI-013`, `UI-014` | CSR SPA, SSE 사건, bytes·connection, client 검색·필터·정렬·페이지, provider 진행률, 운영 명령 확인, light/dark, stale/error | Bun·Playwright·control smoke |
| `UI-012` 일부 | 비인증 client IP network 마스킹, session 인증 후 원본 IP 표시, 민감 export 미제공 | API authorization regression |
| `OPS-002`~`OPS-008` 하네스 | typed plan, ingress rollback, bypass, update rollback, ownership uninstall, arch matrix·SBOM·command audit | `scripts/ops-harness.sh`, release workflow |
| 회귀 차단 코드 | nextest, rustdoc, audit/deny/machete, 영역별 coverage ratchet, loopback integration, k6 부하, Bun unit, desktop/mobile Playwright를 merge gate로 연결 | GitHub branch protection 적용 전에는 강제되지 않음 |
| `SEC-001`, `SEC-005` | root-only token, memory session·CSRF, CSP, query·header·body 미저장 | API auth·web tests |
| `NFR-003`, `NFR-004`, `NFR-006` 일부 | edge/control 분리, 원자 state, versioned strict schema | integration·atomic store tests |

## release gate 미완료

- `EDGE-001`, `EDGE-002`, `EDGE-005`: `g7devops` public 80/443, 인증서별 multi-SNI 선택, WebSocket 실제 VPS E2E
- `OBS-004`, `OBS-007`, `OBS-010`: 실제 2GB VPS 기준 connection/network 계측 정확도와 route-resource 상관 검증
- `UI-005`, `UI-006`, `UI-008`, `UI-010`, `UI-012`: client 상세 score/action, 동일축 상관 그래프, TLS 실제 read-back, 용어집, read/export 세부 역할 분리
- `ACT-006`~`ACT-010`: Cloudflare test zone 전환·복구와 실제 kernel/SSH rule diff 증거
- `TLS-002`~`TLS-005`: staging HTTP-01, renew, 실제 served certificate 비교와 bypass 후 fingerprint 증거
- `OPS-003`~`OPS-007`: public cutover·bypass 왕복, update/uninstall 실증, x86_64/aarch64 artifact 실행 smoke
- 2GB `g7devops` 성능·장애·복구 파일럿

## 실행 범위

현재 허용 범위는 로컬·CI와 `g7devops` **shadow plan**까지입니다. `scripts/deploy-g7devops.sh`는 기본 plan-only이고, 이 변경에서는 실행하지 않습니다. public ingress와 Cloudflare 변경은 위 release gate를 통과한 별도 승인 작업입니다.
