---
title: VPSGuard pre-MVP Status
status: active
doc_type: implementation-status
source_of_truth: true
spec_version: 1
last_reviewed: 2026-07-15
---

# pre-MVP 구현 현황

## 판정

현재 상태는 **pre-MVP 개발용 수직 슬라이스**입니다. 기본 Rust 단위 테스트와 loopback smoke는 재현되지만, 요구사항별 자동 증거·실제 VPS 장애 주입·Cloudflare test zone·public 80/443·rollback 인증이 남아 있습니다. 코드가 존재하는 항목을 완료로 간주하지 않으며 현재 단계는 [`verification-status.tsv`](verification-status.tsv)의 `PLANNED`, `CODE_ONLY`, `AUTO_PASS`, `VPS_PASS`로 판정합니다.

현재 요구사항 95개 중 `PLANNED` 12개, `CODE_ONLY` 41개, `AUTO_PASS` 42개, `VPS_PASS` 0개입니다. 즉 83개는 코드 또는 계약이 존재하며 자동 수용 기준까지 통과한 것은 42개이고, 실제 VPS 운영 수용 기준을 완료한 항목은 아직 없습니다.

## 코드 및 자동 검증 현황

| 영역 | 구현 | 주요 증거 |
|---|---|---|
| `EDGE-003`, `EDGE-004`, `EDGE-006`, `EDGE-007` | streaming loopback proxy, trusted forwarded chain, 경로별 body·timeout, control 비의존 | `scripts/integration-gate.sh`, edge policy tests |
| `EDGE-010`~`EDGE-012` | 첫 origin 성공 전 ready 차단, live/ready 분리, query·header·body 비밀값 로그 제외, bounded limiter | edge unit·integration secret scan |
| `EDGE-013` | enforcement와 독립된 `profiled`·`protocol_only`, app·행동 판정 생략 시에도 HTTP/TLS·Host·forwarded header·body·timeout·bounded 계측 유지 | edge config/runtime unit test와 loopback HTTP/TLS integration; HTTP/2·WebSocket 실 VPS 증거는 별도 `EDGE-002`, `EDGE-005` gate |
| `EDGE-008`, `EDGE-009` | policy hash·request-time TTL·version 검증, last-known-good 원자 hot reload와 5분 lease 갱신 | `policy_runtime`·control runtime tests |
| `OBS-001`, `OBS-008` | status·latency·bytes·upstream connection·client·route aggregate, SQLite WAL·retention, non-blocking datagram 재연결·손실 계측 | telemetry·storage·loopback integration tests |
| `OBS-003`~`OBS-006`, `OBS-011` | Linux `/proc` 서버값, allowlist systemd unit의 cgroup v2 CPU·memory·I/O·process/task, Nginx/Apache·PHP-FPM·MySQL/MariaDB·Redis semantic metric과 component별 timeout/error/stale 상태 | config·bounded parser·loopback transport·cgroup fixture, Control resource API와 Playwright; 실제 DB/Redis·2GB VPS 대조는 미완료 |
| `OBS-007` 자동 검증 | 설정 상한이 적용된 1초 live ring, 전용 blocking batch writer, SQLite WAL 상세·client IP·10초·1분 rollup, 계층별 bounded retention, DB/WAL·disk·drop health | telemetry·storage·API·UI 회귀 테스트; busy·disk-full fault와 2GB VPS 부하 증거는 미완료 |
| `DET-001`, `DET-005`, `DET-007`, `DET-010` | trust·bot·cost 분리, reason code, spike 히스테리시스, 결손 confidence | core detection·state tests |
| `DET-002`, `DET-011`, `DET-012` | 범용 PHP·GnuBoard 5·GnuBoard 7·WordPress route 분리, app 분류와 site override 합성, generic 보안 core와 G7 CSP·auth overlay 분리 | profile·edge runtime·security tests |
| `ACT-001`~`ACT-005` | client·route 제한, 429, signed clearance, 기능별 정책, TTL client rule | edge limiter·challenge·policy tests |
| `ACT-006`~`ACT-012` 코드 | User token preflight, 동일 hostname의 명시적 A·AAAA/CNAME record ID별 checkpoint·즉시 rollback, Cloudflare read-back·외부 `cf-ray` 코드 경로, dual-stack nftables 원자 교체·정확 read-back, 중간 단계 복구·idempotency | fake API/provider/system/control tests; 실제 test zone 변경 증거 없음 |
| `TLS-001` 일부 | 단일 certificate chain의 key·유효기간·SAN 검사 | TLS unit tests |
| `TLS-002`, `TLS-005`, `TLS-006` 하네스 | startup cert/key·SAN·유효기간 preflight, 6시간 공개 cert·Certbot renewal/timer 관측, external/assisted/manual 소유권, systemd credential 경계, 승인 전 HTTP-01 plan, deploy hook과 보존 | typed unit/API/UI tests; 실제 staging 발급·renew·served cert 비교와 graceful reload 증거는 미수집 |
| `UI-001`~`UI-004`, `UI-007`, `UI-009`, `UI-011`, `UI-013`, `UI-014` | 별도 HTTPS 관리 Host→loopback Control 분리, CSR SPA, 인증된 SSE·조회, client 검색·필터·정렬·페이지, 운영 명령 확인, light/dark, stale/error | local TLS integration·Bun·Playwright·control tests |
| `OPS-002`~`OPS-008` 하네스 | typed plan, checksum·architecture shadow preflight, ingress rollback, control+edge update health, bypass 선검증 uninstall, arch matrix·SBOM·command audit | plan test와 release workflow; 실제 VPS apply 증거 없음 |
| 회귀 차단 코드 | nextest, rustdoc, audit/deny/machete, 영역별 coverage ratchet, loopback integration, k6 부하, Bun unit, desktop/mobile Playwright를 merge gate로 연결 | GitHub branch protection 적용 전에는 강제되지 않음 |
| `SEC-003`, `SEC-006`, `SEC-007` | peer-credential local socket의 단회 code, client별 시도 제한·knockout 방지·재사용 거부, Host·Origin 고정, Secure·HttpOnly session, 인증된 읽기·SSE, CSRF·idempotency 변경 | admin socket·API auth tests, local TLS integration |
| `SEC-001`, `SEC-005` | root-only provider secret 원본, systemd credential 전달, memory redaction·임시 buffer zeroize, CSP, query·header·body 미저장 | provider secret·debug redaction, API auth·web tests |
| `SEC-008`~`SEC-011` | CONNECT·TRACE·TRACK 거부, origin version header 제거, baseline header·HTTPS HSTS·CSP report-only/enforce, G7 auth 전용 bounded client 한도와 XSS/SQLi origin 책임 경계 | config·profile·edge unit, loopback HTTP/TLS·secret scan과 관리 API·UI tests |
| `NFR-003`, `NFR-004`, `NFR-006` 일부 | edge/control 분리, 원자 state, versioned strict schema | integration·atomic store tests |
| `NFR-007` | workspace `missing_docs = "deny"`, 모든 crate lint 상속, module `//!`, lint 우회 금지, private item 포함 rustdoc warning 거부 | docs gate·repository contract·CI rustdoc build |
| `NFR-008` 계약 | 표준 protocol·DB driver는 외부 crate/client를 우선하고 project 고유 bounded 불변조건만 직접 구현하는 선택 기준 | ADR 0002; crate별 적용과 2GB binary·RSS 비교는 미완료 |
| 운영 로그 일부 | edge/control JSON stdout 로그를 systemd journal이 수집하고 request 완료는 비식별 `debug`로 제한 | journald per-unit rate limit·보존 상태 UI는 미구현 |

## release gate 미완료

- `EDGE-001`, `EDGE-002`, `EDGE-005`: `g7devops` public 80/443, 인증서별 multi-SNI 선택, WebSocket 실제 VPS E2E
- `OBS-003`~`OBS-006`, `OBS-010`, `OBS-011`: semantic·cgroup 수집 코드는 구현됐으나 실제 MySQL/Redis 최소 권한 smoke, cgroup/systemd 값 대조, busy·disk-full 장애와 2GB VPS 정확도·route-resource 상관 검증이 남음
- `UI-001`: 실제 public 443 관리 Host의 인증서·접속·복구와 앱 origin 비혼선 VPS 증거
- `UI-005`, `UI-006`, `UI-008`, `UI-010`, `UI-012`: client 상세 score/action, 동일축 상관 그래프, TLS 실제 read-back, 용어집, read/export 세부 역할 분리
- `DET-012`, `SEC-009`, `SEC-010`: loopback 자동 증거는 통과했으나 실제 G7 정상 browser CSP violation, Reverb·외부 asset 호환과 shared IP 인증 오탐을 관찰하기 전에는 CSP enforce·강한 auth 한도를 기본 적용하지 않음. 계정·session 단위 방어는 계속 origin 책임
- `ACT-006`~`ACT-010`: User token과 record ID·type preflight는 fake API까지 구현됐으며, Cloudflare test zone 전환·복구와 실제 kernel/SSH·non-web port diff 증거가 남음. Account API Token onboarding은 zone-scoped DNS Write 재현 전까지 제외
- `TLS-002`~`TLS-006`: 기존 manager·timer 감지와 승인 전 plan은 구현됐으며, plan hash 기반 apply, Certbot staging HTTP-01·systemd timer renew, 실제 served certificate 비교와 bypass 후 fingerprint 증거가 남음
- `OPS-003`~`OPS-007`: public cutover·bypass 왕복, update/uninstall 실증, x86_64/aarch64 artifact 실행 smoke
- 2GB `g7devops` 성능·장애·복구 파일럿

## 실행 범위

현재 허용 범위는 로컬·CI와 `g7devops` **shadow plan**까지입니다. `scripts/deploy-g7devops.sh`는 기본 plan-only이고, 이 변경에서는 실행하지 않습니다. public ingress와 Cloudflare 변경은 위 release gate를 통과한 별도 승인 작업입니다.
