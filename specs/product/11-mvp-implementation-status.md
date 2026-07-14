---
title: VPSGuard Development MVP Status
status: active
doc_type: implementation-status
source_of_truth: true
spec_version: 1
last_reviewed: 2026-07-14
---

# 개발 MVP 구현 현황

## 판정

로컬에서 재현 가능한 **개발 MVP**는 완료했습니다. Pingora가 loopback origin을 proxy하고 안전 정책과 telemetry를 실행하며, control API와 독립 운영 UI가 상태를 표시하고 수동 고정을 원자 저장합니다. 실제 고객 서버에 public 80/443을 넘기는 release 인증은 완료하지 않았습니다.

## 구현 완료

| 영역 | 구현 | 주요 증거 |
|---|---|---|
| `EDGE-003`, `EDGE-004`, `EDGE-006`, `EDGE-007` | streaming loopback proxy, trusted forwarded chain, 경로별 body·timeout, control 비의존 | `scripts/integration-gate.sh`, edge policy tests |
| `EDGE-010`~`EDGE-012` | live/ready 분리, query·body 로그 제외, bounded limiter | edge unit·integration tests |
| `OBS-001`, `OBS-008` 일부 | status·latency·client·decision aggregate, non-blocking datagram과 drop counter | edge/control telemetry tests |
| `OBS-003` 일부 | Linux `/proc` load·memory·swap·uptime | agent fixture tests |
| `DET-001`, `DET-005`, `DET-007`, `DET-010` | trust·bot·cost 분리, reason code, spike 히스테리시스, 결손 confidence | core detection·state tests |
| `DET-002` | GnuBoard·WordPress 초기 route 비용 profile | profile tests |
| `ACT-001`, `ACT-002` | client·route fixed-window rate limit, 429·Retry-After | edge limiter·integration tests |
| `TLS-001` 일부 | 단일 certificate chain의 key·유효기간·SAN 검사 | TLS unit tests |
| `UI-001`, `UI-002`, `UI-011`, `UI-013` | loopback 운영 UI, mode·근거, light/dark, stale 상태 | Bun tests, control smoke |
| `OPS-002`, `OPS-007` 일부 | typed plan, systemd/tmpfiles, release bundle과 checksum | CLI tests, `scripts/ops-harness.sh` |
| `SEC-001`, `SEC-005` 일부 | token 환경 파일, query·header·body 미저장 | API auth·web tests |
| `NFR-003`, `NFR-004`, `NFR-006` 일부 | edge/control 분리, 원자 state, versioned strict schema | integration·atomic store tests |

## release gate 미완료

- `EDGE-001`, `EDGE-002`, `EDGE-005`: public 80/443, 인증서별 SNI 선택, WebSocket 실제 VPS E2E
- `EDGE-008`, `EDGE-009`, `ACT-003`~`ACT-005`: policy hot reload, signed challenge, TTL 차단과 nftables
- `OBS-002`, `OBS-004`~`OBS-007`, `OBS-010`: PHP-FPM·MySQL·Redis와 장기 집계·상관분석
- `UI-003`~`UI-010`, `UI-012`: SSE, client/route drill-down, 사건 timeline, 권한 분리
- `ACT-006`~`ACT-012`: 실제 Cloudflare·원본 방화벽 adapter와 audit event. test zone이 아직 보류입니다.
- `TLS-002`~`TLS-005`: renew hook, HTTP-01, served certificate 비교, reset 보존 실증
- `OPS-003`~`OPS-006`, `OPS-008`: public cutover, bypass, update rollback, uninstall, command audit runner
- 2GB `g7devops` 성능·장애·복구 파일럿과 x86_64/aarch64 release artifact

## 실행 범위

현재 허용 범위는 로컬·CI와 `g7devops` **shadow plan**까지입니다. `scripts/deploy-g7devops.sh`는 기본 plan-only이고, 이 변경에서는 실행하지 않습니다. public ingress와 Cloudflare 변경은 위 release gate를 통과한 별도 승인 작업입니다.
