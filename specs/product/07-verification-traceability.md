---
title: VPS Guard Verification and Traceability
status: draft-implementation-ready
doc_type: verification-contract
source_of_truth: true
spec_version: 1
last_reviewed: 2026-07-15
---

# 검증 추적표

## 1. 목적

이 문서는 [요구사항과 계약](06-requirements-contracts.md)의 각 ID를 코드, 자동 테스트, 실제 VPS 증거와 연결합니다. 테스트 이름과 경로는 새 저장소 생성 시 이 계약을 기준으로 만들며, 경로가 바뀌면 추적표를 같은 커밋에서 갱신합니다.

## 2. 테스트 계층

| 계층 | 목적 | 외부 의존성 |
|---|---|---|
| Unit | 점수, 상태 전이, 정책, 정규화와 검증 | 없음 |
| Contract | IPC, 설정, API, event와 provider 의미 검증 | fake server |
| Integration | Pingora, Nginx, collector, SQLite 연결 | local fixture |
| E2E | 브라우저, TLS, WebSocket, upload와 대응 흐름 | 격리 VM/VPS |
| Fault | process kill, disk, API와 부분 실패 | 격리 VM/VPS |
| Load | 지연, 처리량, 메모리와 탐지 효과 | 2GB 기준 서버 |

## 3. 요구사항 추적

아래 경로는 최종 수용 기준을 위한 **목표 테스트 경로**이며 파일 존재 자체를 현재 통과 증거로 간주하지 않습니다. 현재 구현·자동 검증·실제 VPS 검증 단계의 기계 판독 정본은 [`verification-status.tsv`](verification-status.tsv)입니다. `scripts/requirements-gate.sh`는 모든 요구사항의 상태와 증거 파일 존재를 검증하고, `--release`에서는 `PLANNED`와 `CODE_ONLY`를 차단합니다.

### 3.1 Edge

| 요구사항 | 예정 자동 증거 | 운영 증거 |
|---|---|---|
| `EDGE-001`, `EDGE-002` | `tests/e2e/tls_listeners.rs` | 80 redirect, 443 SNI smoke |
| `EDGE-003`, `EDGE-005` | `tests/e2e/proxy_protocols.rs` | HTTP/1.1, HTTP/2, WebSocket, streaming report |
| `EDGE-004` | `crates/guard-edge/tests/forwarded_headers.rs` | spoofed header access log |
| `EDGE-006`, `EDGE-008` | `crates/guard-edge/tests/request_policy.rs` | 일반·upload·search k6 결과 |
| `EDGE-007` | `tests/fault/control_down.rs` | control stop 중 HTTP success count |
| `EDGE-009` | `crates/guard-core/tests/policy_snapshot.rs` | corrupt policy rejection event |
| `EDGE-010` | `tests/integration/health_contract.rs` | origin down 상태 live/ready 비교 |
| `EDGE-011` | `tests/security/log_secret_scan.rs` | 배포 로그 secret scan |
| `EDGE-012` | `tests/load/high_cardinality.js` | RSS와 eviction/drop counter |
| `EDGE-013` | `scripts/integration-gate.sh` | `profiled`·`protocol_only` HTTP/TLS 정상 요청, app 판정 생략과 정적 불변조건 report |

### 3.2 Observation

| 요구사항 | 예정 자동 증거 | 운영 증거 |
|---|---|---|
| `OBS-001`, `OBS-007` | `crates/guard-control/tests/traffic_aggregate.rs` | k6와 UI 집계 비교 |
| `OBS-002`, `OBS-009` | `crates/guard-control/tests/client_enrichment.rs` | offline·GeoIP missing report |
| `OBS-003` | `crates/guard-agent/tests/os_collector.rs` | `/proc` 대조 report |
| `OBS-004` | `crates/guard-agent/tests/php_fpm_collector.rs` | PHP-FPM status 대조 |
| `OBS-005` | `crates/guard-agent/tests/mysql_collector.rs` | 최소 권한 DB 계정 smoke |
| `OBS-006` | `crates/guard-agent/tests/redis_collector.rs` | Redis on/off/error smoke |
| `OBS-008` | `tests/fault/telemetry_backpressure.rs` | drop counter와 HTTP success |
| `OBS-010` | `crates/guard-core/tests/resource_correlation.rs` | incident evidence snapshot |
| `OBS-011` | `crates/guard-agent/tests/systemd_cgroup_collector.rs` | 2GB VPS allowlisted unit과 cgroup 실제값 대조 |

### 3.3 Detection

| 요구사항 | 예정 자동 증거 | 운영 증거 |
|---|---|---|
| `DET-001`, `DET-005` | `crates/guard-core/tests/scoring.rs` | score explanation snapshot |
| `DET-002` | `crates/guard-profiles/src/tests.rs` | 범용 PHP·GnuBoard 5·7·WordPress route inventory |
| `DET-003`, `DET-004` | `crates/guard-core/tests/crawler_identity.rs` | verified·spoofed crawler replay |
| `DET-006`, `DET-007` | `crates/guard-core/tests/baseline_windows.rs` | spike와 지속 부하 비교 |
| `DET-008` | `crates/guard-core/tests/rule_expiry.rs` | TTL expiry event |
| `DET-009` | `crates/guard-core/tests/shared_ip.rs` | NAT browser scenario |
| `DET-010` | `tests/fault/collector_missing.rs` | degraded-confidence incident |
| `DET-011` | `crates/guard-edge/src/runtime/tests.rs` | app profile·site override·incident policy 합성 replay |
| `DET-012` | `crates/guard-profiles/src/tests.rs` | generic core와 G7 auth·CSP overlay 교차 profile fixture |

### 3.4 Action

| 요구사항 | 예정 자동 증거 | 운영 증거 |
|---|---|---|
| `ACT-001`, `ACT-002` | `crates/guard-edge/tests/rate_limit.rs` | 429·Retry-After curl report |
| `ACT-003` | `crates/guard-edge/tests/clearance.rs` | browser challenge E2E |
| `ACT-004` | `tests/e2e/degraded_features.rs` | search 보호 중 정적·상세 정상 |
| `ACT-005` | `crates/guard-core/tests/temporary_block.rs` | nftables set·TTL read-back |
| `ACT-006`, `ACT-007`, `ACT-008` | `crates/guard-provider/tests/cloudflare_transaction.rs` | 실제 test zone 전환·복구 artifact |
| `ACT-009` | `crates/guard-core/tests/manual_hold.rs` | UI hold 중 state timeline |
| `ACT-010` | `crates/guard-provider/tests/firewall_invariants.rs` | 전후 SSH·non-web listener·firewall rule diff |
| `ACT-011` | `tests/fault/provider_unavailable.rs` | local guard 지속 report |
| `ACT-012` | `crates/guard-control/tests/idempotent_actions.rs` | 중복 요청 provider call count |

### 3.5 TLS and operations

| 요구사항 | 예정 자동 증거 | 운영 증거 |
|---|---|---|
| `TLS-001` | `crates/guard-edge/tests/certificate_validation.rs` | invalid cert start rejection |
| `TLS-002`, `TLS-003`, `TLS-006` | `tests/e2e/certbot_renew.rs` | staging webroot issuance·systemd timer·renew·deploy hook report |
| `TLS-004` | `crates/guard-agent/tests/served_certificate.rs` | file/served cert comparison |
| `TLS-005` | `tests/e2e/certificate_preservation.rs` | update·bypass 전후 fingerprint |
| `OPS-001`, `OPS-002` | `tests/e2e/shadow_cutover.rs` | public ingress 전환 timeline |
| `OPS-003` | `scripts/tests/ingress-transaction-harness.sh` | 실패 rollback과 실제 public ingress 전환 timeline |
| `OPS-004` | `scripts/tests/ingress-transaction-harness.sh` | edge -> Nginx -> edge smoke |
| `OPS-005`, `OPS-006` | `tests/e2e/update_uninstall.rs` | rollback·소유 파일 manifest |
| `OPS-007` | release workflow | arch별 hash·SBOM·smoke artifact |
| `OPS-008` | `crates/guard-system/tests/command_audit.rs` | masked command log |
| `OPS-009` | `scripts/tests/deployment-restore-harness.sh` | [`g7devops` first-install 실패 자동 복구·수동 restore·재설치 report](evidence/g7devops-shadow-roundtrip-20260715.md) |

### 3.6 UI, security and NFR

| 요구사항 | 예정 자동 증거 | 운영 증거 |
|---|---|---|
| `UI-001`, `SEC-007` | config·edge runtime·control API tests와 `scripts/integration-gate.sh` | 별도 HTTPS 관리 Host routing·Control public port scan |
| `UI-002`, `UI-003`, `UI-004`, `UI-005`, `UI-006`, `UI-007`, `UI-008`, `UI-009` | `web/tests/fixtures.spec.ts` | 상태별 Playwright video·screenshot |
| `UI-010`, `UI-011` | `web/tests/visual.spec.ts` | theme·viewport screenshot diff |
| `UI-012` | `web/tests/permissions.spec.ts` | role별 IP·export·action matrix |
| `UI-013` | `web/tests/stale-data.spec.ts` | SSE·collector disconnect UI |
| `UI-014` | public surface inventory gate | route·menu allowlist artifact |
| `SEC-001`, `SEC-002`, `SEC-003`, `SEC-006` | admin socket·bootstrap·session authorization tests | 비인가 local UID·만료·재사용 login code denial report |
| `SEC-004`, `SEC-005` | provider allowlist·secret scan tests | fake cross-zone denial report |
| `SEC-008`, `SEC-009`, `SEC-010`, `SEC-011` | `scripts/integration-gate.sh`, edge security unit tests | method·header·auth limit·secret payload report와 G7 정상 브라우저 관찰 |
| `NFR-001`, `NFR-002` | Criterion + k6 regression | 2GB VPS perf artifact |
| `NFR-003` | process kill fault test | zero-error request counter |
| `NFR-004`, `NFR-006` | state crash/migration tests | kill -9 recovery artifact |
| `NFR-005` | error snapshot tests | UI·CLI problem report |
| `NFR-007` | workspace lint 상속·module rustdoc gate·`cargo doc -D warnings` | CI rustdoc build artifact |
| `NFR-008` | dependency decision record + audit·deny·machete | 2GB VPS binary·RSS dependency diff |

## 4. 품질 게이트

모든 pull request:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items
cargo test --workspace --all-features
cargo audit
cargo deny check
bun install --frozen-lockfile
bun run build
bun test
```

릴리스 후보:

```bash
bash scripts/coverage-gate.sh
bash scripts/integration-gate.sh
bash scripts/load-regression-gate.sh
bash scripts/ops-harness.sh
bun run test:e2e
```

## 5. 커버리지 하한

초기 하한:

| 영역 | line coverage |
|---|---:|
| `guard-core` scoring·state·policy | 90% |
| `guard-provider` transaction·rollback | 90% |
| `guard-edge` 자체 policy code | 85% |
| workspace 전체 | 80% |

외부 Pingora 내부 코드와 생성 asset은 분모에서 제외할 수 있지만 제외 목록을 저장소에 명시합니다. 하한을 낮추려면 ADR, 누락 line 목록과 보완 테스트 계획이 필요합니다.

커버리지는 실제 TLS·provider·bypass 검증을 대신하지 않습니다.

## 6. 성능 예산

초기 release gate는 동일 서버·동일 fixture에서 direct Nginx와 guard-edge 경유를 비교합니다.

| 지표 | 초기 예산 |
|---|---:|
| 50 VU 정상 browse p95 추가 지연 | 2ms 이하 |
| 동일 부하 처리량 감소 | 10% 이하 |
| guard-edge + control + agent RSS | 256MB 이하 |
| high-cardinality 30분 RSS 증가 | 시작 대비 20% 이내에서 안정화 |
| control 재시작 중 proxy 오류 | 0건 |
| 정책 reload 중 proxy 오류 | 0건 |

측정 환경, kernel, CPU, artifact hash와 Nginx 설정을 함께 보존합니다. 예산 변경은 실제 데이터와 ADR 없이 허용하지 않습니다.

## 7. 탐지 효과 게이트

합성 시나리오 기준 초기 하한:

- 정상 브라우저 fixture hard block: 0건
- shared IP 정상 세션 전체 차단: 0건
- 위조 검색봇 verified 판정: 0건
- 고비용 scraper 요청의 upstream 도달 감소: 90% 이상
- 지속 임계 초과 후 LOCAL_GUARD 적용: 5초 이내
- 단일 짧은 spike의 EMERGENCY_PROXY 전환: 0건
- 모든 자동 조치 reason code 누락: 0건

실사용 오탐률 목표는 파일럿 관찰 기간을 거쳐 별도로 확정합니다. 합성 테스트만으로 “사람과 봇을 정확히 구분했다”고 발표하지 않습니다.

## 8. 장애 주입

릴리스 전 최소 장애:

1. control process kill과 반복 restart
2. telemetry socket full·삭제·권한 오류
3. policy file truncate·hash mismatch·미래 schema
4. SQLite busy·disk full·read-only 전환
5. PHP-FPM·MySQL·Redis collector timeout
6. Cloudflare 401, 403, 429, 5xx와 response timeout
7. DNS read-back 성공 후 HTTPS probe 실패
8. origin firewall apply 성공 후 verify 실패
9. 만료·불일치 TLS certificate
10. edge public cutover 중 process failure
11. bypass 중 Nginx configtest·bind·probe 실패
12. UI SSE disconnect·event gap·server clock skew

각 장애는 예상 state, 사용자 오류, 자동 rollback과 남은 수동 조치를 snapshot으로 검증합니다.

## 9. 실제 VPS 하네스

공개 지원 조합마다 다음 artifact를 생성합니다.

- commit, version, target triple과 binary SHA-256
- VPS CPU·memory·OS·kernel
- 설치 전 port·service·firewall snapshot
- shadow mode 결과
- direct TLS와 origin smoke
- GnuBoard browse·search·login·upload·WebSocket smoke
- 정상·bot k6 결과
- Cloudflare test zone 전환·복구
- certificate renew
- bypass round trip
- uninstall 후 원본 사이트·인증서 확인
- 구조화 incident와 최종 report

## 10. 릴리스 판정

다음 중 하나라도 있으면 릴리스를 금지합니다.

- 필수 요구사항에 자동 테스트 또는 운영 증거가 없음
- 성능 예산 초과
- 정상 fixture hard block 발생
- provider 부분 실패를 성공으로 표시
- SSH·인증서 보존 불변조건 위반
- bypass 또는 update rollback 실패
- UI가 stale·unavailable 값을 정상으로 표시
- x86_64·aarch64 중 하나의 artifact smoke 누락

## 11. 증거 디렉터리

```text
target/evidence/
  unit/
  integration/
  playwright/
  load/<timestamp>/
  fault/<timestamp>/
  ops-harness/<provider>/<timestamp>/
  release/<version>/
```

CI artifact에는 비밀값과 보존기간이 지난 원본 IP를 포함하지 않습니다.
