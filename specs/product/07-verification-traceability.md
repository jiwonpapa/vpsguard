---
title: VPS Guard Verification and Traceability
status: draft-implementation-ready
doc_type: verification-contract
source_of_truth: true
spec_version: 1
last_reviewed: 2026-07-24
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
| `EDGE-001`, `EDGE-002` | `tests/e2e/tls_listeners.rs` | [`g7devops` 80 redirect, 443 SNI smoke](evidence/g7devops-direct-tls-20260715.md) |
| `EDGE-003`, `EDGE-005` | `tests/e2e/proxy_protocols.rs` | [`g7devops` HTTP/1.1, HTTP/2, WebSocket report](evidence/g7devops-direct-tls-20260715.md) |
| `EDGE-004` | `crates/guard-edge/tests/forwarded_headers.rs` | spoofed header access log |
| `EDGE-006`, `EDGE-008` | `crates/guard-edge/tests/request_policy.rs` | 일반·upload·search k6 결과 |
| `EDGE-007` | `tests/fault/control_down.rs` | control stop 중 HTTP success count |
| `EDGE-009` | `crates/guard-core/tests/policy_snapshot.rs` | corrupt policy rejection event |
| `EDGE-010` | `tests/integration/health_contract.rs` | origin down 상태 live/ready 비교 |
| `EDGE-011` | `crates/guard-edge/src/telemetry/tests.rs`, `scripts/integration-gate.sh` | 배포 로그 secret scan |
| `EDGE-012` | `tests/load/high_cardinality.js` | RSS와 eviction/drop counter |
| `EDGE-013` | `crates/guard-edge/src/runtime/tests.rs`, `scripts/integration-gate.sh` | `profiled`·`protocol_only` HTTP/TLS 정상 요청, app 판정 생략·공통 rate limit과 정적 불변조건 report |
| `EDGE-014` | `crates/guard-edge/src/rate_limit/tests.rs`, `tests/vm/gnuboard5-toolkit.json` | [limiter capacity·prefix/route/global budget, XFF 우회와 2GB burst RSS report](evidence/gnuboard5-standalone-security-20260722.md) |
| `EDGE-015` | `crates/guard-core/src/config/tests.rs`, `crates/guard-edge/src/runtime/tests.rs`, `scripts/integration-gate.sh` | slow-header·slow-body·slow-reader와 2GB concurrent soak report |

### 3.2 Observation

| 요구사항 | 예정 자동 증거 | 운영 증거 |
|---|---|---|
| `OBS-001`, `OBS-007` | `crates/guard-control/src/telemetry/tests.rs`, `crates/guard-control/src/storage.rs`, `scripts/integration-gate.sh` | k6와 UI 집계 비교 |
| `OBS-002`, `OBS-009` | `crates/guard-control/src/storage.rs`, `crates/guard-core/src/crawler.rs` | offline·GeoIP missing report |
| `OBS-003` | `crates/guard-agent/tests/os_collector.rs` | `/proc` 대조 report |
| `OBS-004` | `crates/guard-agent/tests/php_fpm_collector.rs` | PHP-FPM status 대조 |
| `OBS-005` | `crates/guard-agent/tests/mysql_collector.rs` | 최소 권한 DB 계정 smoke |
| `OBS-006` | `crates/guard-agent/tests/redis_collector.rs` | Redis on/off/error smoke |
| `OBS-008` | `crates/guard-edge/src/telemetry/tests.rs`, `crates/guard-control/src/telemetry/tests.rs` | drop counter와 HTTP success |
| `OBS-010` | `crates/guard-core/tests/resource_correlation.rs` | incident evidence snapshot |
| `OBS-011` | `crates/guard-agent/tests/systemd_cgroup_collector.rs` | 2GB VPS allowlisted unit과 cgroup 실제값 대조 |
| `OBS-012` | `crates/guard-core/src/correlation.rs`, `crates/guard-control/src/storage.rs`, `crates/guard-control/src/api/tests.rs`, `scripts/integration-gate.sh` | public 응답·Nginx upstream·Control UI의 동일 request ID 조회 report |
| `OBS-013` | `crates/guard-control/src/api/tests.rs`, `scripts/tests/repository-contracts.sh`, `scripts/integration-gate.sh` | edge/control journal JSON field와 식별자 상관 조회 report |
| `OBS-014` | `crates/guard-control/src/notification/tests.rs`, `crates/guard-control/src/api/tests.rs`, `web/tests/console.e2e.ts` | 실제 HTTPS receiver의 장애·복구와 2GB VPS 알림 read-back report |

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
| `DET-013` | `crates/guard-core/src/crawler.rs`, `crates/guard-core/src/config/tests.rs`, `tools/tests/test_update_crawler_networks.py` | [공식 CIDR fixture, 위조 Googlebot·미허용 AI bot VM replay](evidence/gnuboard5-standalone-security-20260722.md) |
| `DET-014` | `crates/guard-agent/tests/os_collector.rs`, `crates/guard-core/src/detection/tests.rs`, `crates/guard-control/src/runtime/tests.rs` | 2GB VPS의 `/proc`·Control API 대조와 synthetic pressure 상태 전이 timeline |

### 3.4 Action

| 요구사항 | 예정 자동 증거 | 운영 증거 |
|---|---|---|
| `ACT-001`, `ACT-002` | `crates/guard-edge/tests/rate_limit.rs` | 429·Retry-After curl report |
| `ACT-003` | `crates/guard-edge/tests/clearance.rs` | browser challenge E2E |
| `ACT-004` | `tests/e2e/degraded_features.rs` | search 보호 중 정적·상세 정상 |
| `ACT-005` | `crates/guard-core/tests/temporary_block.rs` | nftables set·TTL read-back |
| `ACT-006`, `ACT-007` | `crates/guard-provider/tests/cloudflare_transaction.rs` | 실제 test zone 전환·복구 artifact |
| `ACT-008` | `crates/guard-core/src/state/tests.rs`, `crates/guard-control/src/api/tests.rs`, `web/tests/console.e2e.ts` | 실제 test zone에서 `RECOVERY_READY` 유지·관리자 승인·DNS only read-back artifact |
| `ACT-009` | `crates/guard-core/tests/manual_hold.rs` | UI hold 중 state timeline |
| `ACT-010` | `crates/guard-provider/tests/firewall_invariants.rs` | 전후 SSH·non-web listener·firewall rule diff |
| `ACT-011` | `tests/fault/provider_unavailable.rs` | local guard 지속 report |
| `ACT-012` | `crates/guard-control/tests/idempotent_actions.rs` | 중복 요청 provider call count |
| `ACT-013`, `ACT-014` | `crates/guard-system/src/ufw.rs`, `crates/guard-control/src/api/tests.rs`, `tools/vm/standalone-security-probe.sh` | [standalone UFW apply·read-back·remove, foreign rule·SSH 보존과 JW-agent delegated mutation 0](evidence/gnuboard5-standalone-security-20260722.md) |

### 3.5 TLS and operations

| 요구사항 | 예정 자동 증거 | 운영 증거 |
|---|---|---|
| `TLS-001` | `crates/guard-edge/tests/certificate_validation.rs` | invalid cert start rejection |
| `TLS-002`, `TLS-003`, `TLS-006` | `tests/e2e/certbot_renew.rs` | [`g7devops` staging webroot renew·timer·deploy hook report](evidence/g7devops-direct-tls-20260715.md) |
| `TLS-004` | `crates/guard-system/src/tls/served/tests.rs`, `crates/guard-cli/src/main.rs`, `tools/tests/test_packaging_security.py` | staging renewal 직후 hook·listener fingerprint comparison |
| `TLS-005` | `tests/e2e/certificate_preservation.rs` | [`g7devops` 전환 전후 fingerprint](evidence/g7devops-direct-tls-20260715.md) |
| `OPS-001`, `OPS-002` | `tests/e2e/shadow_cutover.rs` | public ingress 전환 timeline |
| `OPS-003` | `crates/guard-system/src/ingress_state/tests.rs`, `crates/guard-cli/tests/ingress_cli.rs`, `scripts/tests/direct-state-harness.sh` | [`g7devops` 실패 rollback과 실제 public ingress 전환 timeline](evidence/g7devops-direct-tls-20260715.md) |
| `OPS-004` | `crates/guard-system/src/ingress_state/tests.rs`, `crates/guard-cli/tests/ingress_cli.rs`, `scripts/tests/ingress-transaction-harness.sh` | [`g7devops` edge -> Nginx -> direct edge smoke](evidence/g7devops-direct-tls-20260715.md) |
| `OPS-005`, `OPS-006` | `tools/vpsguard_harness/release_lifecycle.py`, `scripts/update-release.sh`, `scripts/tests/repository-contracts.sh`, `scripts/uninstall.sh` | 15초 health hard limit과 격리 Ubuntu VM/VPS의 실제 bundle update·uninstall·public probe timeline |
| `OPS-007` | `.github/workflows/release.yml`, `crates/guard-control/tests/version_cli.rs`, `crates/guard-edge/tests/version_cli.rs`, `tools/tests/test_release_workflow.py` | [x86_64·aarch64 native bundle 실행, checksum·SBOM·attestation artifact](evidence/release-matrix-20260724.md) |
| `OPS-008` | `crates/guard-system/src/command.rs`, `scripts/tests/repository-contracts.sh` | masked command log |
| `OPS-009` | `crates/guard-system/src/deployment_state/tests.rs`, `scripts/tests/deployment-restore-harness.sh` | [`g7devops` first-install 실패 자동 복구·수동 restore·재설치 report](evidence/g7devops-shadow-roundtrip-20260715.md) |
| `OPS-010` | `crates/guard-system/src/operation/tests.rs`, `crates/guard-system/src/deployment_state/tests.rs`, `crates/guard-system/src/ingress_state/tests.rs`, `scripts/tests/operation-harness.sh`, `tools/tests/test_qga.py`, `tools/tests/test_release_endurance.py` | 기존 parent mode·payload mode·uid·gid 원복, guest timeout process 종료 회귀와 `tools/vpsguard_harness/release_endurance.py`의 2GB Ubuntu VM 20회 apply·restore·100ms public probe·단계별 duration report |
| `OPS-011` | `crates/guard-system/src/ingress_state/apache/tests.rs`, `crates/guard-cli/tests/apache_ingress_cli.rs` | [`gnuboard5` Apache 전환·20회 왕복·rollback report](evidence/gnuboard5-apache-vm-20260722.md) |

### 3.6 UI, security and NFR

| 요구사항 | 예정 자동 증거 | 운영 증거 |
|---|---|---|
| `UI-001`, `SEC-007` | config·edge runtime·control API tests와 `scripts/integration-gate.sh` | 별도 HTTPS 관리 Host routing·Control public port scan |
| `UI-002`, `UI-003`, `UI-004`, `UI-005`, `UI-006`, `UI-007`, `UI-008`, `UI-009` | `web/tests/fixtures.spec.ts` | 상태별 Playwright video·screenshot |
| `UI-010`, `UI-011` | `web/tests/console.e2e.ts`, `web/tests/visual.e2e.ts` | 메뉴 그룹·운영 section 계약, 비로그인 gate와 인증 후 overview의 theme·viewport screenshot diff |
| `UI-012` | `web/tests/permissions.spec.ts` | role별 IP·export·action matrix |
| `UI-013` | `web/tests/stale-data.spec.ts` | SSE·collector disconnect UI |
| `UI-014` | public surface inventory gate | route·menu allowlist artifact |
| `UI-015` | `crates/guard-control/src/api/tests.rs`, `web/src/lib/auth.test.ts`, `web/tests/console.e2e.ts` | 별도 HTTPS 관리 Host에서 PAM 미등록 gate·사용자 QR 등록·계정/TOTP 로그인과 terminal 없는 일상 접속 browser report |
| `UI-016` | `crates/guard-core/src/config/tests.rs`, `crates/guard-edge/src/runtime.rs`, `web/tests/console.e2e.ts` | [Apache trusted TLS terminator의 직접 HTTPS 관리 Host·Secure PAM session과 Control public port scan](evidence/gnuboard5-standalone-security-20260722.md) |
| `UI-017` | `crates/guard-control/src/api/tests.rs`, `web/tests/console.e2e.ts` | [standalone typed UFW 화면과 JW-agent 위임 read-only browser/API report](evidence/gnuboard5-standalone-security-20260722.md) |
| `UI-018` | `crates/guard-core/src/policy/tests.rs`, `crates/guard-control/src/protection/tests.rs`, `crates/guard-control/src/api/tests.rs`, `web/tests/console.e2e.ts`, `tools/tests/test_protection_pilot.py` | 구버전 policy writer의 설정 일치 version 전진·불일치 거부와 [격리 VM의 verified bundle update·2GB guest MemTotal·정책 적용 전후 Edge telemetry version·정상/strict/upload 응답·원복 read-back](evidence/gnuboard5-ui018-policy-20260724.md) |
| `SEC-001`, `SEC-002`, `SEC-003`, `SEC-006` | admin socket·bootstrap·session authorization tests | 비인가 local UID·만료·재사용 login code denial report |
| `SEC-004`, `SEC-005` | provider allowlist·secret scan tests | fake cross-zone denial report |
| `SEC-008`, `SEC-009`, `SEC-010`, `SEC-011` | `scripts/integration-gate.sh`, edge security unit tests | method·header·auth limit·secret payload report와 G7 정상 브라우저 관찰 |
| `SEC-012`, `SEC-013`, `SEC-014` | `crates/guard-control/src/auth/tests.rs`, `crates/guard-control/src/pam_mfa.rs`, `crates/guard-control/src/api/tests.rs` | 2GB VPS 재시작 session, root-only AEAD TOTP·hash-only 복구 코드와 auth 저장소 secret scan report |
| `SEC-015` | `crates/guard-control/src/pam_auth.rs`, `crates/guard-control/src/pam_mfa.rs`, `crates/guard-control/src/auth/tests.rs`, `tools/vm/pam-login-probe.sh` | Ubuntu PAM group·root/locked denial, 실제 사용자 QR 등록과 사용자 입력 TOTP session report. 2026-07-22 자동 생성 test seed 증거는 사용자 등록 증거에서 제외 |
| `SEC-016` | `crates/guard-edge/src/security/tests.rs`, `scripts/integration-gate.sh` | [중복 Host·Content-Length·CL+TE raw VM 거부와 정상 HTTP/1.1 report](evidence/gnuboard5-standalone-security-20260722.md) |
| `SEC-017` | `tools/tests/test_vm_lab.py`, `tests/vm/gnuboard5-toolkit.json`, `configs/apache/waf-tuned-enforce.conf` | [ModSecurity·CRS detection/tuned enforce SQLi·XSS와 anonymous 정상 GET report](evidence/gnuboard5-standalone-security-20260722.md) |
| `NFR-001`, `NFR-002` | `crates/guard-edge/src/rate_limit/tests.rs`, `tests/vm/gnuboard5-toolkit.json` | [실제 2GB 정상·burst·AI bot 응답과 service memory peak·OOM report](evidence/gnuboard5-standalone-security-20260722.md) |
| `NFR-003` | process kill fault test | zero-error request counter |
| `NFR-004`, `NFR-006` | state crash/migration tests | kill -9 recovery artifact |
| `NFR-005` | `crates/guard-control/src/api/tests.rs`, error snapshot tests | UI·CLI problem·cause·impact·next action·event ID report |
| `NFR-007` | workspace lint 상속·module rustdoc gate·`cargo doc -D warnings` | CI rustdoc build artifact |
| `NFR-008` | dependency decision record + audit·deny·machete | 2GB VPS binary·RSS dependency diff |
| `NFR-009` | `tools/tests/test_runner.py`, `tools/tests/test_governance.py`, `tools/tests/test_policy.py`, `scripts/state-common.sh`, `scripts/harness-language-gate.sh` | Python 없는 운영 VPS에서도 Rust artifact 기반 apply·restore가 동작하는 2GB VM report |
| `NFR-010` | `tools/tests/test_build_artifacts.py`, `scripts/build-storage.sh`, 주요 build gate의 `--auto`, Cargo dev/test profile gate | 임시 산출물 자동 정리 전후 disk 사용량, 4GiB 경고·debug/release/coverage/rustdoc warm cache와 release bundle·검증 evidence 보존 report |
| `NFR-011` | `tools/tests/test_coverage.py`, `crates/guard-edge/src/response/tests.rs`, `crates/guard-edge/src/startup/tests.rs`, `crates/guard-control/src/provider/tests.rs`, `crates/guard-control/src/runtime/tests.rs`, `scripts/coverage-gate.sh` | versioned LCOV workspace·핵심 production file ratchet artifact |
| `NFR-012` | `tools/tests/test_dev_check.py`, `tools/vpsguard_harness/dev_check.py`, `scripts/dev-check.sh` | crate/Python/Web scoped check 실행 시간과 merge 전체 gate 결과 |
| `NFR-013` | `tools/tests/test_commit_contract.py`, `tools/vpsguard_harness/commit_contract.py`, `scripts/commit-contract-gate.sh`, `scripts/pr-contract-gate.sh` | GitHub PR·push event 전체 commit range gate log |
| `NFR-014` | `tools/tests/test_vm_lab.py`, `tools/vpsguard_harness/vm_lab.py`, `tools/vm/standalone-security-probe.sh` | [`gnuboard5` host-to-VM direct/guarded·standalone 보안 시나리오 report](evidence/gnuboard5-standalone-security-20260722.md) |

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
