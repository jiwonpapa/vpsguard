---
title: VPSGuard pre-MVP Status
status: active
doc_type: implementation-status
source_of_truth: true
spec_version: 1
last_reviewed: 2026-07-24
---

# pre-MVP 구현 현황

## 판정

현재 상태는 **pre-MVP 파일럿**입니다. 기본 Rust·Web 회귀뿐 아니라 `gnuboard5` VM의 Apache public 80/443 편입·rollback, 직접 HTTPS 관리자, standalone UFW, AI bot·과다 요청·request framing·WAF, 보호 정책 hot reload와 실제 2GB 실행 증거가 있습니다. PAM+TOTP는 자동 생성 test seed 증거를 폐기하고 실제 운영자 QR 등록 재검증을 기다립니다. Cloudflare test zone, 공식 crawler source와 authenticated upload WAF 오탐 증거도 남았습니다. 코드가 존재하는 항목을 완료로 간주하지 않으며 현재 단계는 [`verification-status.tsv`](verification-status.tsv)의 `PLANNED`, `CODE_ONLY`, `AUTO_PASS`, `VPS_PASS`로 판정합니다.

현재 요구사항 123개 중 `PLANNED` 9개, `CODE_ONLY` 28개, `AUTO_PASS` 69개, `VPS_PASS` 17개입니다. 즉 114개는 코드 또는 계약이 존재하며 자동 수용 기준까지 통과한 것은 86개입니다. `VPS_PASS`는 보존된 운영 증거 수준이며 요구사항 전체의 release 완료를 뜻하지 않습니다.

## 코드 및 자동 검증 현황

| 영역 | 구현 | 주요 증거 |
|---|---|---|
| `EDGE-003`, `EDGE-004`, `EDGE-006`, `EDGE-007` | streaming loopback proxy, trusted forwarded chain, 경로별 body·timeout, control 비의존 | `scripts/integration-gate.sh`, edge policy tests |
| `EDGE-010`~`EDGE-012` | 첫 origin 성공 전 ready 차단, live/ready 분리, query·header·body 비밀값 로그 제외, bounded limiter | edge unit·integration secret scan |
| `EDGE-013` | enforcement와 독립된 `profiled`·`protocol_only`, app·행동 판정 생략 시에도 HTTP/TLS·Host·forwarded header·body·timeout·bounded 계측 유지 | edge config/runtime unit test와 loopback HTTP/TLS integration; HTTP/2·WebSocket 실 VPS 증거는 별도 `EDGE-002`, `EDGE-005` gate |
| `OBS-014` | 주요 방어 전이와 provider 시작·완료·실패를 HTTPS webhook으로 비차단 전달, event ID dedupe·bounded retry·재시작 재개·상태 UI | notification·storage·API unit test와 Playwright 28개; 실제 외부 receiver·2GB VPS 증거는 미수집 |
| `EDGE-014`, `NFR-002` | client table 포화 시 IP·prefix·route·global aggregate fallback과 bounded memory | limiter unit·VM burst, 실제 2GB에서 정상 75 x 200·burst 515 x 429·service OOM 0; 다중 실제 source soak는 미완료 |
| `EDGE-015` | active request·downstream I/O timeout·최소 HTTP/1 전송률·keepalive 재사용 상한 | config/runtime unit과 loopback slow-origin 동시 요청 503; slow client·HTTP/2·2GB concurrent soak는 미완료 |
| `EDGE-008`, `EDGE-009` | policy hash·request-time TTL·version 검증, last-known-good 원자 hot reload와 5분 lease 갱신 | `policy_runtime`·control runtime tests |
| `OBS-001`, `OBS-008` | status·latency·bytes·upstream connection·client·route aggregate, SQLite WAL·retention, non-blocking datagram 재연결·손실 계측 | telemetry·storage·loopback integration tests |
| `OBS-003`~`OBS-006`, `OBS-011` | Linux `/proc/stat` delta CPU·logical core·load·memory·swap 서버값, allowlist systemd unit의 cgroup v2 CPU·memory·I/O·process/task, Nginx/Apache·PHP-FPM·MySQL/MariaDB·Redis semantic metric과 component별 timeout/error/stale 상태 | config·bounded parser·loopback transport·cgroup fixture, Control resource API와 Playwright; disk wait·network 및 실제 DB/Redis·2GB VPS 대조는 미완료 |
| `OBS-007` 자동 검증 | 설정 상한이 적용된 1초 live ring, 전용 blocking batch writer, SQLite WAL 상세·client IP·10초·1분 rollup, 계층별 bounded retention, DB/WAL·disk·drop health | telemetry·storage·API·UI 회귀 테스트; busy·disk-full fault와 2GB VPS 부하 증거는 미완료 |
| `DET-001`, `DET-005`, `DET-007`, `DET-010` | trust·bot·cost 분리, reason code, spike 히스테리시스, 결손 confidence | core detection·state tests |
| `DET-002`, `DET-011`, `DET-012` | 범용 PHP·GnuBoard 5·GnuBoard 7·WordPress route 분리, app 분류와 site override 합성, generic 보안 core와 G7 CSP·auth overlay 분리 | profile·edge runtime·security tests |
| `DET-013` | 공식 CIDR feed의 Google·Naver·Bing 판정, 위조 crawler와 미허용 declared AI bot 분리 | crawler/config/updater unit와 VM GPTBot·Meta·위조 Googlebot 403; 실제 공식 crawler source allow는 미완료 |
| `DET-014` | traffic latency·5xx와 실제 CPU·core-normalized load·memory·swap host pressure를 합성하고 `protocol_only + enforce` 자동 전이를 유지 | `/proc` fixture와 [격리 2GB VM의 100% CPU·API exact 대조, `NORMAL→WATCH→LOCAL_GUARD→RECOVERING→NORMAL`, 75/75 public 200·무순단·자동 원복](evidence/gnuboard5-host-pressure-20260724.md); provider가 없는 VM이라 실제 `EMERGENCY_PROXY`는 미완료 |
| `ACT-001`~`ACT-005` | client·route 제한, 429, signed clearance, 기능별 정책, TTL client rule | edge limiter·challenge·policy tests |
| `ACT-006`~`ACT-012` 코드 | User token preflight, 동일 hostname의 명시적 A·AAAA/CNAME record ID별 checkpoint·TTL snapshot·즉시 rollback, Cloudflare read-back·외부 `cf-ray`·DNS cache drain, dual-stack nftables 원자 교체·정확 read-back, 재시작 재개·idempotency | fake API/provider/system/control tests; 실제 test zone 변경 증거 없음 |
| `ACT-008` 자동 검증 | 안정 뒤 `RECOVERY_READY`에서 Cloudflare와 origin lock 유지, 관리자 인증·CSRF·재확인·idempotency 이후에만 snapshot 복구 | state·API·Playwright 회귀; 실제 test zone 승인 전후 read-back은 미완료 |
| `ACT-013`, `ACT-014` | standalone UFW, JW-agent delegated, disabled 소유권과 typed IP/CIDR·port rule transaction | 실제 VM UFW active, 외부 규칙 8개 보존, 임시 deny add/read-back/remove, SSH·관리 HTTPS 보존과 delegated mutation 거부 |
| `TLS-001` 일부 | 단일 certificate chain의 key·유효기간·SAN 검사 | TLS unit tests |
| `TLS-002` 하네스 | 갱신 PEM 원자 stage, 새 worker 사전검증, Pingora listener FD 인계, supervisor 보존과 기존 연결 drain | typed unit·packaging tests와 [격리 2GB VM의 동일 TLS socket in-flight 완료, 439/439 신규 handshake, leaf exact read-back](evidence/gnuboard5-tls-reload-20260724.md) |
| `TLS-005`, `TLS-006` 하네스 | startup cert/key·SAN·유효기간 preflight, 6시간 공개 cert·Certbot renewal/timer 관측, external/assisted/manual 소유권, systemd credential 경계와 승인 전 HTTP-01 plan | typed unit/API/UI/packaging tests; 실제 ACME staging 발급·Certbot renew·timer 증거는 미수집 |
| `TLS-004` 자동 검증 | 명시적 IP·port에 exact SNI handshake 후 파일과 실제 leaf SHA-256 비교, mismatch fail-closed Certbot hook | 일치·불일치 local TLS fixture와 CLI·packaging 계약, [격리 2GB VM의 stage leaf와 reload listener leaf exact 일치](evidence/gnuboard5-tls-reload-20260724.md); 실제 Certbot hook 경로는 미수집 |
| `UI-001`~`UI-004`, `UI-007`, `UI-009`, `UI-011`, `UI-013`, `UI-014` | 별도 HTTPS 관리 Host→loopback Control 분리, CSR SPA, 인증된 SSE·조회, client 검색·필터·정렬·페이지, 운영 명령 확인, light/dark, stale/error | local TLS integration·Bun·Playwright·control tests |
| `UI-016`~`UI-018` | trusted Apache TLS terminator의 직접 관리자, standalone/delegated 방화벽과 재시작 없는 단계별 보호정책 SPA | 실제 `:7443` PAM session·Control 비공개, typed UFW form/read-only delegation, 보호 설정 fingerprint·diff·stale/idempotency·hash sidecar·구버전 Edge schema 호환·원자 write·desktop/mobile Playwright와 [verified x86_64 bundle의 실제 2GB Edge version·설정 원복 read-back](evidence/gnuboard5-ui018-policy-20260724.md) |
| `OPS-002`~`OPS-008` 하네스 | typed plan, checksum·architecture shadow preflight, release-bound g7devops Nginx TLS 후보, ingress 실패 rollback, control+edge update health, bypass 선검증 uninstall, arch matrix·SBOM·command audit | update 성공·health 실패 exact rollback·owned-only uninstall 자동 fixture, x86_64/aarch64 native artifact 실행·SBOM·attestation과 [x86_64 격리 2GB VM 20회 update·restore](evidence/gnuboard5-release-endurance-20260724.md); 실제 uninstall은 미완료 |
| `OPS-009` | Rust `DeploymentRestoreDriver` 기반 first install·shadow 배포 전 checksum snapshot, legacy v1 호환, stdin root-only token 전달, 실패·수동 원상복귀와 protected directory identity·listener 경계 read-back | Rust fixture exact restore·corrupt snapshot·partial mutation 자동 rollback과 [`g7devops` 실패 자동 복구·수동 restore·재설치 운영 증거](evidence/g7devops-shadow-roundtrip-20260715.md); 사용자 site tree는 scan·복구하지 않음 |
| `OPS-010` | 단일 OS operation lock, plan hash, typed 단계 ledger·원자 rollback checkpoint 재개, deployment·direct ingress·edge/bypass 실제 driver, 5초 public 순단·60초 apply/update·30초 restore·10초 rollback 예산, 실패 자동 rollback | Rust engine·driver fault·process reconstruction·staged exact-file rollback tests, site tree 거부와 빠른 restore fixture; [격리 Ubuntu 2GB VM 20회·2,180개 100ms probe·최장 순단 1.842초](evidence/gnuboard5-release-endurance-20260724.md) |
| 회귀 차단 코드 | nextest, rustdoc, audit/deny/machete, 영역별 coverage ratchet, loopback integration, k6 부하, Bun unit, desktop/mobile Playwright를 merge gate로 연결 | GitHub branch protection 적용 전에는 강제되지 않음 |
| `SEC-003`, `SEC-006`, `SEC-007` | peer-credential local socket의 단회 code, client별 시도 제한·knockout 방지·재사용 거부, Host·Origin 고정, Secure·HttpOnly session, 인증된 읽기·SSE, CSRF·idempotency 변경 | admin socket·API auth tests, local TLS integration |
| `SEC-001`, `SEC-005` | root-only provider secret 원본, systemd credential 전달, memory redaction·임시 buffer zeroize, CSP, query·header·body 미저장 | provider secret·debug redaction, API auth·web tests |
| `SEC-008`~`SEC-011` | CONNECT·TRACE·TRACK 거부, origin version header 제거, baseline header·HTTPS HSTS·CSP report-only/enforce, G7 auth 전용 bounded client 한도와 XSS/SQLi origin 책임 경계 | config·profile·edge unit, loopback HTTP/TLS·secret scan과 관리 API·UI tests |
| `SEC-015`~`SEC-017` | Linux-PAM group+봉인 TOTP 최초 등록, raw request framing 거부, 선택형 ModSecurity·OWASP CRS mode | PAM은 자동 생성 test seed 증거를 폐기하고 실제 사용자 QR 등록 재검증 대기; duplicate Host/CL·CL+TE 400, SQLi·XSS 403와 anonymous GET 오탐 0; upload·HTTP/2·WebSocket VM replay는 미완료 |
| `NFR-003`, `NFR-004`, `NFR-006` 일부 | edge/control 분리, 원자 state, versioned strict schema | integration·atomic store tests |
| `NFR-007` | workspace `missing_docs = "deny"`, 모든 crate lint 상속, module `//!`, lint 우회 금지, private item 포함 rustdoc warning 거부 | docs gate·repository contract·CI rustdoc build |
| `NFR-008` 계약 | 표준 protocol·DB driver는 외부 crate/client를 우선하고 project 고유 bounded 불변조건만 직접 구현하는 선택 기준 | ADR 0002; crate별 적용과 2GB binary·RSS 비교는 미완료 |
| `NFR-009` | Python 표준 라이브러리 기반 argv runner·구조화 오류·redaction, Rust privileged deployment·public ingress transaction, 얇은 Shell wrapper와 line-count 비증가 ratchet | Python unit·language policy·docs·requirements·ops harness, Rust ingress exact restore·staged switch·fault rollback과 Shell 호환 fixture |
| `NFR-010` | dev/test incremental 비활성, dependency debug 정보 제거와 release/evidence 보존 정리 하네스 | Python profile·cleanup·symlink·hard-link 경계 unit와 전체 check; clean rebuild `target` 35.1GiB → 1.4GiB |
| 요청·오류 상관 추적 | 재시작 고유 request ID를 응답·upstream·detail 저장에 전파하고 request·operation·event 통합 조회와 API cause·event ID 제공 | 실제 VPS journal·Nginx upstream 상관 조회는 미검증 |
| 운영 로그 일부 | edge/control JSON stdout 로그를 systemd journal이 수집하고 공통 component·event/error code와 unit별 rate limit 적용 | host journald 보존 상태 UI는 미구현 |

## release gate 미완료

- `EDGE-001`, `EDGE-002`, `EDGE-005`: `g7devops` public 80/443, 인증서별 multi-SNI 선택, WebSocket 실제 VPS E2E
- `DET-014`: 2GB 로컬 압력·회복은 통과했으나 격리 Cloudflare test zone의 실제 `EMERGENCY_PROXY`·provider read-back·승인 복구가 남음
- `OBS-003`~`OBS-006`, `OBS-010`, `OBS-011`: semantic·cgroup 수집 코드는 구현됐으나 실제 MySQL/Redis 최소 권한 smoke, cgroup/systemd 값 대조, busy·disk-full 장애와 2GB VPS 정확도·route-resource 상관 검증이 남음
- `UI-001`: 실제 public 443 관리 Host의 인증서·접속·복구와 앱 origin 비혼선 VPS 증거
- `UI-005`, `UI-006`, `UI-008`, `UI-010`, `UI-012`: client 상세 score/action, 동일축 상관 그래프, TLS 실제 read-back, 용어집, read/export 세부 역할 분리
- `DET-012`, `SEC-009`, `SEC-010`: loopback 자동 증거는 통과했으나 실제 G7 정상 browser CSP violation, Reverb·외부 asset 호환과 shared IP 인증 오탐을 관찰하기 전에는 CSP enforce·강한 auth 한도를 기본 적용하지 않음. 계정·session 단위 방어는 계속 origin 책임
- `EDGE-014`, `DET-013`, `SEC-016`, `SEC-017`: 여러 실제 source high-cardinality, 실제 공식 crawler allow, HTTP/2·WebSocket framing과 authenticated 글쓰기·업로드 WAF 오탐 replay
- `ACT-006`~`ACT-010`: User token과 record ID·type preflight는 fake API까지 구현됐으며, Cloudflare test zone 전환·복구와 실제 kernel/SSH·non-web port diff 증거가 남음. Account API Token onboarding은 zone-scoped DNS Write 재현 전까지 제외
- `TLS-002`: 격리 2GB VM의 root-owned stage, Pingora FD handoff, supervisor 보존, 같은 TLS socket in-flight 완료와 439/439 신규 handshake는 `VPS_PASS`
- `TLS-003`~`TLS-006`: 기존 manager·timer 감지, 승인 전 plan과 served certificate exact 비교는 구현됐으며, plan hash 기반 apply, 실제 Certbot staging HTTP-01·systemd timer renew·deploy hook 전체 경로와 bypass 후 fingerprint 증거가 남음
- `OPS-006`: owned-only uninstall 자동 fixture는 통과했으나 실제 uninstall 증거가 남음. `OPS-005`, `OPS-010`의 격리 Ubuntu 2GB VM 20회 update·restore와 100ms 순단 timeline은 통과했습니다. `OPS-007` x86_64/aarch64 native artifact 실행·SBOM·attestation은 AUTO_PASS이며, public cutover·bypass와 `OPS-009` shadow 복구는 기존 VPS 증거가 있으나 현재 서버는 원본 Nginx topology로 복구됨
- 2GB `g7devops` 성능·장애·복구 파일럿

## 실행 범위

`gnuboard5` 격리 staging VM에는 standalone 파일럿을 배포해 Apache public 경로, 관리자 `:7443`, UFW와 tuned WAF가 active입니다. `g7devops`는 원본 `Nginx public 80/443 -> PHP-FPM` topology로 복구된 상태이며 이번 변경을 배포하지 않았습니다. 이후 `g7devops` apply는 별도 명시적 승인과 현재 격리 VM 증거 검토 뒤에만 수행합니다.
