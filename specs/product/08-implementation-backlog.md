---
title: VPS Guard Implementation Backlog
status: draft-implementation-ready
doc_type: execution-plan
source_of_truth: true
spec_version: 1
last_reviewed: 2026-07-15
---

# 구현 백로그

## 1. 구현 원칙

- 새 저장소에서 구현하며 `g7-installer`에 런타임 코드를 추가하지 않습니다.
- 기존 월척웹 Pingora 코드를 재사용하되 월척 전용 설정과 경로는 제거합니다.
- 한 배치마다 코드, rustdoc, 테스트, 문서와 migration을 함께 커밋합니다.
- 자동 차단보다 관찰 정확도와 복구 가능성을 먼저 완성합니다.
- 실제 public 80/443 전환은 shadow와 별도 TLS listener 검증 후 수행합니다.
- 각 단계의 exit gate가 실패하면 다음 단계로 진행하지 않습니다.

## 2. 제안 저장소 구조

```text
vps-guard/
  Cargo.toml
  DEVELOPMENT_CONSTITUTION.md
  specs/product/
  crates/
    guard-cli/
    guard-core/
    guard-edge/
    guard-control/
    guard-agent/
    guard-system/
    guard-provider/
    guard-profiles/
  web/
  scripts/
  tests/
    fixtures/
    integration/
    e2e/
    fault/
    load/
  packaging/
    systemd/
    tmpfiles/
```

### 크레이트 경계

| 크레이트 | 책임 |
|---|---|
| `guard-cli` | status, plan, cutover, bypass, report 명령과 출력 |
| `guard-core` | 점수, 상태 머신, 정책, 사건과 provider transaction domain |
| `guard-edge` | Pingora listener, request policy, proxy와 계측 |
| `guard-control` | SQLite, API, SSE, UI asset과 collector orchestration |
| `guard-agent` | OS·Nginx·PHP-FPM·MySQL·Redis collector library. MVP에서는 control 프로세스에 링크 |
| `guard-system` | nftables, systemd, cert, Nginx와 원자 파일 작업 |
| `guard-provider` | Cloudflare와 향후 VPS provider adapter |
| `guard-profiles` | GnuBoard·WordPress route와 비용 profile |

OS 명령과 provider API를 `guard-core`에 넣지 않습니다. `guard-edge`는 웹 UI와 SQLite에 의존하지 않습니다.

### 최근 완료 배치: 관리면·GnuBoard 보안 수직 슬라이스

- 요구사항: `DET-002`, `DET-011`, `UI-001`, `SEC-003`, `SEC-006`, `SEC-007`
- GnuBoard 5와 7을 별도 route inventory로 분리하고 기존 `gnuboard` 값은 G5 호환 alias로만 유지
- app profile 결과를 strict·upload 보호 계층에 연결하고 site prefix override가 우선하도록 합성
- 별도 관리 Host만 edge에서 loopback Control로 전달하며 앱 origin fallback을 금지
- peer credential을 확인한 local admin socket에서 짧은 단회 로그인 코드를 발급
- 로그인 코드는 session 발급에만 사용하고 읽기·SSE·변경은 session, 변경은 Origin·CSRF·idempotency로 보호
- passkey 등록과 역할 분리는 이 인증 경계가 검증된 뒤 별도 요구사항으로 추가

### 최근 완료 배치: Rust 문서화와 구현 현황 정직성

- 요구사항: `NFR-007`
- 모든 workspace crate가 중앙 `missing_docs = "deny"` lint를 상속하도록 강제
- 모든 Rust source 첫 줄의 `//!` module rustdoc를 검사
- `allow`, `warn`, `expect(missing_docs)` 우회와 crate별 lint 상속 누락을 거부
- 로컬 전체 check와 CI에서 `cargo doc --document-private-items` warning을 오류 처리
- 구현·자동 검증·실제 VPS 증거를 `PLANNED`, `CODE_ONLY`, `AUTO_PASS`, `VPS_PASS`로 분리 보고

### 최근 완료 배치: Cloudflare provider 비밀값·transaction 경계

- 요구사항: `ACT-006`~`ACT-010`, `SEC-001`, `SEC-004`, `NFR-008`
- User API Token active preflight와 exact zone·record ID·name·type read-back
- 동일 hostname A·AAAA 다중 변경과 부분 실패 즉시 rollback
- root-only 원본, systemd credential 전달, memory redaction과 fake API 검증
- 실제 test zone 전환·복구와 kernel/SSH·non-web port diff는 release gate로 유지

### 완료된 구현 배치: TLS 소유권·관측·승인 전 계획

- 요구사항: `TLS-001`, `TLS-002`, `TLS-006`, `SEC-001`
- `auto`, `external_managed`, `vpsguard_assisted`, `manual` typed ownership
- edge startup cert/key·SAN·유효기간 검증과 Control 6시간 공개 certificate·Certbot timer 관측
- private key는 edge systemd credential에만 전달하고 Control에는 공개 certificate만 전달
- 관리 UI의 HTTP-01 typed plan은 명시적 mode·Origin·CSRF를 요구하고 apply command를 포함하지 않음
- plan hash 기반 apply, staging 발급·renew·served certificate 비교는 다음 TLS batch

### 완료된 구현 배치: 로그·분석 저장 계층

- 요구사항: `OBS-002`, `OBS-007`, `SEC-005`, `NFR-003`
- [x] request별 SQLite write를 전용 blocking thread의 최대 256건 transaction batch로 교체
- [x] 설정 상한의 1초 live ring, 10초·1분 rollup과 detail·client IP·aggregate·incident·audit retention 분리
- [x] queue/write drop, DB/WAL·reclaimable page, retention 성공과 disk budget 관측·관리 UI 표시
- [x] request body·query·cookie·authorization 미저장 계약 유지
- [ ] SQLite busy·disk-full fault와 2GB VPS load 증거는 release gate에서 수집

### 완료된 구현 배치: 핵심 service cgroup·semantic 관측

- 요구사항: `OBS-004`, `OBS-005`, `OBS-006`, `OBS-011`
- [x] 전체 process 감사를 하지 않고 관리자가 확정한 최대 16개 systemd unit allowlist만 수집
- [x] cgroup v2 CPU·memory·I/O·process/task와 Nginx/Apache·PHP-FPM·MySQL/MariaDB·Redis semantic metric을 분리 표시
- [x] collector timeout·stale·권한 부족을 정상값처럼 표시하지 않는 API·UI·fixture gate
- [ ] 실제 MySQL·Redis 최소 권한 smoke와 2GB VPS cgroup 값 대조는 release gate에서 수집

### 완료된 구현 배치: protocol-only 통과 계층

- 요구사항: `EDGE-013`
- [x] `profiled`와 별도인 typed `protocol_only` inspection mode
- [x] app profile·동적 행동 판정은 생략하되 TLS·Host·forwarded header·body·timeout·연결 상한과 bounded 계측 유지
- [x] 관리 API·UI에 활성 inspection mode 노출
- [x] 지원하지 않는 non-web port는 가로채지 않고, 소유한 HTTP listener의 비HTTP 입력은 명시적으로 거부하는 loopback E2E

### 완료된 구현 배치: 범용·G7 애플리케이션 보안 계층

- 요구사항: `DET-012`, `SEC-008`~`SEC-011`
- [x] generic core, G7 overlay, CSP 관찰·강제와 origin 책임 경계를 요구사항으로 정의
- [x] 위험 method 거부, typed response header와 origin version header 제거
- [x] profile auth 경로의 bounded client별 시도 한도와 G7 교차 profile 회귀
- [x] query·header·body 비밀값 log scan, 관리 status·UI 보안 posture 표시
- [ ] 실제 G7 정상 browser CSP violation·shared IP auth 오탐 관찰 뒤 enforce 여부 결정

### 현재 배치: g7devops 배포·원상복귀 하네스

- 요구사항: `OPS-001`, `OPS-002`, `OPS-005`, `OPS-008`, `OPS-009`, `SEC-001`, `TLS-005`, `ACT-010`
- [x] Ubuntu 24.04·x86_64·2GB·G7 root·Nginx origin을 변경 없이 확인하는 target preflight
- [x] first install 전 binary·unit·drop-in·config·service 상태와 기존/부재 경계를 checksum snapshot으로 보존
- [x] 실패 또는 명시적 요청에서 snapshot만으로 배포 소유 상태를 복구하고 protected SSH·Nginx·인증서·사이트 경계 read-back
- [x] release bundle 설치 경로와 ownership manifest의 정확 일치, 예제 drop-in의 운영 경로 설치 금지
- [x] Cloudflare token을 bundle·argv·log·evidence에 넣지 않고 stdin에서 root-only 파일로 전달
- [x] shadow apply는 public 80/443·Nginx·Cloudflare를 변경하지 않고 loopback health 뒤에만 완료 처리
- [x] 실제 `g7devops` 실패 자동 복구·apply·수동 restore·동일 release 재설치와 snapshot 운영 증거

### 현재 배치: g7devops 실제 요청 경로 편입

- 요구사항: `EDGE-003`, `EDGE-004`, `EDGE-005`, `OPS-002`, `OPS-003`, `OPS-004`, `TLS-005`, `ACT-010`
- [x] 기존 Nginx가 public TLS·ACME를 유지하고 VPSGuard 뒤의 loopback Nginx가 기존 PHP-FPM·Reverb 경로를 보존하는 후보
- [x] Nginx가 덮어쓴 실제 client IP만 trusted loopback edge에 전달하고 외부 forwarded header를 신뢰하지 않는 설정
- [x] release checksum에 config·Nginx·remote transaction 후보를 포함하고 설치 binary·commit과 일치할 때만 apply
- [x] probe 실패 시 active Nginx·VPSGuard config·edge 기동 상태를 복구하는 격리 fixture
- [ ] 실제 `g7devops` edge -> Nginx bypass -> edge 왕복과 HTTPS·G7·WebSocket smoke

## 3. 배치 0: 저장소와 헌법

### 구현

- 새 repository 생성
- 이 아이디어 북을 `specs/product/`로 이동
- Rust 2024 workspace와 pinned toolchain
- `deny.toml`, audit, rustdoc, coverage와 CODEOWNERS
- module rustdoc 필수 gate
- dependency 선택 기록과 audit·deny·machete, binary·RSS diff gate
- x86_64·aarch64 CI skeleton
- Bun lockfile과 React·TypeScript·Tailwind CLI·shadcn/ui source component build skeleton

### 커밋

```text
docs: establish VPS Guard product SDD and development constitution
chore: scaffold Rust workspace and quality gates
```

### Exit gate

- 빈 workspace에서 전체 quality gate 통과
- requirement ID를 PR template에서 요구
- 문서 link와 schema lint 통과

## 4. 배치 1: 기존 Pingora 소스 추출

### 입력

```bash
git show 87c0f0e61^:crates/edge_proxy/src/main.rs
git show 87c0f0e61^:crates/common/src/config/model/edge_proxy_config.rs
```

관련 기존 테스트, staging 설정과 systemd 문서도 함께 검토합니다.

### 구현

- 단일 upstream proxy 추출
- 월척 domain, route와 `irongate` 명칭 제거
- config model 분리
- Host, trusted proxy, forwarded header, request ID
- IP·CIDR, body, timeout과 rate limit 기존 테스트 복구
- `profiled`·`protocol_only` typed inspection mode와 protocol별 E2E
- Pingora 의존성·license inventory

### 커밋

```text
feat(edge): recover and generalize the Pingora edge proxy
test(edge): restore proxy policy regression coverage
```

### Exit gate

- HTTP loopback E2E
- 기존 기능별 회귀 테스트
- control과 DB 의존 없음
- 월척 고유 문자열과 운영 secret 없음

## 5. 배치 2: 설정·상태·정책 계약

### 구현

- versioned TOML parser와 unknown-key rejection
- `state.json`, `policy.json`, event schema
- atomic file store
- policy hash, expiry와 last-known-good
- Unix control·telemetry socket
- error contract

### 커밋

```text
feat(core): add versioned config state and policy contracts
feat(edge): apply validated policy snapshots without hot-path RPC
```

### Exit gate

- crash·future schema·corrupt hash 테스트
- control 종료 중 proxy 요청 성공
- 잘못된 정책에서 이전 정상 정책 유지

## 6. 배치 3: 계측 데이터 플레인

### 구현

- RPS, connection, status, bytes와 latency histogram
- normalized route class
- bounded client·route cardinality
- 1초 aggregate와 non-blocking telemetry
- telemetry drop·stale 계측
- 민감 path/query/header 마스킹

### 커밋

```text
feat(edge): emit bounded request and client telemetry
test(edge): enforce telemetry backpressure and privacy contracts
```

### Exit gate

- high-cardinality memory soak
- control socket full 상태에서 요청 오류 0건
- k6 원본 요청 수와 aggregate 오차 허용 기준 충족

## 7. 배치 4: Control 저장·API

### 구현

- SQLite WAL schema와 migration
- live ring buffer와 downsampling
- 전용 blocking writer의 SQLite batch transaction과 queue drop 계측
- detail·client IP·10초·1분·incident·audit 계층별 retention과 disk budget
- status, traffic, clients, routes, incidents API
- SSE event stream과 event gap 복구
- retention과 IP 보존기간
- peer credential 기반 one-time login code, session, Origin과 CSRF
- 별도 HTTPS 관리 Host와 loopback Control 분리

### 커밋

```text
feat(control): persist aggregates incidents and versioned API
feat(control): secure loopback sessions and SSE event delivery
```

### Exit gate

- 10,000 client fixture API 성능
- SQLite busy·disk full 장애 주입
- API secret scan과 authorization matrix

## 8. 배치 5: 독립 웹 UI

### 구현

- program-style app shell
- 개요와 상태 근거
- 실시간 트래픽 그래프
- 외부 IP 목록·상세
- route·resource 상관 화면
- 사건 타임라인
- 정책·설정 read-only 화면
- light/dark, 한국어와 도움말
- loading, stale, disconnected와 error state

### 커밋

```text
feat(web): add the real-time VPS Guard operations console
test(web): cover status fixtures permissions and visual states
```

### Exit gate

- [모니터링 웹 UI](09-monitoring-web-ui.md)의 수용 기준 통과
- 10,000 client fixture에서 조작 중단 없음
- desktop/mobile, light/dark screenshot 회귀
- UI 종료와 무관하게 guard 동작 지속

## 9. 배치 6: 서버 resource collector

### 구현

- OS `/proc`와 network collector
- Nginx status
- PHP-FPM status
- MySQL 최소 권한 collector
- Redis collector
- 관리자 확정 핵심 service allowlist와 systemd unit inventory
- cgroup v2 CPU·memory·I/O·process 집계
- collector health·timeout·stale
- route spike와 resource pressure 상관관계
- HTTP transport는 `reqwest`, Redis와 MySQL은 검증된 protocol crate, unit discovery는 `zbus` spike를 우선

### 커밋

```text
feat(agent): collect bounded OS web PHP database and Redis signals
feat(core): correlate request cost with server pressure
```

### Exit gate

- collector on/off/error fixture
- 2GB VPS 실제값 대조
- collector timeout이 edge 요청에 영향 없음

## 10. 배치 7: 탐지 엔진과 profile

### 구현

- trust, bot likelihood와 resource cost
- reason code와 설명 생성
- GnuBoard 5·7 route profile과 기존 G5 alias 호환
- 정적 안전 한도·app profile·site override·incident policy 합성
- WordPress route profile은 GnuBoard 검증 후 추가
- baseline window와 fixed safety threshold
- verified crawler adapter와 spoof 방지
- TTL rule과 shared IP 보호

### 커밋

```text
feat(core): add explainable bot and resource-cost scoring
feat(profiles): add the verified GnuBoard traffic profile
```

### Exit gate

- 정상 browser, NAT, crawler와 scraper replay
- 모든 판정 reason code 존재
- 단일 spike 비상 전환 없음
- 누락 collector에서 confidence 하향

## 11. 배치 8: 로컬 대응

### 구현

- route·client rate limit
- 429·Retry-After
- signed clearance와 local challenge
- 기능별 보호 mode
- nftables 전용 table·chain·TTL set
- manual hold와 action idempotency
- UI 명령·권한·확인 modal

### 커밋

```text
feat(guard): enforce temporary local protection policies
feat(web): add reviewed local response controls
```

### Exit gate

- 정상 fixture hard block 0건
- 고비용 scraper upstream 감소 90% 이상
- SSH rule diff 0건
- action 중복 실행 없음

## 12. 배치 9: 직접 TLS와 ingress 전환

### 구현

- SNI와 cert/key 사전 검사
- 기존 외부 manager·Certbot timer·renewal hook의 읽기 전용 감지와 ownership 상태
- 자동 갱신이 없을 때만 기존 인증서 등록과 Certbot HTTP-01 신규 발급 plan·승인·apply
- Certbot systemd timer와 renew deploy hook
- shadow listener와 direct 80/443 plan
- Nginx loopback 후보 설정
- cutover transaction과 smoke
- served certificate 비교

### 커밋

```text
feat(tls): terminate public TLS with validated certificate reloads
feat(ops): add shadow-to-public ingress cutover transactions
```

### Exit gate

- GnuBoard browse, search, login, upload와 WebSocket
- cert issuance·renew·reload
- HTTP/1.1·HTTP/2
- 직접 Nginx 대비 성능 예산 통과

## 13. 배치 10: Bypass·업데이트·제거

### 구현

- edge -> Nginx public bypass
- Nginx -> edge 복귀
- systemd watchdog와 restart policy
- update backup·rollback
- ownership manifest와 uninstall
- 인증서·사이트·원본 설정 보존

### 커밋

```text
feat(ops): add reversible edge bypass and update rollback
test(ops): prove certificate and origin preservation
```

### Exit gate

- 실제 VPS bypass round trip
- 각 단계 장애 주입과 rollback
- uninstall 후 기존 사이트 HTTPS 정상

## 14. 배치 11: Cloudflare 비상 전환

### 구현

- 최소 권한 token 검사
- User API Token의 단일 zone `DNS Edit` 검사와 설정 문서
- User API Token verify endpoint preflight
- Account API Token은 dashboard 또는 API로 zone-scoped `DNS Write`를 재현하고 대상 계정에서 검증하기 전 onboarding 제외
- 명시적 record ID·type·name allowlist와 다중 A/AAAA/CNAME 처리
- root-only token 원본을 unprivileged control에 전달하는 systemd credential drop-in
- DNS snapshot·proxied request·read-back
- 외부 HTTPS 프록시 경유 probe
- origin 보호 transaction
- 부분 실패와 resume
- 안정 구간·DNS only 복구
- UI 진행률과 실제 상태

### 커밋

```text
feat(provider): add transactional Cloudflare emergency protection
feat(web): report provider progress failures and recovery
```

### Exit gate

- test zone 실제 전환·복구
- 401·403·429·5xx·timeout 장애 주입
- proxy verify 전 origin lock 0건
- SSH rule 변경 0건
- 새로고침 후 transaction 진행 상태 복원

## 15. 배치 12: 파일럿과 릴리스

### 구현

- observe-only 기본 설치
- GnuBoard 2GB VPS 파일럿
- bot replay와 k6 workload
- 사건·절감 리포트
- x86_64·aarch64 build
- checksum, SBOM와 provenance
- bootstrap과 signed update manifest
- 설치·운영·복구 초보 문서

### 커밋

```text
test(ops): certify the 2GB GnuBoard VPS pilot harness
chore(release): publish multi-architecture verified artifacts
```

### Exit gate

- [검증 추적표](07-verification-traceability.md) 전체 필수 증거
- 공개 지원 환경과 제한 명시
- 자동 차단은 관찰 기간과 관리자 opt-in 후에만 활성
- release artifact 재현성과 설치 smoke

## 16. 초기 공개에서 보류

- 자체 ACME 구현
- HTTP/3
- Pingora cache
- 머신러닝 모델
- 다중 서버 중앙 SaaS
- 모든 VPS provider 방화벽 API
- 범용 Apache 공개 지원
- packet capture와 SIEM
- 모바일에서 정책 전체 편집

보류 기능은 핵심 안전성과 파일럿 증거를 통과한 뒤 별도 ADR로 검토합니다.

## 17. 시작 전 결정 체크리스트

새 저장소 첫 커밋 전에 다음을 기록합니다.

- [x] 제품·binary·systemd service 작업명
- [x] 저장소 공개 여부
- [ ] 라이선스와 유료 기능 경계
- [x] 기존 월척 소스 기준 commit과 저작권
- [x] Nginx-only 초기 공개 범위
- [x] UI 기본 port
- [x] raw IP 기본 보존기간
- [ ] 첫 Cloudflare test zone
- [x] 첫 2GB VPS 파일럿 환경

이 결정 중 라이선스와 소스 기준 commit은 코드 복사 전에 반드시 완료합니다.

확정값과 남은 보류 항목은 [초기 구현 결정](10-bootstrap-decisions.md)을 따릅니다.
