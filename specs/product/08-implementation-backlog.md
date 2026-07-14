---
title: VPS Guard Implementation Backlog
status: draft-implementation-ready
doc_type: execution-plan
source_of_truth: true
spec_version: 1
last_reviewed: 2026-07-14
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

## 3. 배치 0: 저장소와 헌법

### 구현

- 새 repository 생성
- 이 아이디어 북을 `specs/product/`로 이동
- Rust 2024 workspace와 pinned toolchain
- `deny.toml`, audit, rustdoc, coverage와 CODEOWNERS
- module rustdoc 필수 gate
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
- status, traffic, clients, routes, incidents API
- SSE event stream과 event gap 복구
- retention과 IP 보존기간
- one-time bootstrap token, session과 CSRF

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
- collector health·timeout·stale
- route spike와 resource pressure 상관관계

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
- GnuBoard route profile
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
- Certbot HTTP-01와 renew hook
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
- zone·record allowlist
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
