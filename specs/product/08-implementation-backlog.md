---
title: VPS Guard Implementation Backlog
status: draft-implementation-ready
doc_type: execution-plan
source_of_truth: true
spec_version: 1
last_reviewed: 2026-07-24
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

### 현재 배치: 재시작 없는 관리자 보호 정책

- 요구사항: `UI-018`, `ACT-001`, `ACT-004`, `NFR-004`
- [x] WATCH·LOCAL_GUARD·EMERGENCY_PROXY strict/upload 제한의 typed model과 단계 관계 검증
- [x] 기존 policy와 hash settings sidecar에서 설정·version 복원, 구버전 Edge schema 호환과 writer 단일화
- [x] fingerprint 기반 plan·diff·stale plan 거부·idempotent apply
- [x] 원자 policy write·read-back 뒤 Edge telemetry 관측 version 분리
- [x] 관리자 정책 화면과 desktop/mobile Playwright
- [x] verified bundle update·2GB balloon·break-glass policy probe·deployment/memory 자동 원복 Python 하네스
- [x] built-in virtio balloon binding 감지·60초 bounded read-back·사전 module 상태 원복
- [x] 실제 실패에서 발견한 deployment restore parent mode 변경 회귀 차단
- [x] 격리 2GB Ubuntu VM의 정상·strict·upload 적용 전후 Edge version·설정 원복 read-back 증거

### 현재 배치: multi-architecture release 실행 검증

- 요구사항: `OPS-007`, `NFR-008`
- [x] CLI·Control·privileged helper·Edge의 공통 package version 실행 경로
- [x] x86_64·aarch64 Linux checksum·ELF architecture 사전 검증
- [x] x86_64·aarch64 Ubuntu 24.04 native runner와 PAM·Clang build dependency 명시
- [x] target별 native Ubuntu container에서 bundle의 네 binary 직접 실행
- [x] bundle에 포함된 실제 example config를 packaged CLI로 검증
- [x] 실행 smoke 성공 뒤에만 provenance attestation과 artifact upload
- [x] native runner matrix와 workflow 순서 회귀
- [x] GitHub workflow_dispatch에서 두 matrix job의 artifact·SBOM·attestation 증거 수집

### 최근 완료 배치: update 자동 원복·owned-only uninstall 회귀

- 요구사항: `OPS-005`, `OPS-006`, `OPS-009`, `NFR-009`
- [x] 실제 release script와 Rust deployment snapshot/restore CLI를 같은 fixture에서 실행
- [x] 후보 stage·unit 교체·control/edge health 성공과 versioned symlink read-back
- [x] edge health 실패 뒤 binary·unit·service state exact rollback과 실패 release 제거
- [x] control·edge health 재시도 전체를 각각 15초로 제한하고 guest command 종료 grace 강제
- [x] 구버전 Control이 앞선 policy version만 쓴 상태는 route 설정 일치 때만 metadata 복구
- [x] uninstall 전후 Nginx public probe와 ownership manifest allowlist만 제거
- [x] config·runtime state·SSH·Nginx·certificate·site sentinel 보존
- [x] 시험 root는 별도 확인 문자열·절대 non-root 경로에서만 허용
- [x] Shell line-count ratchet을 늘리지 않고 Python 표준 라이브러리 하네스로 전체 gate 편입
- [x] 격리 Ubuntu 24.04 2GB에서 실제 systemd·Apache·검증 bundle로 update·restore 20회와 owned-only uninstall·exact restore 증거 수집

### 현재 배치: TLS served certificate read-back

- 요구사항: `TLS-001`, `TLS-002`, `TLS-004`
- [x] 설정 certificate·private key·exact SNI·유효기간 사전 검증
- [x] DNS·CDN과 분리된 명시적 IP·port TLS handshake로 실제 leaf 수집
- [x] 파일과 listener leaf의 SHA-256 exact 비교와 mismatch non-zero 종료
- [x] Certbot deploy hook이 edge health 뒤 served certificate 일치까지 성공 조건으로 강제
- [x] 일치·불일치 local TLS fixture와 packaging env 계약 자동 회귀
- [x] root·service group 전용 `/run/vps-guard-tls`에 갱신 PEM 검증·원자 stage
- [x] 새 worker 사전검증 뒤 Pingora listener FD 인계와 30초 기존 연결 drain
- [x] systemd main supervisor 유지, 중복 reload 거부와 기존 worker 보존
- [x] deploy hook의 service restart 제거와 graceful reload·served fingerprint 강제
- [x] 격리 Ubuntu 24.04 2GB에서 합성 갱신 PEM stage, FD 인계, 같은 TLS socket in-flight 완료와 신규 handshake `439/439` 증거 수집
- [ ] 실제 ACME staging renewal·Certbot hook·timer와 listener fingerprint timeline 수집

### 최근 완료 배치: host 자원 압력 기반 보호 전이

- 요구사항: `DET-014`, `DET-007`, `DET-010`, `OBS-003`
- [x] `/proc/stat` 누적 counter delta 기반 CPU 사용률과 logical core 수 수집
- [x] CPU·core-normalized load·memory·swap을 bounded host pressure로 합성
- [x] traffic latency·5xx와 host pressure를 resource cost에 반영하고 reason code 노출
- [x] 단일 window WATCH, 연속 5개 window 비상 승격과 collector 결손 confidence 회귀
- [x] `protocol_only + enforce`에서도 자동 local/provider 제어 유지
- [x] 관리자 Overview·Resource 화면에 host CPU와 core-normalized load 표시
- [x] private 2GB guest·고정 CPU worker·`/proc`/API·상태 전이·1초 public probe를 강제하는 pressure 하네스
- [x] 실제 2GB VPS에서 `/proc` 대조, 100% CPU 부하와 `NORMAL→WATCH→LOCAL_GUARD→RECOVERING→NORMAL` timeline·무순단·원복 수집
- [ ] 격리 Cloudflare test zone에서 `EMERGENCY_PROXY`·provider read-back·관리자 승인 복구 timeline 수집

### 최근 완료 배치: 클라이언트 상세 판정 drill-down

- 요구사항: `UI-005`, `SEC-005`
- [x] 인증 session에서만 exact IPv4·IPv6 상세 조회 허용
- [x] 상세 retention에 남은 요청·bytes·5xx·최대 경로 비용 점수·마지막 실제 조치를 bounded 조회
- [x] 정규화 route별 요청·오류·비용·throttle/challenge/deny 분해를 최대 32개로 제한
- [x] 원본 path·query·header·body와 수집하지 않은 trust score를 생성·노출하지 않음
- [x] 목록→상세 desktop·mobile Playwright와 storage·API 회귀 통과

### 최근 완료 배치: route·서버 압력 동일 시간축

- 요구사항: `UI-006`, `OBS-007`, `OBS-010`, `OBS-011`
- [x] OS와 최대 16개 allowlist service 최신 표본을 1분 bucket으로 upsert
- [x] 최대 24시간·1,440점과 상위 정규화 route 5개로 조회 상한 고정
- [x] 원본 path·query·header·body와 unrelated process를 저장하지 않음
- [x] route 요청·OS CPU·memory·service CPU·semantic pressure를 같은 epoch 축에 표시
- [x] storage·인증 API와 desktop/mobile Playwright 회귀 통과
- [ ] 사건 상세의 발생 시간창 자동 선택과 운영 incident snapshot 증거

### 최근 완료 배치: 인프라 실제 상태 통합 read-back

- 요구사항: `UI-008`, `ACT-008`, `ACT-013`, `TLS-006`
- [x] Cloudflare transaction stage와 drain deadline 표시
- [x] UFW ownership·backend·active snapshot·rule 보존 수·fingerprint 표시
- [x] TLS ownership·manager·renewal·인증서 수·최초 만료 표시
- [x] 설정 의도와 실제 read-back을 구분하고 방화벽 API 단독 실패에도 Overview 유지
- [x] desktop/mobile 정상·부분 실패 Playwright 회귀 통과

### 최근 완료 배치: Cloudflare 비대칭 복구 정책

- 요구사항: `ACT-006`~`ACT-009`, `UI-008`
- [x] DNS-only record의 TTL을 rollback snapshot에 보존하고 Auto TTL을 300초로 정규화
- [x] 설정 TTL 상한 초과 시 proxy 변경 전 fail-closed
- [x] `cf-ray`와 API read-back 뒤에도 drain deadline 전 origin lock 금지
- [x] drain stage·deadline을 원자 저장하고 Control 재시작 뒤 자동 재개
- [x] `EMERGENCY_PROXY` 안정 구간 뒤 외부 보호를 유지하는 `RECOVERY_READY` 전이
- [x] 추가 안정 window가 지나도 자동 DNS only·origin unlock 금지
- [x] 새 위험 신호가 오면 즉시 `EMERGENCY_PROXY`로 복귀
- [x] 인증·CSRF·재확인·idempotency를 거친 관리자 action만 snapshot 복구
- [x] 복구 승인 대기 상태와 Cloudflare 보호 해제 영향을 관리자 UI에 표시
- [ ] 실제 test zone에서 승인 전 DNS·origin lock 불변과 승인 후 read-back 증거

### 최근 완료 배치: 관리면·GnuBoard 보안 수직 슬라이스

- 요구사항: `DET-002`, `DET-011`, `UI-001`, `SEC-003`, `SEC-006`, `SEC-007`
- GnuBoard 5와 7을 별도 route inventory로 분리하고 기존 `gnuboard` 값은 G5 호환 alias로만 유지
- app profile 결과를 strict·upload 보호 계층에 연결하고 site prefix override가 우선하도록 합성
- 별도 관리 Host만 edge에서 loopback Control로 전달하며 앱 origin fallback을 금지
- peer credential을 확인한 local admin socket에서 짧은 단회 로그인 코드를 발급
- 로그인 코드는 session 발급에만 사용하고 읽기·SSE·변경은 session, 변경은 Origin·CSRF·idempotency로 보호
- passkey 등록과 역할 분리는 이 인증 경계가 검증된 뒤 별도 요구사항으로 추가

### 완료된 구현 배치: 전용 관리자 계정과 2단계 인증

- 요구사항: `UI-015`, `SEC-012`, `SEC-013`, `SEC-014`
- [x] Linux·SSH와 분리된 VPSGuard 관리자 ID와 Argon2id password verifier
- [x] 단회 local bootstrap으로 시작하는 최초 계정·TOTP 등록
- [x] 비밀번호 유래 key로 봉인한 TOTP seed와 hash-only 일회용 복구 코드
- [x] 원문 cookie·CSRF를 저장하지 않는 bounded SQLite session과 재시작 복원
- [x] 계정·TOTP, 복구 코드, break-glass 로그인과 명시적 로그아웃·전체 폐기 UI/API
- [x] login rate limit, 일반화된 인증 실패 오류, session actor·인증 방식 기록
- [ ] 2GB VPS에서 재시작 복원·RSS·인증 DB secret scan과 실제 TOTP browser 증거 수집

### 완료된 구현 배치: shadcn 관리 콘솔 디자인 체계

- 요구사항: `UI-011`, `UI-015`
- [x] shadcn CLI의 Vite·Tailwind CSS v4·Radix Nova 설정과 소스 소유형 `components.json`
- [x] Button·Badge·Input·Label·Select·Checkbox·Dialog·AlertDialog·Tooltip·Alert·Skeleton 공통 컴포넌트
- [x] Geist 타이포그래피, 주황색 단일 primary, light/dark semantic token과 reduced-motion 계약
- [x] 비로그인 상태에서 보호 화면과 SSE를 열지 않는 관리자 인증 게이트
- [x] desktop/mobile Playwright의 로그인 게이트와 shadcn `data-slot` 회귀
- [x] 모니터링·운영 메뉴 그룹, mobile drawer와 상시 우측 설명 패널을 제거한 반응형 app shell
- [x] 현재 보호·실시간 트래픽·서버 압력·TLS를 우선순위대로 분리한 overview와 공통 `ConsoleSection`·지표 체계
- [x] client·route·incident·resource·UFW 화면의 검색·상태·목록·위험 작업 section 표준화
- [x] 비로그인 gate와 인증 후 overview의 desktop/mobile, light/dark Playwright screenshot diff

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
- [x] process lifetime 오표기를 제거한 live window·10초 평균 RPS·현재 처리 중 요청 표시
- [x] declared bot class·provider 검증·UA family의 bounded 1분 aggregate와 관리 UI
- [x] retention 10초 drain, 삭제·IP 비식별화·backlog 분리 계측
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
- [x] app profile·app 전용 행동 판정은 생략하되 공통 다계층 rate limit·명시적 정책과 TLS·Host·forwarded header·body·timeout·연결 상한·bounded 계측 유지
- [x] 관리 API·UI에 활성 inspection mode 노출
- [x] 지원하지 않는 non-web port는 가로채지 않고, 소유한 HTTP listener의 비HTTP 입력은 명시적으로 거부하는 loopback E2E

### 완료된 구현 배치: 범용·G7 애플리케이션 보안 계층

- 요구사항: `DET-012`, `SEC-008`~`SEC-011`
- [x] generic core, G7 overlay, CSP 관찰·강제와 origin 책임 경계를 요구사항으로 정의
- [x] 위험 method 거부, typed response header와 origin version header 제거
- [x] profile auth 경로의 bounded client별 시도 한도와 G7 교차 profile 회귀
- [x] query·header·body 비밀값 log scan, 관리 status·UI 보안 posture 표시
- [ ] 실제 G7 정상 browser CSP violation·shared IP auth 오탐 관찰 뒤 enforce 여부 결정

### 완료된 구현 배치: 2GB edge 자원 경계

- 요구사항: `EDGE-015`, `NFR-002`
- [x] typed active-request·downstream I/O timeout·최소 HTTP/1 전송률·keepalive 요청 상한과 범위 검증
- [x] Pingora transport 기능을 사용하고 별도 응답 buffering·자체 전송률 구현 배제
- [x] 상한 초과 app 요청을 origin 전에 503·Retry-After로 거부하는 loopback 동시 요청 E2E
- [ ] slow-header·slow-body·HTTP/2 slow-reader와 2GB concurrent soak 운영 증거

### 현재 배치: g7devops 배포·원상복귀 하네스

- 요구사항: `OPS-001`, `OPS-002`, `OPS-005`, `OPS-008`, `OPS-009`, `OPS-010`, `SEC-001`, `TLS-005`, `ACT-010`
- [x] Ubuntu 24.04·x86_64·2GB·G7 root·Nginx origin을 변경 없이 확인하는 target preflight
- [x] first install 전 binary·unit·drop-in·config·service 상태와 기존/부재 경계를 checksum snapshot으로 보존
- [x] 실패 또는 명시적 요청에서 snapshot만으로 배포 소유 상태를 복구하고 protected SSH·Nginx·인증서·사이트 경계 read-back
- [x] release bundle 설치 경로와 ownership manifest의 정확 일치, 예제 drop-in의 운영 경로 설치 금지
- [x] Cloudflare token을 bundle·argv·log·evidence에 넣지 않고 stdin에서 root-only 파일로 전달
- [x] shadow apply는 public 80/443·Nginx·Cloudflare를 변경하지 않고 loopback health 뒤에만 완료 처리
- [x] 실제 `g7devops` 실패 자동 복구·apply·수동 restore·동일 release 재설치와 snapshot 운영 증거
- [x] 사이트 전체 tree hash를 제거하고 변경 경로만 담는 versioned transaction manifest로 교체
- [x] 단일 operation lock, typed 단계·duration·timeout과 실패 단계 자동 rollback을 Rust 운영 엔진으로 강제
- [x] snapshot restore가 payload mode·uid·gid를 유지하면서 기존 destination parent mode를 변경하지 않는 회귀
- [x] preflight 무순단 60초, public 순단 5초, update 60초, rollback 10초, first-install restore 30초 hard limit fault gate
- [x] private guest·exact Host·20회·100ms·5초 outage budget을 강제하는 release endurance 하네스와 continuous body-free probe
- [x] 격리 Ubuntu 24.04 VM 20회 왕복과 100ms public probe timeline 수집

### 현재 배치: g7devops 실제 요청 경로 편입

- 요구사항: `EDGE-003`, `EDGE-004`, `EDGE-005`, `OPS-002`, `OPS-003`, `OPS-004`, `TLS-005`, `ACT-010`
- [x] 기존 Nginx가 public TLS·ACME를 유지하고 VPSGuard 뒤의 loopback Nginx가 기존 PHP-FPM·Reverb 경로를 보존하는 후보
- [x] Nginx가 덮어쓴 실제 client IP만 trusted loopback edge에 전달하고 외부 forwarded header를 신뢰하지 않는 설정
- [x] release checksum에 config·Nginx·remote transaction 후보를 포함하고 설치 binary·commit과 일치할 때만 apply
- [x] probe 실패 시 active Nginx·VPSGuard config·edge 기동 상태를 복구하는 격리 fixture
- [ ] 실제 `g7devops` edge -> Nginx bypass -> edge 왕복과 HTTPS·G7·WebSocket smoke

### 현재 배치: gnuboard5 Apache VM 파일럿과 공격 회귀 하네스

- 요구사항: `OPS-011`, `NFR-014`, `DET-003`, `DET-004`, `DET-009`, `EDGE-012`, `SEC-008`~`SEC-010`, `NFR-001`~`NFR-003`
- [x] VM baseline snapshot과 기존 Apache TLS·사이트·SSH·비-web listener read-back
- [x] Apache public TLS -> VPSGuard loopback -> Apache loopback origin 후보와 원자 전환·bypass·자동 rollback
- [x] release artifact를 외부 Linux builder에서 생성하고 target VM에는 toolchain을 설치하지 않는 배포
- [x] digest 고정 container 도구로 정상·burst·slow connection·visible bot·spoofed forwarded header·위험 method A/B 시나리오
- [ ] verified crawler allowlist와 미허용 bot default deny replay (`DET-003`, `DET-004`)
- [x] 정상 오탐, origin 도달 감소, 429/405, RSS·CPU, public probe와 복구 시간을 비밀값 없는 evidence로 수집
- [x] 20회 edge/bypass 왕복과 실패 주입 완료, crawler gap을 명시한 Apache 파일럿 지원 판정

### 완료 배치: 직접 관리·standalone 방화벽·AI bot 방어

- 요구사항: `UI-016`, `UI-017`, `SEC-015`~`SEC-017`, `ACT-013`, `ACT-014`, `EDGE-014`, `DET-013`, `NFR-002`, `NFR-014`
- [x] Apache·Nginx trusted external TLS terminator에서 별도 관리 Host 직접 접속
- [x] Linux-PAM `vpsguard-admin` allowlist, root·system·잠김·만료 거부와 MFA
- [x] standalone typed UFW plan·dry-run·apply·read-back·rollback과 JW-agent delegated fail-closed mode
- [x] limiter capacity fail-open 제거와 IP·prefix·route·global bounded fallback
- [x] Google·Naver·Bing 공식 CIDR 검증과 미허용 declared AI bot 정책
- [x] request framing·smuggling 거부와 선택형 ModSecurity·OWASP CRS profile
- [x] host-to-VM UFW·PAM·위조 crawler·XFF 우회·WAF A/B와 실제 2GB 부하 증거
- [x] JW-agent가 소유하는 Nginx·Certbot·service·file·terminal 관리 기능은 VPSGuard에 중복 구현하지 않음
- [ ] 실제 공식 crawler source allow, 다중 실제 source high-cardinality, authenticated upload WAF와 HTTP/2·WebSocket VM replay

### 현재 배치: PAM 최초 TOTP 등록 신뢰 복구

- 요구사항: `UI-015`, `SEC-013`, `SEC-015`, `OPS-005`
- [x] PAM mode의 외부 선등록 고정 가정을 제거하고 root helper credential read-back으로 최초 설정 상태 판정
- [x] 단회 local code와 기존 Linux 계정 비밀번호·group·account 검증 뒤 사용자 QR 등록
- [x] PAM TOTP seed의 root-only master key·XChaCha20-Poly1305 봉인과 hash-only 일회용 복구 코드
- [x] PAM stack의 서버 비밀번호 검증과 VPSGuard MFA 검증을 분리하고 사용자 home seed 의존 제거
- [x] update bundle이 PAM service·tmpfiles credential directory를 snapshot·설치·rollback 범위에 포함
- [ ] 실제 운영자가 QR을 스캔한 뒤 PAM TOTP·복구 코드와 재시작 session VM 증거 재수집

### 현재 배치: 요청 상관관계와 운영 로그 표준화

- 요구사항: `OBS-012`, `OBS-013`, `NFR-005`, `SEC-005`
- [x] process nonce와 atomic sequence를 결합한 canonical request ID
- [x] Edge 응답·upstream과 loopback Control request span의 동일 ID 전파
- [x] detail retention에만 request ID·method를 저장하고 장기 rollup에서는 제거
- [x] request·operation·event ID를 함께 찾는 인증된 bounded 상관 조회 API·UI
- [x] API 오류의 cause·event ID와 JSON operational log 공통 field
- [x] systemd journal 식별자·per-unit rate limit과 비밀값 회귀 gate
- [x] request별 원본 IP·path journal 제거, 반복 차단 100회 sampling과 외부 command stderr fail-closed redaction
- [x] release binary startup event의 version·Git commit, Edge telemetry 손실·재연결 UI 노출
- [ ] 실제 `g7devops` public 응답·Nginx upstream·journal 상관 조회는 다음 배포 검증에서 수집

### 현재 배치: 주요 방어 상태 외부 알림

- 요구사항: `OBS-014`, `SEC-005`, `NFR-002`
- [x] HTTPS-only webhook 설정과 root-only bearer credential
- [x] Edge·provider와 분리한 bounded queue·재시도 worker
- [x] event ID 기반 영속 중복 방지와 재시작 후 미완료 재개
- [x] `LOCAL_GUARD`, `EMERGENCY_PROXY`, `RECOVERY_READY`, provider 시작·완료·실패·수동 복구 완료 알림
- [x] 마지막 성공·실패·drop 상태 API와 관리자 UI
- [x] webhook 장애가 방어·provider transaction을 막지 않는 자동 회귀
- [ ] 실제 외부 HTTPS receiver 장애·복구와 2GB VPS read-back 증거

### 현재 배치: 인프라 거버넌스·하네스 언어 경계

- 요구사항: `NFR-009`, `OPS-008`, `OPS-010`, `SEC-005`
- [x] Python 3.11+ 표준 라이브러리 기반 bounded argv runner, timeout, 구조화 오류와 secret redaction
- [x] Rustdoc·요구사항·언어 정책 gate를 Python 주력 구현으로 이전하고 Shell 호환 wrapper 유지
- [x] ops plan·fixture·evidence 오케스트레이션을 Python으로 이전하고 production mutation 금지 경계 적용
- [x] 기존 Shell line-count baseline과 신규 40줄 상한 ratchet
- [x] 배포·direct 복원 adapter의 중복 hash·machine identity helper를 31줄 공통 호환 계층으로 추출하고 두 상태 script 총 43줄 감축
- [x] CI에 Python gate 연결·로컬 전체 gate와 Python unit test 통과
- [x] first-install deployment snapshot·검증·복원을 `guard-system` 실제 `OperationDriver`와 단일 typed transaction으로 이전
- [x] 기존 v1 snapshot 형식 호환, checksum·machine·owned/protected read-back, partial restore fault 자동 rollback과 process 재시작 checkpoint 회귀
- [x] `deployment-state.sh`를 488줄 privileged mutation에서 62줄 CLI 호환 adapter로 축소
- [x] direct apply·restore와 edge/bypass public ingress mutation을 별도 Rust `OperationDriver`로 이전
- [x] exact-file staged candidate·legacy v1 restore·process checkpoint·probe failure rollback 격리 fixture 왕복
- [x] public ingress Shell을 compatibility·SSH transport·read-only preflight adapter로 축소하고 line-count baseline 하향
- [x] 기존 QGA·verified bundle·Rust deployment restore를 재사용하는 20회 endurance orchestration과 cycle별 candidate/release/service read-back
- [x] 격리 Ubuntu VM 20회 왕복과 100ms public probe timeline 수집

### 현재 배치: 로컬 빌드 산출물 저장공간 제한

- 요구사항: `NFR-010`
- [x] Cargo dev/test incremental 비활성화와 dependency debug 정보 제거
- [x] repository `target` 실제 directory만 허용하는 Python 정리 하네스
- [x] `release-bundle`, 검증 `evidence`와 알 수 없는 운영자 파일 보존
- [x] 정리 plan·apply, symlink 경계와 Cargo profile 단위 테스트
- [x] 정리 후 전체 check 재빌드에서 `target` 35.1GiB → 1.4GiB(약 96% 감소) 확인
- [x] 주요 개발 gate 종료 시 재사용 불가 임시 산출물만 자동 회수하고 warm cache 보존
- [x] 반복 빌드 cache는 자동 삭제하지 않고 4GiB 초과만 경고하며 전체 정리는 명시적 `--clean`으로 제한

### 현재 배치: 정직한 커버리지 회귀 방지

- 요구사항: `NFR-011`, `EDGE-003`, `NFR-003`, `ACT-006`, `TLS-001`
- [x] workspace 실측 line coverage를 versioned baseline으로 고정
- [x] Edge proxy·response·startup, Control runtime·provider, Cloudflare·system command·TLS를 제외 없이 named ratchet으로 추적
- [x] LCOV source 저장소 경계, 누락 production file과 하한 하락 fail-closed unit test
- [x] direct response header·startup config와 Control provider·transition helper characterization test
- [x] privileged deployment driver 6개 production module의 실측 file coverage 하한 고정
- [x] public ingress driver 11개 production module의 실측 file coverage 하한 고정
- [ ] workspace release 80%, core 90%, provider transaction 90%, edge policy 85% 도달

### 현재 배치: 빠른 개발 feedback과 변경 추적성

- 요구사항: `NFR-012`, `NFR-013`
- [x] Rust crate·Python·Web 명시 범위의 bounded fast check plan과 얇은 Shell 진입점
- [x] 범위 밖 workspace build 방지와 잘못된 scope fail-closed unit test
- [x] CI에 실제 Cargo profile 저장공간 gate 연결
- [x] PR·push event의 전체 비-merge commit에 요구사항 ID를 강제하고 생성 merge commit은 제외
- [x] 범위 검증은 개발 feedback 전용으로 두고 merge의 전체 `check.sh` gate 유지

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
- 안정 구간에는 `RECOVERY_READY`까지만 자동 전이하고 DNS only 복구는 관리자 승인
- UI 진행률과 실제 상태

### 커밋

```text
feat(provider): add transactional Cloudflare emergency protection
feat(web): report provider progress failures and recovery
```

### Exit gate

- [x] User token·exact record read-only preflight와 비밀 없는 typed report
- [x] 운영 금지 hostname·`vpsguard-` test prefix·초기 DNS-only·TTL 상한 fail-closed gate
- [ ] 격리 public origin과 test zone 실제 전환·복구
- [x] 401·403·429·5xx·timeout 장애 주입
- [x] proxy verify 전 origin lock 0건
- [x] SSH rule 변경 0건 자동 검증
- [x] 새로고침 후 transaction 진행 상태 복원

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
