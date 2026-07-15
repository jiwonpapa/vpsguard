---
title: VPS Guard Requirements and Contracts
status: draft-implementation-ready
doc_type: contract
source_of_truth: true
spec_version: 1
last_reviewed: 2026-07-15
---

# 요구사항과 구현 계약

## 1. 요구사항 ID 규칙

| 접두사 | 영역 |
|---|---|
| `EDGE` | Pingora 데이터 플레인 |
| `OBS` | 계측과 수집 |
| `DET` | 탐지와 점수 |
| `ACT` | 로컬·외부 대응 |
| `TLS` | 인증서와 HTTPS |
| `UI` | 독립 웹 관리 화면 |
| `OPS` | 설치, 업데이트, bypass와 복구 |
| `SEC` | 보안과 비밀값 |
| `NFR` | 성능, 안정성, 이식성 |

요구사항을 변경하거나 제거할 때 ID를 재사용하지 않습니다. 폐기한 ID는 사유와 대체 ID를 기록합니다.

## 2. 기능 요구사항

### 2.1 Edge

| ID | 필수 요구사항 | 수용 기준 |
|---|---|---|
| `EDGE-001` | public 80/443 listener를 제공해야 함 | 실제 VPS에서 HTTP redirect와 HTTPS 요청 성공 |
| `EDGE-002` | SNI 기반 인증서 선택과 TLS 종료 | 등록 도메인별 올바른 인증서 제공 |
| `EDGE-003` | loopback Nginx upstream으로 streaming proxy | 일반·chunked·대용량 응답 손실 없음 |
| `EDGE-004` | trusted proxy 외의 forwarded header를 무시 | spoofed IP가 client identity로 사용되지 않음 |
| `EDGE-005` | HTTP/1.1, HTTP/2, WebSocket을 지원 | protocol별 E2E 통과 |
| `EDGE-006` | 일반·업로드·고비용 경로별 body와 timeout 정책 | 경로별 한도와 정상 업로드 모두 통과 |
| `EDGE-007` | hot path에서 동기 control·DB·disk 의존 금지 | control 종료 중에도 정상 요청 처리 |
| `EDGE-008` | allow, throttle, challenge, deny 정책 실행 | fixture 정책별 정확한 응답과 upstream 차단 |
| `EDGE-009` | 정책은 schema, hash와 범위 검증 후 원자 교체 | 잘못된 정책 거부, 이전 정책 유지 |
| `EDGE-010` | health/live와 health/ready를 분리 | process 생존과 upstream 준비 상태 구분 |
| `EDGE-011` | 요청 body와 민감 query 값을 기본 로그에서 제외 | 로그 fixture에 비밀값이 없음 |
| `EDGE-012` | client·route별 bounded in-memory counter 사용 | 공격 cardinality에서도 메모리 상한 유지 |
| `EDGE-013` | 지원 HTTP protocol에서 app 분석을 생략하는 `protocol_only` mode 제공 | profile 판정은 생략하되 TLS·Host·forwarded header·body·timeout·bounded 계측 불변조건과 HTTP E2E 유지 |

`protocol_only`는 raw L4 pass-through가 아니라 HTTP parsing 이후 app profile·행동 분석만 생략하는 mode이며, WebSocket은 upgrade handshake 이후 frame payload를 해석하지 않습니다. VPSGuard가 bind·변경하지 않은 port의 protocol은 기존 service로 계속 전달되며, 소유한 80/443의 비HTTP protocol은 protocol confusion 방지를 위해 거부합니다.

### 2.2 Observation

| ID | 필수 요구사항 | 수용 기준 |
|---|---|---|
| `OBS-001` | RPS, 동시 연결, status, bytes, latency와 upstream 결과 수집 | live 화면과 테스트 집계 일치 |
| `OBS-002` | IP·prefix·ASN·국가·UA family·route class별 집계 | 외부 IP 상세 화면에서 필드 확인 |
| `OBS-003` | CPU, load, memory, swap, disk wait와 network 수집 | agent fixture와 실제 서버 값 표시 |
| `OBS-004` | PHP-FPM active/idle/max children와 queue 상태 수집 | status endpoint 장애를 별도 표시 |
| `OBS-005` | MySQL connection, slow query, lock wait 상태 수집 | 최소 권한 계정으로 수집 성공 |
| `OBS-006` | Redis memory, connected clients와 hit/miss 수집 | Redis 비활성·장애 상태 구분 |
| `OBS-007` | 1초·10초·1분 집계 계층 제공 | 지정 보존기간과 downsampling 검증 |
| `OBS-008` | edge 계측 전송은 non-blocking이며 손실량을 기록 | control 중단 시 drop counter 증가, 요청 성공 |
| `OBS-009` | 외부 GeoIP/ASN API를 요청 hot path에서 호출 금지 | 네트워크 차단 상태에서도 edge 처리 동일 |
| `OBS-010` | route와 server pressure를 동일 시간창으로 상관분석 | 사건 리포트에 원인 경로와 자원 변화 표시 |
| `OBS-011` | 관리자가 확정한 핵심 service별 CPU·memory·I/O·process/task 수를 cgroup v2 기준으로 수집 | 전체 process 감사 없이 allowlisted systemd unit 값과 semantic health를 동일 시간축에 표시 |

ASN·국가 정보는 로컬 데이터베이스가 없으면 `알 수 없음`으로 표시합니다. 정확하지 않은 위치를 추정해서 확정값처럼 표시하지 않습니다.

service 자동 발견은 읽기 전용 후보 제시까지만 허용합니다. 관리자가 선택하지 않은 unit, unrelated daemon과 개별 process command line은 수집·저장하지 않습니다. Nginx/Apache, PHP-FPM, MySQL/MariaDB와 Redis는 HTTP 요청의 실제 병목 경로에 포함될 때만 관측하며, 일반 health와 service 자원값 외에 각각 connection·queue·lock·memory 같은 semantic metric을 별도 상태로 표시합니다.

### 2.3 Detection

| ID | 필수 요구사항 | 수용 기준 |
|---|---|---|
| `DET-001` | trust, bot likelihood, resource cost를 별도 계산 | 각 점수와 근거가 API에 노출 |
| `DET-002` | 범용 PHP·GnuBoard 5·GnuBoard 7·WordPress route profile을 분리 지원 | 각 profile의 실제 route inventory fixture가 서로 오분류되지 않음 |
| `DET-003` | User-Agent 단독으로 검색봇을 검증하지 않음 | 위조 Googlebot fixture가 verified 처리되지 않음 |
| `DET-004` | 검증된 검색봇도 고비용 경로 한도 적용 | 과도한 verified bot 요청이 throttle 됨 |
| `DET-005` | 초기 판단은 규칙 기반이며 설명 가능해야 함 | 모든 판정에 reason code 존재 |
| `DET-006` | 사이트별 기준선과 고정 안전 한도를 함께 사용 | 학습 기간에도 정적 포화 보호 동작 |
| `DET-007` | 단일 spike로 비상 전환하지 않음 | 지속 window가 없으면 WATCH 이하 유지 |
| `DET-008` | 자동 차단은 TTL과 재평가를 가져야 함 | TTL 만료 후 정책 자동 제거 |
| `DET-009` | NAT/shared IP를 고려해 IP 외 세션·행동 사용 | 한 정상 세션 때문에 전체 IP 영구 차단 없음 |
| `DET-010` | 판정 입력 결손을 명시 | agent 장애 중 자원 기반 확정 판정 금지 |
| `DET-011` | 정적 안전 한도, app profile, site override와 incident policy를 결정적 순서로 합성 | app의 auth·admin·search는 strict, media는 upload로 보호되고 명시적 site override가 우선 |

### 2.4 Action

| ID | 필수 요구사항 | 수용 기준 |
|---|---|---|
| `ACT-001` | client·route class별 rate limit | 한 route 제한이 정적 파일에 영향 없음 |
| `ACT-002` | 429와 Retry-After를 일관되게 제공 | HTTP 계약 테스트 통과 |
| `ACT-003` | signed clearance와 선택형 challenge 제공 | 정상 token 통과, 위조·만료 token 거부 |
| `ACT-004` | 검색·로그인·업로드 등 기능별 보호 모드 | 사이트 전체 차단 전 부분 보호 가능 |
| `ACT-005` | IP·CIDR 임시 차단과 TTL 해제 | 만료·수동 해제가 edge에 반영 |
| `ACT-006` | Cloudflare proxied 전환을 재개 가능한 단계로 실행 | 단계별 state와 부분 실패 복구 |
| `ACT-007` | 프록시 경유 확인 후 원본 80/443 보호 | 확인 전 origin lock 실행 금지 |
| `ACT-008` | 안정 구간 후 DNS only 복구 | snapshot 기반 역순 복구와 read-back |
| `ACT-009` | 관리자가 자동 전이를 고정·해제 | MANUAL_HOLD에서 외부 자동 조치 없음 |
| `ACT-010` | SSH와 TCP 80/443 외 기존 listener·firewall rule·service를 자동 변경하지 않음 | ingress·provider 전후 non-web port와 SSH rule diff 0, 모든 firewall mutation property test 통과 |
| `ACT-011` | provider 미설정·장애 시 로컬 보호 유지 | 외부 실패가 edge 요청 실패로 전파되지 않음 |
| `ACT-012` | 모든 action에 idempotency key와 audit event | 중복 명령이 중복 방화벽 변경을 만들지 않음 |

### 2.5 TLS

| ID | 필수 요구사항 | 수용 기준 |
|---|---|---|
| `TLS-001` | PEM cert/key 일치와 유효기간 사전 검사 | 불일치·만료 인증서로 시작하지 않음 |
| `TLS-002` | 외부 ACME renew hook 지원 | 갱신 인증서 무중단 반영 |
| `TLS-003` | HTTP-01 경로를 명시적으로 허용 | 발급·갱신 E2E 통과 |
| `TLS-004` | 실제 제공 인증서와 파일 인증서 비교 | 불일치 경고와 리포트 생성 |
| `TLS-005` | reset·update·bypass에서 인증서 보존 | 파괴 작업 회귀 테스트 통과 |
| `TLS-006` | 기존 외부 갱신 수단을 우선 감지·사용하고, 없을 때만 외부 ACME client 구성을 plan·승인·apply로 보조 | startup은 검사만 수행하며 기존 timer를 변경하지 않고, 미설정 fixture에서만 Certbot staging 발급·timer·deploy hook과 실패 사건 E2E 통과 |

### 2.6 Web UI

| ID | 필수 요구사항 | 수용 기준 |
|---|---|---|
| `UI-001` | Control은 loopback에 유지하고 edge의 별도 관리 Host로 HTTPS UI 제공 | 관리 Host는 Control로만 전달되고 Control 포트는 public에 노출되지 않음 |
| `UI-002` | 현재 상태와 판정 근거 3개를 첫 화면에 표시 | NORMAL~RECOVERING 모든 fixture 렌더링 |
| `UI-003` | 실시간 RPS, bandwidth, latency, status와 연결 수 표시 | SSE 갱신과 서버 집계 일치 |
| `UI-004` | 외부 IP 목록과 상세 drill-down 제공 | 검색·정렬·필터·페이지 이동 동작 |
| `UI-005` | IP별 요청, bytes, routes, errors, score와 조치 표시 | API와 화면 값 일치 |
| `UI-006` | PHP-FPM·MySQL·Redis·OS 상관 그래프 제공 | 동일 시간축으로 원인 비교 가능 |
| `UI-007` | 사건 타임라인과 자동 조치 결과 제공 | 부분 실패와 복구 단계가 누락되지 않음 |
| `UI-008` | Cloudflare·방화벽·TLS 실제 상태 표시 | 설정값이 아닌 read-back 결과 사용 |
| `UI-009` | 자동 대응 중지·비상 시작·복구 명령 제공 | 권한·재확인·idempotency 계약 통과 |
| `UI-010` | 어려운 지표에 도움말과 산정 근거 제공 | 용어집과 tooltip이 잘리지 않음 |
| `UI-011` | 한국어 기본, light/dark theme 제공 | 테마별 desktop/mobile 시각 회귀 통과 |
| `UI-012` | 원시 IP와 민감 정보의 표시·내보내기 권한 분리 | 읽기 전용 사용자는 민감 export 불가 |
| `UI-013` | 연결 끊김·데이터 지연·수집 실패를 명확히 표시 | stale 값을 정상처럼 표시하지 않음 |
| `UI-014` | 범용 패킷 캡처·프로세스 관리 기능은 제공하지 않음 | 공개 UI 기능 목록 감사 통과 |

세부 정보 구조와 화면 계약은 [모니터링 웹 UI](09-monitoring-web-ui.md)를 따릅니다.

### 2.7 Operations

| ID | 필수 요구사항 | 수용 기준 |
|---|---|---|
| `OPS-001` | 기존 운영 사이트에 shadow mode로 먼저 설치 | public port 변경 없이 관찰 검증 가능 |
| `OPS-002` | 설정 변경 전 plan과 snapshot 생성 | 영향 파일·서비스·포트 표시 |
| `OPS-003` | edge public cutover를 원자적 단계로 실행 | 실패 시 기존 ingress 복구 |
| `OPS-004` | bypass enable/disable 제공 | 실제 VPS 양방향 smoke 통과 |
| `OPS-005` | update 전 backup과 rollback 제공 | 실패 바이너리 자동 복구 |
| `OPS-006` | uninstall이 사이트·인증서·원본 설정을 보존 | 소유 파일만 제거 |
| `OPS-007` | x86_64와 aarch64 artifact 제공 | checksum·SBOM과 설치 smoke |
| `OPS-008` | root 변경은 공통 runner와 감사 로그 사용 | argv·exit·duration 기록, 비밀 마스킹 |

### 2.8 Security and non-functional

| ID | 필수 요구사항 | 수용 기준 |
|---|---|---|
| `SEC-001` | 비밀값은 전용 root-only 파일로 관리 | 로그·state·API에 token 없음 |
| `SEC-002` | UI는 root 비밀번호를 수집하지 않음 | 입력·API schema에 password 필드 없음 |
| `SEC-003` | Unix socket peer credential과 파일 권한 검증 | 비인가 local user 명령 거부 |
| `SEC-004` | provider resource allowlist 적용 | 다른 zone·instance 변경 거부 |
| `SEC-005` | event와 report의 query·header 비밀 마스킹 | fixture secret scan 통과 |
| `SEC-006` | 짧은 단회 로그인 코드는 session 발급에만 사용 | 만료·client별 시도 한도·재사용·운영 명령 직접 사용이 거부되고 오입력만으로 정상 code가 폐기되지 않음 |
| `SEC-007` | 관리 Host·Origin을 고정하고 읽기·SSE·변경 API를 session으로 보호 | 잘못된 Host·Origin, 익명 읽기와 CSRF 없는 변경이 거부되고 HTTPS cookie에 Secure·HttpOnly·SameSite=Strict 적용 |
| `NFR-001` | edge 추가 지연 예산을 벤치마크로 관리 | 승인 기준 초과 시 릴리스 차단 |
| `NFR-002` | 2GB VPS에서 bounded memory 보장 | 고 cardinality soak에서 상한 증명 |
| `NFR-003` | control restart가 public 요청을 중단하지 않음 | fault injection 통과 |
| `NFR-004` | 상태·정책·snapshot 원자 저장 | 강제 종료 후 손상 없음 |
| `NFR-005` | 구조화 오류에 문제·원인·영향·다음 조치 포함 | API·CLI 오류 snapshot 통과 |
| `NFR-006` | 설정과 상태에 schema version 포함 | 구버전 migration과 미래 버전 거부 |
| `NFR-007` | 모든 Rust module과 공개 API의 rustdoc를 빌드 게이트로 강제 | module `//!`, workspace `missing_docs = "deny"`, rustdoc warning 거부와 lint 우회 차단 |
| `NFR-008` | 표준 protocol·parser·DB driver는 검증된 외부 crate/client를 우선하고 project 고유 불변조건만 직접 구현 | dependency 결정에 유지보수·license·advisory·MSRV·unsafe·전이 의존성·binary/RSS 영향과 adapter test 근거 존재 |

## 3. 프로세스 간 계약

### 3.1 Hot path 원칙

`guard-edge`는 요청 처리 중 다음 작업을 금지합니다.

- control HTTP/RPC 동기 호출
- SQLite 또는 외부 DB 접근
- Cloudflare·GeoIP 외부 API 호출
- 요청별 파일 append와 fsync
- DNS 검증을 위한 요청별 lookup

edge는 in-memory policy와 bounded counter만 사용합니다.

### 3.2 Unix socket

| 경로 | 방향 | 보장 |
|---|---|---|
| `/run/vps-guard/telemetry.sock` | edge -> control | non-blocking, 손실 허용, drop 계측 |
| `/run/vps-guard/control.sock` | control <-> edge | versioned command, peer credential, 응답 필수 |

정책 본문은 `/var/lib/vps-guard/policy.json`에 원자 저장하고 control socket은 새 version 적용을 알립니다. edge는 파일을 다시 읽어 schema와 hash를 검증한 뒤 한 번에 교체합니다.

### 3.3 정책 snapshot 최소 필드

```json
{
  "schema_version": 1,
  "policy_version": 42,
  "generated_at": "2026-07-14T00:00:00Z",
  "expires_at": "2026-07-14T00:10:00Z",
  "mode": "LOCAL_GUARD",
  "route_rules": [],
  "client_rules": [],
  "static_limits": {},
  "content_sha256": "..."
}
```

만료 정책은 자동 차단과 challenge를 제거하되 정적 body·timeout·Host 안전 규칙은 유지합니다.

## 4. 설정 계약

초기 형식은 versioned TOML입니다.

```toml
schema_version = 1

[edge]
http_bind = "0.0.0.0:80"
https_bind = "0.0.0.0:443"
trusted_proxy_cidrs = []

[origin]
address = "127.0.0.1:8080"
protocol = "http"

[tls]
management = "auto"
[[tls.certificates]]
domains = ["example.com", "guard.example.com"]
cert_file = "tls-cert.pem"
key_file = "tls-key.pem"
certbot_lineage = "example.com"

[ui]
bind = "127.0.0.1:7727"
public_host = "guard.example.com"
admin_socket = "/run/vps-guard/admin.sock"
login_rate_limit_rpm = 10
language = "ko"

[detection]
profile = "gnuboard7"
mode = "observe"

[cloudflare]
enabled = false
zone_id = ""
records = []
token_file = "cloudflare-token"

# [[cloudflare.records]]
# id = "0123456789abcdef0123456789abcdef"
# name = "example.com"
# record_type = "A"

[retention]
live_seconds = 900
detail_hours = 24
aggregate_days = 30
incident_days = 90
raw_ip_days = 7
```

설정 검증:

- unknown key는 warning이 아니라 오류로 처리합니다.
- port, path, CIDR, duration과 threshold 범위를 검증합니다.
- token 본문을 TOML에 직접 넣는 것을 금지합니다.
- `tls.management`은 기존 manager 자동 감지, 명시적 외부 관리, VPSGuard 보조와 수동 교체를 구분합니다. startup은 어떤 mode에서도 발급·timer 변경을 실행하지 않습니다.
- 상대 TLS PEM 경로는 각 service의 systemd `$CREDENTIALS_DIRECTORY`에서만 해석합니다. Control에는 공개 certificate만, edge에는 certificate와 private key를 별도 credential로 전달합니다.
- `cloudflare.token_file`의 상대값은 systemd `$CREDENTIALS_DIRECTORY`의 단일 credential 이름으로만 해석하고, 운영 token 원본은 root-only 파일로 유지합니다.
- Cloudflare record는 32자리 ID·정확한 hostname·A/AAAA/CNAME type을 명시하고 한 transaction에서 같은 hostname만 허용합니다.
- `ui.public_host`는 exact hostname이며 app canonical Host와 분리하고 TLS certificate domain에 포함해야 합니다.
- `ui.bind`는 loopback, `ui.admin_socket`은 절대 경로, 로그인 시도 한도는 `1..=60`이어야 합니다.
- `detection.profile = "gnuboard"`는 기존 설정 호환을 위해 GnuBoard 5 alias로만 읽고 새 설정은 `php`, `gnuboard5`, `gnuboard7`, `wordpress`를 명시합니다.
- 설정 적용 전 후보 parse, semantic validation, edge dry-load를 통과해야 합니다.

## 5. 상태 계약

`state.json` 최소 필드:

```json
{
  "schema_version": 1,
  "current_mode": "NORMAL",
  "manual_hold": false,
  "policy_version": 42,
  "provider_transaction": null,
  "last_transition_at": "2026-07-14T00:00:00Z",
  "last_healthy_at": "2026-07-14T00:00:00Z",
  "active_incident_id": null,
  "bypass_enabled": false
}
```

상태 전이는 event를 먼저 계획하고 action 결과와 함께 원자 기록합니다. 외부 provider 작업은 현재 단계, 시도 횟수, 마지막 오류와 rollback snapshot을 별도 transaction object에 저장합니다.

## 6. 사건 이벤트 계약

모든 중요 이벤트는 다음 공통 필드를 가집니다.

```json
{
  "schema_version": 1,
  "event_id": "uuid",
  "occurred_at": "2026-07-14T00:00:00Z",
  "severity": "warning",
  "kind": "state.transition",
  "summary": "검색 경로 부하로 로컬 방어를 시작했습니다.",
  "reason_codes": ["SEARCH_COST_SPIKE", "PHP_FPM_PRESSURE"],
  "evidence": {},
  "action": {},
  "result": {},
  "recovery": {}
}
```

사건 저장은 request hot path와 분리합니다. 동일 주체의 반복 차단은 집계해 event 폭증을 막습니다.

## 7. Web API 계약

초기 API prefix는 `/api/v1`입니다.

### 7.1 읽기

| Method | Path | 목적 |
|---|---|---|
| `GET` | `/status` | mode, provider, TLS, collector와 stale 상태 |
| `GET` | `/traffic/summary` | 현재·비교 구간 핵심 지표 |
| `GET` | `/traffic/series` | downsampled time series |
| `GET` | `/clients` | 외부 IP·identity 목록과 필터 |
| `GET` | `/clients/{id}` | 경로·점수·조치 상세 |
| `GET` | `/routes` | route class별 비용과 상태 |
| `GET` | `/resources` | OS·PHP·DB·Redis 상태 |
| `GET` | `/incidents` | 사건 목록 |
| `GET` | `/incidents/{id}` | 타임라인·증거·복구 |
| `GET` | `/events` | SSE 실시간 event stream |

### 7.2 명령

| Method | Path | 목적 |
|---|---|---|
| `POST` | `/actions/manual-hold` | 자동 상태 전이 고정 |
| `POST` | `/actions/resume-auto` | 자동 전이 재개 |
| `POST` | `/actions/local-guard` | 로컬 보호 수동 시작 |
| `POST` | `/actions/emergency-proxy` | Cloudflare 비상 전환 |
| `POST` | `/actions/recover` | 검증된 정상 복구 시작 |
| `POST` | `/clients/{id}/block` | TTL 차단 |
| `DELETE` | `/clients/{id}/block` | 차단 해제 |

모든 명령은 CSRF 방어, 권한 확인, `Idempotency-Key`, 현재 state precondition과 확인 문구를 요구합니다.

## 8. 오류 계약

```json
{
  "error": {
    "code": "PROVIDER_VERIFY_FAILED",
    "problem": "Cloudflare 프록시 경유를 확인하지 못했습니다.",
    "cause": "DNS read-back은 성공했지만 HTTPS probe에 Cloudflare 응답 증거가 없습니다.",
    "impact": "원본 방화벽 잠금은 실행하지 않았습니다.",
    "next_action": "DNS 전파와 record 이름을 확인한 뒤 다시 시도하십시오.",
    "retriable": true,
    "event_id": "uuid"
  }
}
```

내부 stack trace, token, command secret과 인증서 private path 세부 권한은 사용자 API에 반환하지 않습니다.

## 9. Provider 계약

Cloudflare adapter는 다음 의미 단계를 구현합니다.

1. `snapshot()`
2. `request_proxy_enable()`
3. `verify_proxy_enabled()`
4. `request_origin_lock()`
5. `verify_origin_lock()`
6. `restore(snapshot)`
7. `verify_restored(snapshot)`

각 단계는 idempotent해야 하며 API 요청 성공과 실제 상태 확인을 구분합니다. zone, record와 instance 식별자는 설정 allowlist 밖으로 벗어날 수 없습니다.

로컬 nftables adapter는 provider와 분리하고 최소한 다음을 보장합니다.

- 관리 SSH rule 불변
- installer 또는 사용자 소유 chain을 수정하지 않음
- `vps-guard` 전용 table·chain·set만 소유
- TTL set과 atomic ruleset 적용
- uninstall·bypass 시 소유 rule만 제거

## 10. 저장 계약

- 운영 로그는 구조화 JSON으로 stdout/stderr에 기록해 systemd journal이 수집하며 request별 원본 IP·path 로그를 기본 `info`에 남기지 않습니다. VPSGuard는 host의 전역 journald 보존 설정을 임의 변경하지 않습니다.
- live 1초 자료는 bounded 메모리 ring buffer로 유지합니다.
- edge telemetry는 query·header·body 원문 없이 normalized route, status, latency, byte count와 판정만 bounded non-blocking channel로 보냅니다.
- control은 bounded queue 뒤의 전용 blocking writer에서 transaction batch로 상세 sample을 SQLite WAL에 기록합니다. async runtime worker에서 request별 동기 SQLite write를 실행하지 않습니다.
- 10초·1분 rollup table과 incident·audit table을 분리하고 각 retention 값을 실제 삭제·downsampling에 연결합니다.
- edge는 SQLite에 접근하지 않습니다.
- retention 만료는 bounded batch로 삭제하고 WAL checkpoint·vacuum 때문에 실시간 control이 장시간 멈추지 않게 합니다.
- raw IP는 장기 route aggregate와 분리된 상세·client 단기 계층에만 두고 상세·IP·aggregate·incident 보존기간을 독립 적용합니다.
- DB·WAL 크기, queue drop, 마지막 rollup·retention 성공과 disk 여유를 계측합니다.
- request body, cookie 원문, authorization header와 민감 query 값은 저장하지 않습니다.
