---
title: VPS Guard Initial MASTER SDD
status: draft-implementation-ready
doc_type: contract
source_of_truth: true
spec_version: 1
last_reviewed: 2026-07-16
bounded_context: adaptive-vps-guard
---

# VPS Guard Initial MASTER SDD

## 1. 목적

VPS Guard는 소규모 VPS의 최앞단에서 HTTP 요청을 판정하고 서버 자원 상태와 결합하여, 정상 사용자의 직접 연결 성능을 유지하면서 자동화 트래픽으로 인한 장애와 비용을 줄이는 Rust 기반 적응형 보안 게이트웨이입니다.

이 문서는 새 저장소를 만들고 첫 코드를 작성할 수 있는 초기 구현 계약입니다. 제품 배경은 [페인킬러](01-painkiller.md), 세부 기능 계약은 [요구사항과 계약](06-requirements-contracts.md), 완료 증명은 [검증 추적표](07-verification-traceability.md)를 따릅니다.

## 2. 제품 명제

```text
정상 상태
  Cloudflare DNS only
  -> VPS Guard
  -> Nginx/Apache
  -> Application

비상 상태
  Cloudflare proxied
  -> VPS Guard
  -> Nginx/Apache
  -> Application
```

VPS Guard 자체는 정상 상태에도 로컬 VPS 최앞단에 존재합니다. 해외 프록시를 상시 통과하지 않으며, 이상 트래픽이 로컬 방어 한계를 넘을 때만 Cloudflare를 활성화합니다.

## 3. 사용자와 지원 범위

### 3.1 초기 사용자

- Ubuntu VPS 한 대를 직접 관리하는 개인 또는 소규모 운영자
- 1~4GB 메모리에서 Nginx 또는 Apache, PHP-FPM, MySQL과 Redis를 운영하는 사용자
- GnuBoard 또는 WordPress 기반 커뮤니티·콘텐츠 사이트
- SSH는 사용할 수 있지만 로그 분석과 방화벽·Cloudflare 수동 전환이 어려운 사용자

### 3.2 초기 지원 환경

- Linux x86_64와 aarch64
- Ubuntu 24.04를 1차 운영 검증 기준으로 사용
- Nginx를 첫 공개 upstream으로 지원
- Apache는 기존 월척웹 자산의 호환 시험을 거친 뒤 공개 지원 여부 결정
- Cloudflare DNS zone과 API token을 선택적으로 사용
- 로컬 방화벽은 nftables를 기준으로 사용

지원 환경 확대는 추측으로 선언하지 않고 실제 설치·장애·복구 하네스가 통과한 조합만 공개합니다.

## 4. 비목표

- CDN 또는 Cloudflare 대체
- 범용 정적 파일 웹서버나 PHP FastCGI 서버 구현
- 애플리케이션 소스·쿼리 자동 수정
- 네트워크 회선에 도달하기 전의 L3/L4 대규모 공격을 로컬에서 흡수
- 바이러스 백신, SIEM, 범용 서버 관리 패널
- SMTP, R2, 결제 등 애플리케이션 외부 서비스 설정
- 자체 ACME 프로토콜 클라이언트 구현
- 임의 TCP/UDP 프로토콜을 전달하는 범용 L4 proxy
- 전체 systemd unit·process를 감사하거나 제어하는 서버 관리 도구
- 첫 버전의 머신러닝 봇 판별
- Docker 기반 배포

## 5. 시스템 경계

```text
Internet
  |
  v
guard-edge (Pingora, public :80/:443)
  |         |
  |         +-- non-blocking metrics/events
  |                    |
  v                    v
Nginx loopback     guard-control
  |                    |-- detection/state machine
  v                    |-- Web UI/API on loopback
PHP-FPM                 |-- Cloudflare/nftables actions
  |                     |
  v                     +-- guard-agent collectors
MySQL/Redis                  (OS/PHP/DB/Redis)
```

### 5.1 `guard-edge`

- public 80/443과 TLS를 소유하는 데이터 플레인
- 요청 hot path에서 동기 외부 API, DB, 파일 쓰기와 control RPC를 금지
- 메모리에 적재된 마지막 정상 정책으로 요청을 허용·제한·차단·검증
- 계측 전송 실패가 정상 요청 실패로 전파되지 않도록 bounded non-blocking 채널 사용
- control 장애 시 마지막 정상 정책과 정적 안전 한도를 유지

### 5.2 `guard-control`

- 요청 집계와 서버 자원을 결합해 점수 계산
- 방어 상태 머신 실행
- 정책 snapshot 생성·검증·배포
- Cloudflare와 로컬 방화벽 조치
- 웹 API, SSE 사건 스트림과 감사 로그 제공

### 5.3 `guard-agent`

- OS, Nginx, PHP-FPM, MySQL, Redis 관측
- 자동 발견 결과를 그대로 수집하지 않고 관리자가 확인한 HTTP 핵심 경로 service만 allowlist로 관측
- service별 CPU, memory, I/O와 process/task 수는 systemd unit의 cgroup v2 계정값으로 집계
- 읽기 전용 또는 최소 권한으로 수집
- 수집 실패를 명시하고 추정값으로 성공 처리하지 않음
- 초기에는 control 프로세스 내부 모듈로 구현 가능

## 6. 기존 소스 재사용 계약

기준 자산은 과거 `rest-middleware/crates/edge_proxy`입니다. 제거 커밋 `87c0f0e61`의 부모에서 복구할 수 있습니다.

```bash
git show 87c0f0e61^:crates/edge_proxy/src/main.rs
git show 87c0f0e61^:crates/common/src/config/model/edge_proxy_config.rs
```

코드는 복사 후 바로 운영하지 않습니다.

1. 원본 마지막 정상 테스트와 의존성 버전을 기록합니다.
2. 월척 도메인·경로·포트·설정 의존성을 제거합니다.
3. 재사용한 정책마다 요구사항 ID를 부여합니다.
4. 기존 테스트를 함께 이동하고 새 프로젝트에서 다시 통과시킵니다.
5. 라이선스와 third-party notice를 감사합니다.
6. 직접 TLS, 업로드, WebSocket과 bypass를 새 하네스로 재검증합니다.

## 7. 요청 처리 계약

1. edge가 연결·TLS·Host·요청 크기 기본 검사를 수행합니다.
2. trusted proxy가 아니면 inbound forwarded header를 신뢰하지 않습니다.
3. 요청의 route class와 client identity를 계산합니다.
4. 메모리 정책으로 allow, throttle, challenge, deny 중 하나를 선택합니다.
5. 허용 요청만 loopback upstream으로 전달합니다.
6. 응답 코드, bytes, latency와 upstream 결과를 메모리 집계에 반영합니다.
7. 집계 결과는 요청 처리와 분리된 비동기 경로로 control에 전달합니다.

정책 조회 때문에 요청마다 control 프로세스나 SQLite에 접근하는 구현은 금지합니다.

VPSGuard의 공개 protocol 범위는 HTTP/1.1, HTTP/2와 HTTP Upgrade로 시작하는 WebSocket입니다. 지원한다고 선언한 protocol은 모두 E2E를 통과해야 하지만 인터넷의 모든 protocol을 해석하지는 않습니다. 요청 처리 mode는 다음 두 축을 분리합니다.

- `profiled`: app profile, route class와 행동 신호를 사용해 분석·판정합니다.
- `protocol_only`: app profile과 행동 판정을 생략하고 upstream으로 전달합니다. 다만 TLS·SNI·Host, forwarded header, 연결·body·timeout 상한, bounded 계측과 비밀값 미저장 불변조건은 유지합니다.

`protocol_only`도 Pingora가 HTTP와 TLS를 종료하므로 raw TCP/TLS pass-through가 아닙니다. WebSocket은 HTTP upgrade까지 검사한 뒤 frame 내용은 해석하지 않고 bounded tunnel로 전달합니다. enforcement의 `observe`·`enforce`와 inspection의 `profiled`·`protocol_only`는 서로 독립된 설정입니다.

VPSGuard는 소유한 TCP 80/443 외 listener와 firewall rule을 가로채지 않습니다. SSH, DB, mail, game server와 사용자 정의 port의 트래픽은 VPSGuard를 통과시키는 것이 아니라 기존 kernel·service 경로를 그대로 유지합니다. 반대로 VPSGuard가 소유한 80/443에 들어온 비HTTP protocol을 HTTP origin으로 무조건 전달하면 protocol confusion과 우회가 생기므로 거부합니다. 동일 443에서 별도 raw TLS service를 multiplex해야 하는 요구는 명시적 SNI/ALPN L4 listener와 별도 요구사항 없이는 지원하지 않습니다.

### 7.1 애플리케이션 보안 계층

범용 core는 위험한 HTTP method 거부, Host·forwarded header 경계, body·timeout 상한, response version header 제거와 보안 header 적용을 소유합니다. `profiled+enforce`에서는 app profile이 인증으로 분류한 경로에 별도 bounded client 한도를 적용합니다. G7 overlay는 Laravel API·SPA의 실제 인증 경로와 기본 CSP를 소유하고 범용·G5 규칙과 섞지 않습니다.

CSP는 기본 report-only로 관찰한 뒤 site 호환성을 확인해 enforce합니다. HSTS는 HTTPS 운영·bypass 경로가 확인된 site에서만 명시적으로 켭니다. `protocol_only`는 app CSP overlay와 인증 행동 판정을 생략하지만 protocol 안전 method와 비밀값 미저장 불변조건은 유지합니다.

VPSGuard는 query나 request body의 공격 문자열을 정규식으로 찾았다는 이유만으로 SQL injection·XSS 방어 완료를 선언하지 않습니다. parameterized query, schema validation, context-aware output escaping, CSRF·session·계정별 로그인 제한은 origin 애플리케이션 책임이며 CSP와 client별 edge rate limit은 보조 방어입니다.

## 8. 클라이언트 식별 계약

단일 IP를 사람 한 명으로 간주하지 않습니다. client identity는 다음 자료를 조합한 단기 식별자입니다.

- trusted chain에서 얻은 source IP
- IP prefix와 ASN
- User-Agent family
- 서명된 guard session cookie
- 애플리케이션 인증 상태가 제공되는 경우 익명화한 session class

개인정보 최소화를 위해 원본 cookie와 애플리케이션 계정 ID는 저장하지 않습니다. 차단에 필요한 IP는 제한된 보존기간 동안 저장하고 장기 통계는 집계값을 사용합니다.

## 9. 방어 상태 머신

### 9.1 상태

| 코드 | 표시 | 의미 |
|---|---|---|
| `NORMAL` | 정상 | 기준선 이내, 관찰만 수행 |
| `WATCH` | 주의 | 이상 신호가 있으나 강한 조치 전 |
| `LOCAL_GUARD` | 로컬 방어 | rate limit, challenge, TTL 차단과 기능 보호 적용 |
| `EMERGENCY_PROXY` | 비상 보호 | Cloudflare proxied와 원본 보호 적용 |
| `RECOVERING` | 복구 | 제한을 단계적으로 해제하며 재발 감시 |
| `MANUAL_HOLD` | 수동 고정 | 관리자가 자동 전이를 중지한 상태 |

### 9.2 전이 규칙

- 한 번의 spike만으로 `EMERGENCY_PROXY`로 전이하지 않습니다.
- `bot_likelihood`, `resource_cost`, `server_pressure` 중 둘 이상이 임계치를 지속해서 넘을 때 자동 승격합니다.
- 회선 포화나 다수 source의 빠른 확산처럼 즉시성 높은 신호는 별도 비상 규칙을 허용합니다.
- 복구는 승격보다 긴 안정 구간을 요구합니다.
- provider가 설정되지 않았으면 `LOCAL_GUARD`를 유지하고 비상 전환 불가 이유를 표시합니다.
- `MANUAL_HOLD`에서는 자동 상태 전이를 금지하지만 정적 body·timeout 안전 한도는 유지합니다.

정확한 기본 임계값은 파일럿 데이터로 확정하며 설정 스키마에는 버전과 범위를 둡니다. 임계값 미확정은 상태 머신 구현을 막지 않으며 테스트에서는 명시적 fixture 값을 사용합니다.

## 10. Cloudflare 전환 트랜잭션

`EMERGENCY_PROXY` 전환은 다음 단계를 개별 기록하는 재개 가능한 트랜잭션입니다.

1. 로컬 고비용 경로 제한과 확인
2. 현재 DNS record와 원본 방화벽 snapshot 저장
3. Cloudflare proxied 요청
4. DNS API read-back 확인
5. 외부 HTTPS probe로 프록시 경유 확인
6. 원본 80/443 보호 규칙 적용
7. 원본 직접 접근과 프록시 경유 접근 재검증
8. 상태 완료 기록

5단계 전에 원본을 Cloudflare 대역만 허용하도록 잠그는 것을 금지합니다. 부분 실패 시 성공한 단계와 복구 명령을 리포트하며, SSH 규칙은 어떠한 단계에서도 변경하지 않습니다.

복구는 저장된 snapshot을 기반으로 역순 수행하고 각 단계가 실제로 복구됐는지 read-back 합니다.

## 11. TLS와 인증서

- edge가 public TLS를 종료합니다.
- MVP 인증서는 Certbot 또는 검증된 외부 ACME 클라이언트가 발급합니다.
- 기존 Certbot timer·renewal 설정이나 다른 인증서 관리 수단이 있으면 소유권을 빼앗거나 재설정하지 않고 감지·검증해 그대로 사용합니다.
- edge 시작 때마다 설정된 cert/key 일치, SAN과 현재 유효기간을 검사하되 package 설치, 인증서 발급과 timer 활성화를 startup 부작용으로 실행하지 않습니다.
- 자동 갱신 수단이 없을 때만 관리 UI·CLI가 plan과 명시적 승인을 거쳐 Certbot 설치·발급·timer·deploy hook 구성을 보조할 수 있습니다. VPSGuard는 ACME protocol과 private key 저장소를 직접 구현하지 않습니다.
- 초기 발급은 HTTP-01 webroot를 기본으로 하고 wildcard 등 DNS-01이 필요한 경우 provider별 별도 자격증명을 사용합니다.
- edge는 PEM 경로를 설정으로 받고 시작 전에 cert/key 일치와 유효기간을 검사합니다.
- 갱신 hook은 새 인증서를 검증한 뒤 graceful reload합니다.
- 갱신 실패, 만료 임박과 현재 제공 중인 인증서 불일치를 이벤트로 기록합니다.
- 인증서와 개인키를 reset, update 또는 bypass 과정에서 삭제하지 않습니다.

## 12. 비상 bypass

edge가 반복 실패할 때 기존 Nginx가 public 80/443을 회수할 수 있어야 합니다.

`vps-guard bypass enable` 계약:

1. Nginx public 후보 설정 생성
2. 후보 설정 문법 검사
3. 기존 설정과 인증서 snapshot
4. edge 중지
5. Nginx public 설정 원자 적용·기동
6. HTTP/HTTPS probe
7. 실패 시 Nginx 변경 복구 후 edge 재기동

`bypass disable`은 edge 후보를 먼저 별도 포트에서 검증한 뒤 역순으로 복귀합니다. 이 경로는 릴리스마다 실제 VPS 하네스로 검증해야 합니다.

## 13. 데이터와 파일 위치

| 경로 | 내용 | 권한 원칙 |
|---|---|---|
| `/etc/vps-guard/config.toml` | 비밀값 없는 사용자 설정 | root write, service read |
| `/etc/vps-guard/secrets/` | API token과 비밀값 | root 전용 |
| `/var/lib/vps-guard/state.json` | 상태 머신과 실행 상태 | 원자 저장 |
| `/var/lib/vps-guard/policy.json` | 마지막 정상 정책 snapshot | hash·schema 검증 |
| `/var/lib/vps-guard/events/` | 보존할 사건 기록 | 기간·크기 제한 |
| `/var/backups/vps-guard/` | 전환·bypass 복구 snapshot | root 전용 |
| systemd journal | edge·control 구조화 운영 로그 | unit별 rate limit, 비밀값 마스킹, host 보존 정책 존중 |
| `/run/vps-guard/` | PID, socket과 임시 런타임 상태 | tmpfiles 관리 |

상태와 정책은 temp file write, fsync, rename, parent directory fsync 순서로 저장합니다.

## 14. 보안 불변조건

다음 조건은 기능보다 우선합니다.

1. SSH port와 현재 관리 접속 규칙은 자동 변경하지 않습니다.
2. Cloudflare token, 인증서 private key와 애플리케이션 비밀은 로그·API·UI에 출력하지 않습니다.
3. 외부 명령은 shell 문자열이 아니라 검증된 argv로 실행합니다.
4. provider 조치는 최소 권한 token과 allowlisted zone·record·instance에만 수행합니다.
5. 정책 schema, hash와 범위를 검증하지 못하면 적용하지 않습니다.
6. 새로운 정책 실패가 마지막 정상 정책을 제거하면 안 됩니다.
7. control·agent 장애가 edge 정상 요청 처리 실패로 전파되면 안 됩니다.
8. 기존 Nginx/Apache 설정은 snapshot 없이 변경하지 않습니다.
9. 영구 IP 차단은 MVP에서 금지하고 모든 자동 차단에 TTL을 둡니다.
10. 자동 조치는 이유, 입력 신호, 결과와 복구 정보를 남겨야 합니다.

## 15. 관리 UI 경계

- 기본 bind는 loopback입니다.
- 일상 접속은 edge의 별도 HTTPS 관리 Host를 사용하며 관리 포트를 public 방화벽에 열지 않습니다.
- 관리 Host는 애플리케이션 origin으로 fallback하지 않고 SSH는 초기 코드 발급과 복구에만 사용합니다.
- 서버 root 비밀번호를 웹으로 받지 않습니다.
- Linux·SSH 계정과 분리된 단일 VPSGuard 관리자 ID를 사용하며 비밀번호는 Argon2id verifier로만 저장합니다.
- peer credential이 확인된 local admin socket의 one-time code는 최초 관리자·TOTP 등록과 break-glass 복구에만 사용하고 일상 접속은 관리자 비밀번호와 TOTP를 요구합니다.
- TOTP seed는 비밀번호 유래 key로 AEAD 봉인하고 복구 코드는 hash만 저장해 성공 즉시 소비합니다.
- 운영 session은 원문 cookie·CSRF 없이 bounded SQLite에 영속화하고 Secure·HttpOnly·SameSite=Strict cookie, 명시적 logout과 actor 전체 폐기를 제공합니다.
- 로그인 코드는 운영 명령에 사용할 수 없고 모든 변경에는 Origin·CSRF·idempotency 검사가 필요합니다.
- 상태 조회와 사건 스트림은 읽기 권한, 방어·복구 명령은 별도 재확인 권한을 요구합니다.
- 파괴적 또는 연결 경로 변경 명령은 영향 범위, 현재 snapshot과 예상 복구를 모달에 표시합니다.

초기 API와 UI 계약은 [요구사항과 계약](06-requirements-contracts.md)에 정의합니다.

## 16. 관측성과 설명 가능성

모든 자동 판정은 다음 질문에 답해야 합니다.

- 무엇이 평시와 달라졌는가
- 어느 주체와 경로가 자원을 사용했는가
- PHP·DB·Redis·OS에 어떤 영향이 있었는가
- 어떤 조치를 왜 선택했는가
- 조치 후 지표가 개선됐는가
- 언제 어떤 조건으로 복구하는가

원시 로그 나열만으로 성공 처리하지 않습니다. UI와 리포트에는 사람이 읽을 수 있는 사건 요약과 근거를 함께 제공합니다.

## 17. 완료 정의

MVP 완료는 코드 작성이 아니라 다음 증거가 모두 있을 때입니다.

- 요구사항 ID별 구현·테스트 추적 완료
- 기존 월척 프록시보다 기능·안전 회귀가 없음
- 정상 직접 요청의 추가 지연이 승인된 성능 예산 이내
- GnuBoard 파일럿에서 봇 시나리오가 PHP·DB 포화 전에 제한됨
- 정상 브라우저·검증된 검색봇 시나리오의 오탐 허용 기준 충족
- Cloudflare 전환·부분 실패·복구 하네스 통과
- 인증서 갱신과 edge bypass 실제 VPS 하네스 통과
- x86_64·aarch64 릴리스와 checksum·SBOM 생성
- 운영자 UI가 조치 이유와 현재 실제 상태를 일관되게 표시

세부 품질 기준은 [검증 추적표](07-verification-traceability.md)를 따릅니다.

## 18. 공개 전 보류 조건

- edge가 public TLS를 안정적으로 처리하지 못함
- 정상 사용자 오탐이 파일럿 기준을 넘음
- provider 부분 실패 후 자동 복구가 불확실함
- bypass가 실제 VPS에서 재현 가능하지 않음
- hot path가 control이나 디스크에 동기 의존함
- 절감 효과를 서버 지표로 설명할 수 없음
- 공개 지원 조합별 설치·업데이트·제거 증거가 없음

## 19. 제품 결정 상태

제품명, 바이너리·서비스명, UI 포트, 원본 IP 기본 보존기간과 첫 파일럿은 [초기 구현 결정](10-bootstrap-decisions.md)에서 확정합니다. Community/Pro 공개 라이선스와 첫 Cloudflare test zone은 파일럿 외부 공개 전까지 보류합니다.

## 20. 연결 문서

- [요구사항과 계약](06-requirements-contracts.md)
- [검증 추적표](07-verification-traceability.md)
- [구현 백로그](08-implementation-backlog.md)
- [기존 소스 재사용](04-architecture-reuse.md)
- [탐지 모델](03-detection-model.md)
