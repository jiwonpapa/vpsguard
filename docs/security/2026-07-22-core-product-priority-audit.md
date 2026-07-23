# VPSGuard 범용 트래픽 보호 MVP 재점검

- 점검일: 2026-07-22
- 범위: 저장소 코드, 제품 계약, 로컬 자동 검증
- 제외: 실제 서버 설치·ingress 전환, 공인 TLS, Cloudflare 실계정, 인터넷 공격·온라인 배포 증거
- 제품 전제: GnuBoard 5 전용이 아닌 범용 HTTP reverse proxy. MVP는 단일 origin·단일 서비스 hostname을 우선 지원

> 2026-07-23 후속 조치: `OBS-014` generic HTTPS webhook, event ID 영속
> dedupe, bounded queue·retry, 재시작 재개와 관리자 read-back을 구현해 자동 gate를
> 통과했습니다. SMTP adapter와 실제 외부 receiver·2GB VPS 증거는 후속 release
> gate로 남습니다.

## 결론

VPSGuard의 1차 제품 목표는 **범용 WAF가 아니라 트래픽 관측·기록, 봇과 과도한 요청의 로컬 억제, 서버 과부하 시 Cloudflare proxy 자동 활성화, 관리자 통지와 승인 기반 해제**로 고정하는 것이 맞습니다.

현재 Pingora forwarding, HTTP 안전 불변조건, bounded rate limiter, SQLite traffic 저장, 상태 머신과 Cloudflare 단계별 transaction의 기반은 있습니다. 그러나 1차 목표 기준 MVP 완료 상태는 아닙니다. 다음 여섯 항목이 출시 차단 항목입니다.

1. 범용 `protocol_only` mode에서 봇 차단·rate limit·incident 정책이 모두 비활성화됩니다.
2. 자동 탐지가 실제 CPU·memory·PHP·DB 수치를 사용하지 않고 collector 존재 여부만 사용합니다. 일반 경로의 단순 대량 요청만으로는 보호 전이가 안정적으로 발생하지 않습니다.
3. rate limiter가 요청 횟수만 제한하고 egress bytes와 동시 연결을 제한하지 않습니다.
4. 상태 전이·Cloudflare 성공·실패·복구 준비를 외부로 알리는 notification provider가 없습니다.
5. Cloudflare 해제가 관리자 승인 없이 짧은 안정 window 뒤 자동 실행됩니다.
6. DNS-only에서 proxy ON으로 바꿀 때 기존 DNS cache가 남는 시간을 계산하지 않고 origin을 잠급니다.

따라서 WAF 기능 확장보다 위 네 항목과 traffic 관측 정확도를 먼저 완성해야 합니다.

## 제품 경계

### 1차 MVP

- HTTP/1.1·HTTP/2·WebSocket reverse proxy
- Host·request framing·body·timeout·forwarded identity의 안전 경계
- 실시간 RPS, 활성 연결, HTTP payload bytes, status, latency, top client·route·bot 분류
- bounded SQLite detail·rollup·incident·audit 보존
- 허용 검색 crawler 검증, 미허용 declared AI bot 차단
- client·network prefix·route·listener 전체 계층 rate limit
- edge traffic과 OS·origin pressure를 결합한 설명 가능한 상태 전이
- `NORMAL -> WATCH -> LOCAL_GUARD -> EMERGENCY_PROXY` 자동 승격
- Cloudflare proxy ON과 origin 80/443 보호의 단계별 read-back·rollback
- 상태 전이·조치 성공·실패·복구 준비 notification
- Cloudflare OFF는 기본적으로 관리자 재확인 뒤 snapshot 복구

### 2차 보조 보안

- app profile별 auth·search·upload 가중치
- CSP·HSTS·version header 제거
- standalone UFW 관리
- 외부 ModSecurity·OWASP CRS adapter
- SQL injection·XSS signature 검사는 WAF가 켜진 설치에서만 보조 보호

### 비목표

- origin의 prepared query, 입력 검증, escaping, CSRF와 계정 보안 대체
- 모든 unknown·위장 봇 식별 보장
- L3/L4 대규모 DDoS 흡수
- payload 전수 저장·DPI·SIEM·백신
- WAF를 기본 강제로 켜서 정상 서비스를 위험하게 만드는 구성

WAF는 기본 `off`, 선택 시 `detection`부터 시작해야 합니다. app 정상 흐름의 오탐 fixture 없이 `tuned_enforce`로 올리면 안 되며, WAF 완료 여부는 1차 MVP 출시 gate에서 분리합니다.

## 현재 구현 판정

| 영역 | 판정 | 근거 |
|---|---|---|
| 범용 HTTP forwarding | 준비 | Pingora streaming proxy, H1/H2/WebSocket 계약과 로컬 integration gate 존재 |
| HTTP 기본 hardening | 준비 | Host allowlist, ambiguous framing 거부, 위험 method 거부, body·upstream timeout |
| traffic 수집·SQLite | 부분 준비 | status·latency·client·route·body bytes·decision·policy version과 1초/10초/1분 rollup 존재 |
| 범용 봇·과다 요청 차단 | 미완성 | `protocol_only`가 동적 보호 전체를 끔 |
| egress·동시 연결 보호 | 미구현 | request count limiter만 있고 byte·concurrency budget 없음 |
| 서버 부하 연계 탐지 | 미완성 | 실제 resource 값 대신 availability boolean만 사용 |
| Cloudflare 자동 ON | 코드 경로 존재 | provider transaction은 있으나 핵심 trigger와 DNS TTL 전환 경계가 불완전함 |
| 관리자 notification | 미구현 | 설정 schema, provider, retry·dedupe, UI가 없음 |
| Cloudflare 승인 기반 OFF | 목표와 불일치 | 현재 자동 recovery가 provider snapshot을 즉시 복구함 |
| 범용 WAF | 의도적으로 비목표 | 현재는 Apache ModSecurity·CRS 외부 adapter이며 GnuBoard fixture 중심 |
| 로컬 회귀 gate | 통과 | `bash scripts/check.sh`: Rust·docs·dependency·Bun build/test gate PASS |
| coverage gate | 실패 | `guard-edge/src/proxy.rs` named-file coverage가 최소 기준 미달 |

## 핵심 발견사항

### VG-CORE-001 — MVP blocker — 범용 mode에서 핵심 보호가 꺼짐

- `InspectionMode::ProtocolOnly`는 app profile만 생략하는 mode로 설명되지만, `EdgeRuntimeConfig::enforces_dynamic_protection()`은 `profiled+enforce`에서만 true입니다 (`crates/guard-edge/src/runtime.rs:296`, `crates/guard-edge/src/runtime.rs:354`, `crates/guard-edge/src/runtime.rs:383`).
- 그 결과 declared bot 거부, client policy deny·challenge·throttle과 모든 일반·strict·upload rate limit이 실행되지 않습니다 (`crates/guard-edge/src/proxy.rs:212`, `crates/guard-edge/src/proxy.rs:305`, `crates/guard-edge/src/proxy.rs:359`).
- 현재 지원 app profile은 PHP, GnuBoard 5·7, WordPress뿐입니다 (`crates/guard-core/src/config.rs:434`, `crates/guard-profiles/src/lib.rs:5`). Node.js, Go, Python, Java와 범용 API를 보호할 올바른 profile이 없습니다.

조치: app 분석과 공통 보호를 분리합니다. `enforce`에서는 inspection mode와 무관하게 declared bot 정책, client·prefix·route·global rate limit과 incident policy를 적용합니다. `profiled`는 auth·search·upload 비용 가중치만 추가해야 합니다. 별도 `generic_http` profile과 설정 가능한 route class override를 추가합니다.

### VG-CORE-002 — MVP blocker — 과부하 탐지가 실제 서버 부하를 사용하지 않음

- 5초 detection loop는 OS snapshot의 존재 여부만 `resources_available`로 넘깁니다 (`crates/guard-control/src/runtime.rs:492`, `crates/guard-control/src/runtime.rs:498`).
- 탐지 입력은 traffic window의 요청 수, 기존 보호 판정 비율, 5xx, 최대 route cost와 최대 latency만 사용하고 trust=40, session=false, crawler=false를 고정합니다 (`crates/guard-control/src/telemetry.rs:308`).
- CPU, memory, load average, Nginx active connection, PHP worker, DB connection·lock·latency는 전환 점수에 들어가지 않습니다.
- 5초에 500건 이상인 일반 저비용 경로는 automation 점수만 올라가고 cost가 낮으면 `Observe`에 머물 수 있습니다 (`crates/guard-core/src/detection.rs:131`). 대량 traffic 자체가 `LOCAL_GUARD`와 `EMERGENCY_PROXY`를 보장하지 않습니다.

조치: edge RPS·payload rate·활성 연결·5xx·p95 latency와 OS CPU·memory·load를 공통 신호로 사용합니다. PHP·DB·Redis는 설치된 경우에만 보강 신호로 사용합니다. 절대 안전 한도와 적응형 기준선을 분리하고 두 개 이상 신호가 연속 window에서 확인될 때 승격합니다.

### VG-CORE-003 — MVP blocker — 응답 traffic과 동시 연결을 제어하지 못함

- 현재 `RateLimitPolicy`는 client·prefix·route·global의 requests per minute만 가집니다 (`crates/guard-edge/src/rate_limit.rs:64`).
- request와 response body bytes는 사후 telemetry로 기록하지만 byte budget 판정에는 사용하지 않습니다 (`crates/guard-edge/src/proxy.rs:685`). active downstream request·connection 상한도 edge 정책에 없습니다.
- 따라서 큰 응답, download 또는 오래 유지되는 connection은 낮은 요청 횟수로도 egress와 worker·socket 자원을 소모할 수 있습니다.

조치: bounded client·prefix·route·listener 계층에 request token, egress byte token과 concurrent in-flight budget을 분리합니다. `Content-Length`가 있으면 전달 전 예산을 확인하고 streaming response는 chunk별 사용량을 debit합니다. download·media·WebSocket은 별도 site policy와 정상 이용자 예외를 두며, UI에는 request rate와 egress rate를 따로 표시합니다.

### VG-CORE-004 — MVP blocker — 관리자 notification이 없음

- 제품 UI 문서에는 알림 설정이 있으나 실제 `GuardConfig`에 notification 설정이 없고 runtime에는 발송 adapter가 없습니다 (`specs/product/09-monitoring-web-ui.md:291`, `crates/guard-core/src/config.rs:16`).
- 현재 전이 결과는 SQLite event와 접속 중인 SSE 구독자에게만 전달됩니다 (`crates/guard-control/src/runtime.rs:637`). 관리자가 화면을 보고 있지 않으면 Cloudflare 전환·실패를 알 수 없습니다.

조치: generic HTTPS webhook을 MVP 기본 adapter로, SMTP email을 선택 adapter로 제공합니다. `LOCAL_GUARD`, Cloudflare 시작·완료·실패, `RECOVERY_READY`, 수동 복구 완료를 발송하고 event ID 기반 dedupe, bounded retry, 마지막 성공·실패 read-back을 저장합니다. 알림 실패가 edge나 provider 조치를 막아서는 안 됩니다.

### VG-CORE-005 — MVP blocker — Cloudflare 해제가 너무 공격적으로 자동화됨

- `EMERGENCY_PROXY`는 5개의 안정 window 뒤 `RECOVERING`으로 전환하고 runtime이 즉시 provider restore를 실행합니다 (`crates/guard-core/src/state.rs:132`, `crates/guard-control/src/runtime.rs:576`). 현재 5초 loop 기준 약 25초입니다.
- Cloudflare를 DNS only로 돌리면 HTTP/HTTPS traffic이 다시 origin으로 직접 가고 Cloudflare proxy 보호가 제거됩니다. Cloudflare도 proxied record와 DNS-only record의 보안·노출 차이를 명시합니다.

조치: 자동 승격과 자동 해제를 비대칭으로 둡니다. 안정 구간 충족 시 Cloudflare를 유지한 채 `RECOVERY_READY`를 기록·통지하고, 관리 UI의 영향 설명·재확인·idempotency를 거쳐서만 restore합니다. `auto_restore`는 후속 opt-in 기능으로 분리하고 기본 false로 둡니다.

공식 참고: [Cloudflare proxy status](https://developers.cloudflare.com/dns/proxy-status/), [Cloudflare DNS record API](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/edit/)

### VG-CORE-006 — MVP blocker — DNS 전환 cache와 origin lock 사이의 정상 이용자 공백

- DNS-only record를 proxy ON으로 바꿔도 기존 resolver가 origin 주소를 이전 TTL 동안 사용할 수 있습니다. Cloudflare 공식 문서도 proxied record의 Auto TTL이 기본 300초이며 DNS cache 때문에 상태 전환이 즉시 모든 client에 반영되지는 않는다고 설명합니다.
- 현재 `DnsRecord` read-back model은 `proxied`와 `proxiable`만 읽고 TTL을 저장하지 않습니다 (`crates/guard-provider/src/cloudflare.rs:396`).
- provider는 `cf-ray`가 한 번 확인되면 바로 origin lock을 적용합니다 (`crates/guard-provider/src/lib.rs:219`, `crates/guard-provider/src/lib.rs:225`). 이전 DNS-only 응답을 캐시한 정상 이용자는 원본에 직접 도달했다가 차단될 수 있습니다.

조치: preflight와 snapshot에 실제 TTL을 포함하고, 평상시 DNS-only TTL 상한을 명시합니다. proxy 검증 뒤 `drain_deadline` 동안 로컬 보호를 유지한 뒤 origin lock을 적용하되, 서버 생존이 급한 경우 조기 lock과 예상 이용자 영향을 사건·notification에 명시합니다. local fake provider로 TTL 60·300·3600초와 조기 lock 정책을 시간 제어 테스트합니다.

공식 참고: [Cloudflare proxy status와 Auto TTL](https://developers.cloudflare.com/dns/proxy-status/), [Cloudflare DNS TTL](https://developers.cloudflare.com/dns/manage-dns-records/reference/ttl/)

### VG-CORE-007 — High — traffic DB가 봇 운영 분석에 부족하고 route cardinality가 완전히 bounded되지 않음

- 저장되는 값은 method, client IP, route class/key, status, latency, body bytes, decision과 policy version입니다 (`crates/guard-edge/src/telemetry.rs:32`). declared bot provider·검증 상태·차단 이유는 telemetry에 없습니다.
- UI의 bandwidth 표시는 실제 network bytes가 아니라 request·response body 합계입니다 (`web/src/pages/traffic.tsx:46`). header와 TLS overhead는 포함하지 않으므로 “HTTP payload”로 표시해야 합니다.
- `protocol_only`는 raw path를 route key로 사용합니다 (`crates/guard-edge/src/runtime.rs:296`). profiled mode도 숫자와 UUID만 `:id`로 바꿉니다 (`crates/guard-profiles/src/lib.rs:259`). 임의 문자열 path를 계속 보내면 SQLite rollup key가 계속 증가합니다 (`crates/guard-control/src/storage.rs:1110`).

조치: bot class·verification·reason을 bounded enum으로 기록하고 top bot·source·route와 차단 전후 traffic을 제공합니다. route key 길이·segment·고유 key 수를 제한하고 high-entropy segment와 overflow를 `:opaque`·`:other`로 합칩니다. active downstream connection과 현재 RPS를 별도 계측합니다.

### VG-CORE-008 — High — 범용 origin으로 전달되는 client identity header가 완전히 정리되지 않음

- edge는 검증된 client로 `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`, `X-Forwarded-Host`를 덮어씁니다 (`crates/guard-edge/src/proxy.rs:448`).
- 그러나 inbound RFC `Forwarded`, `CF-Connecting-IP`, `True-Client-IP` 같은 대체 identity header는 제거하지 않습니다. 이 header를 신뢰하는 origin framework에서는 공격자 입력이 남을 수 있습니다.

조치: inbound proxy identity header를 명시적 denylist로 모두 제거한 뒤 하나의 canonical set만 생성합니다. 필요하면 RFC `Forwarded`도 edge가 새로 생성하며, origin echo integration test에 모든 변형을 추가합니다.

### VG-CORE-009 — Medium — app route 분류 우회와 호환성 위험

- 정적 asset 판정이 path의 마지막 확장자만 확인하고 app의 auth·admin 판정보다 먼저 실행됩니다 (`crates/guard-profiles/src/lib.rs:103`, `crates/guard-profiles/src/lib.rs:239`). PATH_INFO를 허용하는 origin에서 `/wp-login.php/a.css` 같은 요청이 저비용 static으로 오분류될 수 있습니다.
- percent encoding, dot segment와 origin별 path 정규화 차이를 고려하지 않습니다.

조치: app profile은 보호를 강화하는 힌트로만 사용하고 공통 listener limit을 우회하지 못하게 합니다. 모호한 encoding을 거부하거나 분류 전 canonical view를 만들고 PATH_INFO·encoded path regression fixture를 추가합니다.

### VG-CORE-010 — Medium — 범용 배포 범위는 아직 단일 hostname 중심

- Cloudflare 활성 설정은 allowed host 하나와 동일 hostname의 최대 16개 A·AAAA 또는 단일 CNAME만 허용합니다 (`crates/guard-core/src/config.rs:1008`, `crates/guard-core/src/config.rs:1047`, `crates/guard-core/src/config.rs:1062`).
- edge TLS runtime은 인증서 한 개만 허용합니다 (`crates/guard-edge/src/runtime.rs:143`). SAN·wildcard 한 장으로 여러 host를 전달할 수는 있지만 host별 별도 인증서는 지원하지 않습니다.

판정: 이는 GnuBoard 종속은 아니며 “범용 app stack의 단일 서비스” MVP에는 허용 가능합니다. 다중 사이트·다중 zone 지원은 MVP 이후 별도 요구사항으로 둡니다.

## 로컬에서 닫아야 할 MVP 수용 기준

서버 설치나 Cloudflare 실계정 없이 다음을 모두 자동화할 수 있습니다.

1. generic HTTP fixture에서 declared AI bot, 회전 IP, 단일 IP burst, 고유 path flood와 정상 browser 혼합 replay
2. `protocol_only+enforce`에서도 declared bot 403, 일반·prefix·route·global 429와 정상 browser 성공
3. 큰 response, slow download와 WebSocket 혼합 fixture에서 egress·in-flight budget과 정상 download 예외 검증
4. synthetic CPU·memory·latency·5xx·connection pressure로 상태 전이와 히스테리시스 검증
5. fake Cloudflare backend로 자동 ON, DNS TTL drain, 조기 origin lock 영향, 단계별 실패·재개·rollback 검증
6. 안정화 후 provider가 유지되고 `RECOVERY_READY` notification만 발생하며 관리자 승인 전 restore 0회 검증
7. webhook·SMTP fake server로 retry, dedupe, redaction과 발송 실패 비차단 검증
8. 고유 path flood 뒤 edge·control memory, queue, SQLite route key 수가 설정 상한 안인지 검증
9. traffic UI에서 현재 RPS·연결·payload·status·latency·top bot/client/route와 notification 상태 검증
10. WAF off 상태에서 위 모든 1차 기능이 통과하고 정상 앱 요청의 내용·응답이 변하지 않는 회귀 검증

## 구현 우선순위

1. 제품 계약 수정: WAF를 2차로 내리고 generic protection, notification, 승인 복구 요구사항을 추가
2. generic protection 분리: `protocol_only`에서도 bot·rate limit·incident policy 활성
3. request·egress·concurrency의 bounded 다층 budget 추가
4. traffic·resource signal 재설계: 실제 수치, active connection, bot attribution, bounded route key
5. Cloudflare DNS TTL drain과 origin lock 정책 추가
6. recovery 정책 수정: 자동 OFF 제거, `RECOVERY_READY`와 관리자 승인
7. webhook·SMTP notification과 관리 UI 상태
8. 위 로컬 시나리오의 TDD·회귀 gate
9. 이후에만 선택형 WAF profile과 다중 hostname·multi-SNI 확장

## 하네스 상태

`bash scripts/check.sh`는 2026-07-22 현재 통과했습니다. Rust fmt·clippy·rustdoc·workspace test, dependency audit·deny·machete, 요구사항 gate, 운영 transaction fixture, Bun typecheck·unit test·production build를 포함합니다. 요구사항 정본은 총 119개이며 `PLANNED=10`, `CODE_ONLY=32`, `AUTO_PASS=62`, `VPS_PASS=15`입니다.

별도 coverage gate는 현재 `guard-edge/src/proxy.rs` named-file 최소 coverage를 충족하지 못합니다. 위 1차 목표 변경은 해당 hot path와 detection/runtime에 TDD를 먼저 추가한 뒤 구현해야 합니다.

## 최종 판정

VPSGuard는 GnuBoard 5 전용이 아닙니다. 다만 현재 범용성은 **HTTP 전달과 기본 hardening**에 가깝고, 형님이 정한 1차 가치인 **범용 봇·과다 traffic 방어, 부하 기반 Cloudflare 자동 ON, 외부 알림, 사람 승인 OFF**는 아직 완성되지 않았습니다.

WAF는 더 키우지 않아도 됩니다. 외부 adapter를 선택형 2차 기능으로 유지하고, 먼저 1차 traffic control loop와 관측·DB를 완성하는 것이 MVP의 올바른 마감선입니다.
