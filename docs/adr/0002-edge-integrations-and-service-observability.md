# ADR 0002: 외부 연동, protocol mode와 핵심 service 관측

- 상태: 승인
- 날짜: 2026-07-15
- 요구사항: EDGE-013, OBS-011, TLS-006, NFR-008, ACT-006, SEC-004

## 문맥

VPSGuard는 public HTTP gateway이지만 범용 L4 proxy, ACME client, DB protocol 구현체나 전체 서버 관리 패널은 아닙니다. 현재 코드는 Certbot deploy hook을 제공하고, Nginx/PHP-FPM HTTP 200, MySQL TCP connect, Redis PING과 서버 전체 `/proc` 값만 수집합니다. 서비스별 CPU·memory·I/O와 실제 PHP·DB·Redis 병목 지표는 아직 구현되지 않았습니다.

## 결정

### 인증서

- `external_managed`, `vpsguard_assisted`, `manual` 갱신 소유 상태를 구분합니다.
- 기존 Certbot timer·renewal 설정 또는 다른 외부 관리 수단이 있으면 `external_managed`로 감지하고 그대로 사용합니다.
- edge startup은 cert/key/SAN/유효기간만 검사하며 package 설치, 발급, 기존 timer와 renewal 설정 변경을 하지 않습니다.
- 자동 갱신 수단이 없을 때만 UI·CLI에서 사용자가 plan을 승인하면 `vpsguard_assisted` 경로를 제공합니다.
- ACME protocol은 직접 구현하지 않고 Ubuntu 1차 지원 환경의 Certbot을 typed command adapter로 실행합니다.
- HTTP-01 webroot 발급, systemd timer 갱신과 successful renewal 뒤 deploy hook을 기본 경로로 사용합니다.
- wildcard의 DNS-01 token은 VPSGuard 비상 전환 token과 분리합니다.
- VPSGuard는 발급 plan, cert/key/SAN/만료 preflight, served certificate read-back과 실패 사건을 소유하되 private key와 ACME account secret은 소유하지 않습니다.

### protocol과 분석 mode

- 공개 지원은 HTTP/1.1, HTTP/2와 WebSocket으로 제한하고 지원 선언마다 E2E 증거를 요구합니다.
- `profiled`는 app profile과 행동 신호를 사용합니다.
- `protocol_only`는 app profile·행동 판정을 생략하지만 TLS·Host·forwarded header, 연결·body·timeout 상한과 bounded 계측은 유지합니다.
- WebSocket frame payload, 업로드 body와 응답 body의 범용 DPI는 하지 않습니다.
- raw TCP/TLS pass-through와 임의 TCP/UDP service는 범위 밖입니다.
- TCP 80/443 외 port는 intercept하지 않아 기존 SSH·DB·mail·사용자 service가 그대로 동작합니다. 소유 port의 비HTTP protocol은 거부하고, 같은 443의 raw TLS multiplex는 별도 L4 요구사항으로만 검토합니다.

### service 관측

- 모든 systemd unit과 process를 감사하지 않습니다.
- Nginx/Apache, PHP-FPM, MySQL/MariaDB, Redis와 VPSGuard처럼 HTTP 처리 핵심 경로에 있는 service 후보만 읽기 전용으로 발견하고 관리자가 확정한 allowlist만 수집합니다.
- service resource는 process 이름 합산보다 systemd unit의 cgroup v2 `cpu.stat`, `memory.current`, `memory.events`, `io.stat`, `pids.current`를 기준으로 합니다.
- PHP-FPM queue, DB connection·lock wait, Redis memory·client·eviction 같은 semantic metric과 cgroup resource를 같은 시간축에 둡니다.
- 수집은 control/agent의 저주기 out-of-band 작업이며 edge hot path에 넣지 않습니다.

### dependency 선택

| 영역 | 결정 |
|---|---|
| HTTP proxy | Pingora 유지. 지원 protocol과 성능은 실제 E2E로 검증 |
| ACME | Certbot 외부 client 사용. ACME wire protocol 직접 구현 금지 |
| HTTP status 수집 | 수동 `TcpStream` HTTP parser를 `reqwest` 기반 bounded client로 교체 |
| Redis | 인증·TLS·RESP·timeout은 `redis` crate를 사용하고 직접 RESP 구현 금지 |
| MySQL/MariaDB | 유지보수되는 async MySQL driver를 feature 최소화해 사용하고 TCP connect만으로 정상 판정 금지 |
| systemd/cgroup | unit 발견·ControlGroup 조회는 `zbus` 후보를 우선 spike하고, 안정된 cgroup v2 숫자 파일은 작은 typed bounded parser로 처리 |
| GeoIP/ASN | network API 대신 `maxminddb` 계열 local reader 사용 |
| TLS/X.509 | `rustls`와 검증된 X.509 parser 사용. 직접 ASN.1·PEM parser 구현 금지 |
| Cloudflare | 현재 필요한 DNS list/PATCH가 작고 공식 `cloudflare-rs`도 WIP를 명시하므로 우선 typed `reqwest` adapter를 유지. SDK는 권한·API coverage·dependency fanout spike가 우월할 때만 교체 |
| Nginx/PHP status text | HTTP transport는 crate를 쓰고 작고 bounded된 domain parser만 직접 유지 |
| rate limit·policy·atomic state·owned nftables | VPSGuard 고유 bounded·read-back·ownership 불변조건이므로 직접 typed model 유지 |

새 crate를 고르는 것 자체가 목적은 아닙니다. protocol·crypto·database driver처럼 재구현 위험이 큰 곳은 외부 구현을 우선하고, 작은 고정 형식과 제품 고유 상태 전이는 의존성 fanout·RSS·공격면을 비교해 결정합니다.

### 로그와 분석 데이터

- operational log는 structured journald, traffic 분석은 bounded telemetry와 SQLite로 분리합니다.
- request 완료를 기본 `info`로 매번 남기지 않고 debug sampling 또는 사건 evidence로 제한합니다.
- edge는 원본 query·header·body를 전송하지 않으며 control persistence queue가 차면 요청을 막지 않고 drop counter를 증가시킵니다.
- SQLite writer는 전용 blocking thread에서 batch transaction을 사용하고 `raw detail -> 10초 -> 1분` rollup을 생성합니다.
- 상세·raw IP client·aggregate·incident·audit retention을 각각 실행하며 bounded delete, WAL checkpoint, DB/WAL 크기와 disk pressure를 관측합니다.

## 현재 dependency audit

- Cloudflare bearer token은 `secrecy 0.10.3`의 `SecretString`으로 보관해 `Debug` 노출을 막고 drop 시 zeroize합니다. crate는 MIT/Apache-2.0, MSRV 1.60, `unsafe` 금지이며 기존 lockfile의 `zeroize`를 재사용합니다.
- Cloudflare fake API 실패·rollback 검증에만 dev dependency `mockito 1.7.2`를 기본 feature 없이 사용합니다. production binary에는 포함되지 않습니다.
- `vps-guard-control` macOS release binary는 적용 전 7,207,616 bytes에서 적용 후 7,240,848 bytes로 33,232 bytes(0.46%) 증가했습니다. 2GB Linux VPS RSS 차이는 release gate에 남깁니다.
- 공통 TLS lifecycle 관측은 이미 workspace에 있던 `rustls`, `rustls-pemfile`, `x509-parser`를 `guard-system` adapter로 이동해 재사용하며 새 runtime crate version을 추가하지 않습니다. Control release binary는 Cloudflare 배치 기준 7,240,848 bytes에서 7,460,784 bytes로 219,936 bytes(3.04%) 증가했습니다. 2GB Linux VPS RSS와 systemd credential 실증은 release gate에 남깁니다.
- filesystem 여유는 OS별 `statvfs` ABI를 직접 구현하지 않고 `rustix 1.1.4`의 safe API를 사용합니다. MIT/Apache-2.0, MSRV 1.63이며 이미 lockfile에 있던 version을 직접 의존성으로 승격해 전이 crate는 늘지 않았습니다. 저장 배치 후 Control release binary는 7,460,784 bytes에서 7,527,824 bytes로 67,040 bytes(0.90%) 증가했고 SHA-256은 `d44a2a9805610192705a34ec132109115549801361af693572bf7bcfc3e8fafb`입니다. 2GB Linux VPS RSS와 disk-full fault는 release gate에 남깁니다.
- MySQL wire/auth protocol은 `mysql_async 0.37.0`을 default feature 없이 `minimal-rust`로 사용합니다. MIT/Apache-2.0이며 crate metadata에 MSRV가 명시되지 않아 workspace Rust 1.96 build·clippy로 검증합니다. direct crate source에는 4개 파일의 5개 `unsafe` block이 있고 VPSGuard adapter는 URL·credential·query·timeout을 좁힌 safe API만 호출합니다.
- Redis RESP/auth protocol은 `redis 0.32.7`을 default feature 없이 `tokio-comp`만 켜 사용합니다. BSD-3-Clause, MSRV 1.80이며 direct crate source에 `unsafe` block이 없습니다. 최신 1.4.0은 이 사용 범위와 무관한 unconditional `xxhash-rust`의 BSL-1.0 license가 repository policy를 위반해 제외했습니다. adapter는 loopback URL과 `PING`, `INFO`만 허용합니다.
- 두 driver와 공통 `url` 검증을 추가하면서 lockfile production package가 10개 늘었습니다. Control macOS release binary는 7,527,824 bytes에서 9,343,696 bytes로 1,815,872 bytes(24.12%) 증가했고 SHA-256은 `661bf6347c430a39acb47dd65905a73e2682a87d8606f870221900eabf5f842c`입니다. wire protocol·인증을 직접 구현하지 않는 안전성과 교환한 증가이며 9.34MB absolute 크기는 유지하되, 2GB Linux RSS·5초 probe 비용이 256MB 합산 상한을 넘으면 collector 별도 프로세스 또는 feature 분리를 재검토합니다.
- `cargo audit`: 허용되지 않은 알려진 취약점은 없고 Pingora 경로의 unmaintained `daemonize`, `derivative`, `rustls-pemfile` 경고 3건이 예외 문서로 추적됩니다.
- `rustls-pemfile`은 VPSGuard도 직접 사용하므로 유지보수되는 rustls pki type 경로로 교체 가능한지 우선 확인합니다. Pingora 전이 의존성 제거는 upstream 갱신과 별도입니다.
- `cargo deny check`: 통과했으며 Pingora 중심의 중복 version은 계속 측정합니다.
- `cargo machete`: 사용하지 않는 workspace 직접 의존성이 없습니다.

## 결과

- `guard-agent`는 명시된 최대 16개 unit의 cgroup v2와 service semantic metric을 수집합니다. PHP-FPM·cgroup fixture는 자동 검증됐지만 MySQL·Redis 최소 권한과 2GB VPS 실제 unit 대조 전에는 운영 완료가 아닙니다.
- `profiled`와 `protocol_only`는 enforcement의 `observe`와 `enforce`와 독립된 typed 설정으로 구현해야 합니다.
- 인증서 자동화는 필요하지만 자체 ACME 구현 backlog는 만들지 않습니다.
- dependency 변경 PR은 maintenance, license, advisory, MSRV, unsafe, transitive dependency와 2GB VPS binary/RSS 차이를 기록합니다.
