# VPSGuard 개발 헌법

이 문서는 VPSGuard의 코드, 문서, 테스트, 배포와 운영 변경이 따라야 하는 최상위 개발 원칙입니다. VPSGuard는 public 80/443과 TLS, 트래픽 판정, 방화벽과 외부 provider를 다루므로 기능 편의보다 가용성, 복구 가능성, 설명 가능성과 최소 권한을 우선합니다.

## 1. 목적 우선

- 제품 목적은 정상 사용자의 직접 연결 성능을 유지하면서 자원 고갈형 자동화 트래픽으로 인한 장애와 비용을 줄이는 것입니다.
- Cloudflare는 상시 CDN이 아니라 로컬 방어 한계를 넘을 때 사용하는 비상 방어망입니다.
- DDoS뿐 아니라 검색봇, AI 봇, 스크래퍼와 비정상 자동화 트래픽을 다룹니다.
- 요청 수보다 PHP-FPM, DB, Redis와 고비용 경로에 미친 실제 영향을 우선 판단합니다.
- 범용 웹서버, CDN, SIEM, 서버 패널과 애플리케이션 튜너를 만들지 않습니다.

## 2. 스펙 주도 개발

- 구현 전 계약의 정본은 `specs/product/MASTER_SDD.md`입니다.
- 모든 기능, 보안 정책과 운영 변경은 `EDGE`, `OBS`, `DET`, `ACT`, `TLS`, `UI`, `OPS`, `SEC`, `NFR` 요구사항 ID를 가져야 합니다.
- 요구사항 ID가 없는 기능 코드를 추가하지 않습니다.
- 코드 변경 PR과 커밋에는 관련 요구사항 ID와 검증 증거를 기록합니다.
- 요구사항 변경과 구현·테스트 변경은 같은 커밋 또는 같은 변경 묶음에서 처리합니다.
- 폐기한 요구사항 ID를 다른 의미로 재사용하지 않습니다.
- 구현이 시작되면 Rust 타입, 상태 전이, 설정 schema와 module rustdoc가 실행 정본입니다.
- 문서와 코드가 다르면 코드를 무조건 옳다고 간주하지 않고 계약 위반으로 차단한 뒤 둘을 함께 수정합니다.

## 3. 코드가 정본 문서

- 모든 Rust module 상단에는 `//!` module rustdoc를 작성합니다.
- public type, trait, state, error와 안전 관련 함수에는 `///` rustdoc를 작성합니다.
- rustdoc에는 목적, 불변조건, 실패 의미와 외부 부작용을 기록합니다.
- 상태 코드, reason code, 설정 기본값, 범위와 provider 단계는 Rust enum과 typed model로 정의합니다.
- README와 웹 UI는 코드의 정책을 복제해 새 정본을 만들지 않고 schema 또는 API 결과를 표시합니다.
- `RUSTDOCFLAGS="-D warnings"`와 `--document-private-items`를 품질 게이트로 사용합니다.

## 4. 저장소와 소유 경계

- VPSGuard 런타임 코드는 이 저장소만 소유합니다.
- G7 Installer, GnuBoard와 WordPress 원본 코드를 직접 수정하지 않습니다.
- 기존 월척 Pingora 코드는 기준 commit과 저작권·라이선스를 기록한 뒤 이관합니다.
- 이관 코드의 월척 domain, route, port, secret과 운영 경로를 제거합니다.
- 외부 의존성 코드나 기존 프로젝트 파일을 출처 없이 복사하지 않습니다.

## 5. 크레이트 경계

- `guard-cli`: 명령 파싱과 사용자 출력만 담당합니다.
- `guard-core`: 점수, 상태 머신, 정책, 사건과 provider transaction domain을 담당합니다.
- `guard-edge`: Pingora listener, request policy, proxy와 hot-path 계측만 담당합니다.
- `guard-control`: 저장, collector orchestration, versioned API, SSE와 UI asset을 담당합니다.
- `guard-system`: UFW·VPSGuard-owned nftables set, systemd, TLS 파일, Nginx와 원자 OS 작업을 담당합니다.
- `guard-provider`: Cloudflare와 VPS provider API adapter를 담당합니다.
- `guard-profiles`: GnuBoard·WordPress route와 비용 profile을 담당합니다.
- 크레이트 책임이 섞이면 새 기능보다 경계 복구를 먼저 합니다.

## 6. Edge hot path 불변조건

- 요청마다 control RPC, SQLite, 외부 DB, 파일 write 또는 외부 API를 동기 호출하지 않습니다.
- 요청 판정은 메모리에 적재된 검증된 마지막 정상 정책만 사용합니다.
- telemetry는 bounded non-blocking 경로로 전송하고 실패·drop을 계측합니다.
- client, route, header와 User-Agent cardinality에 명시적 상한을 둡니다.
- control, agent와 telemetry 장애가 정상 proxy 요청 실패로 전파되면 안 됩니다.
- 정책 reload는 schema, hash, expiry와 범위를 검증한 뒤 원자 교체합니다.
- 잘못된 새 정책 때문에 마지막 정상 정책을 제거하지 않습니다.

## 7. 안전과 복구

- SSH port와 현재 관리 접속 규칙을 자동 변경하지 않습니다.
- provider 전환, 방화벽, ingress, TLS와 bypass 작업 전 snapshot과 plan을 만듭니다.
- standalone mode는 VPSGuard 소유 comment가 있는 UFW rule과 VPSGuard-owned nftables set만 수정·삭제합니다.
- JW-agent 위임 mode에서는 firewall mutation을 실행하지 않고 소유자와 실제 상태만 표시합니다.
- 기존 Nginx/Apache 설정은 소유권과 snapshot 없이 덮어쓰지 않습니다.
- 상태, 정책과 transaction은 temp write, fsync, rename, parent fsync 순서로 원자 저장합니다.
- 모든 자동 IP 차단에는 TTL을 두며 MVP에서 영구 차단을 금지합니다.
- edge 반복 장애 시 기존 웹서버가 public 80/443을 회수하는 bypass를 제공합니다.
- bypass, update, uninstall과 reset은 인증서와 사이트 데이터를 보존합니다.
- rollback이 검증되지 않은 파괴 작업은 공개 기능으로 제공하지 않습니다.

## 8. 탐지 원칙

- trust, bot likelihood와 resource cost를 별도 계산합니다.
- User-Agent 하나로 봇이나 정상 검색엔진을 확정하지 않습니다.
- 정상 검색봇도 고비용 경로를 과도하게 사용하면 친화적인 속도 제한을 적용합니다.
- 단일 IP를 한 사람으로 간주하지 않고 session, prefix, ASN, route 행동을 함께 봅니다.
- 한 번의 spike만으로 Cloudflare 비상 전환을 실행하지 않습니다.
- collector 데이터가 누락되면 confidence를 낮추고 누락 사실을 표시합니다.
- 초기 판정은 규칙 기반이며 모든 결정에 사람이 읽을 수 있는 reason code를 남깁니다.
- 충분한 파일럿 데이터와 오탐 증거 없이 머신러닝을 도입하지 않습니다.

## 9. Provider와 외부 조치

- provider token은 최소 권한과 명시적 zone·record·instance allowlist를 사용합니다.
- API 요청 성공과 실제 상태 적용을 구분하고 read-back을 수행합니다.
- Cloudflare 프록시 경유가 확인되기 전에 원본을 Cloudflare IP만 허용하도록 잠그지 않습니다.
- 모든 외부 조치는 idempotency key와 재개 가능한 단계 상태를 가집니다.
- 부분 실패는 성공으로 표시하지 않고 완료 단계, 실패 단계와 복구 방법을 보고합니다.
- provider 장애 중에는 로컬 보호를 유지하고 edge 요청 처리를 중단하지 않습니다.
- 복구는 저장된 snapshot을 기준으로 역순 실행하고 실제 복구 상태를 확인합니다.

## 10. TLS 원칙

- public TLS를 소유하는 edge는 시작 전에 cert/key 일치, 유효기간과 domain을 검사합니다.
- MVP에서 ACME 프로토콜을 직접 구현하지 않고 검증된 Certbot 또는 ACME client와 연동합니다.
- 새 인증서는 검증 후 graceful reload합니다.
- 파일 인증서와 실제 제공 중인 인증서를 비교합니다.
- private key를 로그, API, UI, state와 artifact에 출력하지 않습니다.
- 인증서 갱신 실패와 만료 임박을 일반 warning이 아니라 운영 사건으로 기록합니다.

## 11. 비밀값과 개인정보

- Cloudflare token과 비밀값은 root-only 전용 파일에 저장합니다.
- token, private key, cookie, authorization header와 application secret을 로그에 남기지 않습니다.
- request body와 원본 query 값을 기본 저장하지 않습니다.
- 원본 IP 보존기간과 집계 통계 보존기간을 분리합니다.
- 외부 GeoIP·ASN API를 request hot path에서 호출하지 않습니다.
- UI의 원본 IP 조회·내보내기와 방어 명령 권한을 분리합니다.
- server root 비밀번호와 SSH private key를 웹 UI로 받지 않습니다.

## 12. 웹 UI 원칙

- 독립 웹 UI는 부가 기능이 아니라 제품 운영 본체입니다.
- Control UI는 loopback에 bind하고 public 접속은 edge의 별도 HTTPS 관리 Host로만 제공합니다.
- Control 포트를 public에 열거나 관리 Host 요청을 애플리케이션 origin으로 fallback하지 않습니다.
- SSH는 초기 단회 로그인 코드 발급과 복구 경로로 유지하며 일상 UI 접속에 tunnel을 요구하지 않습니다.
- standalone Ubuntu 설치의 일상 인증은 Linux-PAM과 `vpsguard-admin` group allowlist를 사용하고 root·system·잠김·만료 계정을 거부하며 MFA와 일회용 복구 경로를 유지합니다.
- PAM 비밀번호는 저장·로그·재노출하지 않고 서버 계정·group·sudo 권한 자체를 웹에서 변경하지 않습니다.
- 비밀번호, TOTP seed, 복구 코드와 session 원문을 평문 저장하거나 로그·API에 다시 노출하지 않습니다.
- 실시간 트래픽, 외부 IP, route, server resource, provider, TLS와 사건 상태를 표시합니다.
- `주의`, `대기`, `실패`만 표시하지 않고 원인, 영향, 조치와 복구 조건을 설명합니다.
- stale, delayed, unavailable과 error를 정상값과 명확히 구분합니다.
- 파괴적 명령은 영향 범위, snapshot과 예상 복구를 보여주고 재확인합니다.
- 운영 콘솔은 CSR SPA로 제공하며 React·TypeScript, Tailwind CSS CLI와 선별한 shadcn/ui source component를 사용합니다.
- Bun과 Vite는 개발·CI asset build에만 사용하고 운영 VPS에는 JavaScript runtime을 설치하지 않습니다.
- SPA build 결과만 `guard-control` binary에 포함하며 원본 source asset을 직접 제공하지 않습니다.
- 범용 terminal, file manager, packet capture와 process manager를 UI에 추가하지 않습니다.

## 13. Rust 코드 원칙

- Rust stable과 Rust 2024 edition을 사용합니다.
- 서버에 Rust toolchain을 설치하지 않고 검증된 release artifact를 배포합니다.
- ACME, HTTP, TLS, DNS, DB와 Redis처럼 표준 프로토콜·암호·wire format을 다루는 기능은 유지보수되는 검증된 crate 또는 외부 client를 우선하고 임의로 재구현하지 않습니다.
- 새 외부 의존성은 유지보수 상태, license, RustSec, MSRV, `unsafe` 범위, 전이 의존성 수와 2GB VPS의 binary·RSS 영향을 기록한 뒤 선택합니다.
- 외부 crate는 project-owned typed adapter 뒤에 두고 timeout, 크기 상한, 최소 권한과 fake test를 적용합니다.
- 작은 bounded parser, VPSGuard 고유 상태 전이와 hot-path cardinality 불변조건은 범용 crate 도입이 더 큰 공격면이나 자원 비용을 만들면 직접 구현할 수 있으며 근거를 ADR에 기록합니다.
- `unwrap`, `expect`, `panic`을 production path에서 금지합니다.
- 실패는 typed error로 표현하고 문제, 원인, 영향, 다음 조치를 분리합니다.
- 비즈니스 로직과 외부 명령·HTTP·파일 부작용을 분리합니다.
- trait와 fake adapter로 provider, clock, DNS, filesystem과 command runner를 테스트 가능하게 만듭니다.
- `unsafe`는 금지가 기본이며 Pingora FFI 등 불가피한 경우 범위, 안전 근거와 전용 테스트를 문서화합니다.
- shell 문자열 조합보다 argv 전달을 사용합니다.

## 14. TDD와 테스트

- 요구사항 구현 전 실패하는 테스트 또는 contract fixture를 먼저 추가합니다.
- 상태 전이, 점수, 정책, TTL, provider transaction과 rollback은 unit test를 가집니다.
- Pingora proxy, TLS, upload, WebSocket과 Nginx upstream은 integration/E2E로 검증합니다.
- control kill, socket full, policy 손상, disk full, provider timeout과 bypass 실패를 장애 주입합니다.
- 정상 browser, shared IP, 검증 검색봇, 위조 검색봇과 scraper replay를 분리합니다.
- 자동 조치는 정상 fixture hard block 0건을 기본 release gate로 사용합니다.
- 성능은 동일 서버의 direct Nginx baseline과 비교하며 절대 수치만 보고하지 않습니다.
- 테스트를 삭제하거나 완화해 gate를 통과시키지 않습니다.

## 15. 커버리지와 품질 게이트

- release 목표는 `guard-core` 90%, provider transaction·rollback 90%, edge policy 85%, workspace 전체 80% 이상입니다.
- 개발 중 실측 baseline은 `scripts/coverage-gate.sh`의 영역별 ratchet으로 고정하고 한 줄도 하향하지 않습니다.
- process·network·kernel adapter의 낮은 unit coverage를 숨기지 않으며 integration·fault·VPS 증거와 함께 release 목표까지 올립니다.
- 커버리지 하향은 ADR, 누락 line과 보완 계획 없이는 금지합니다.
- `cargo fmt`, clippy `-D warnings`, rustdoc `-D warnings`, test, audit와 deny를 통과합니다.
- UI는 build, unit, Playwright E2E와 light/dark·desktop/mobile 시각 회귀를 통과합니다.
- 커버리지는 실제 VPS, TLS, provider와 bypass 증거를 대신하지 않습니다.

## 16. 성능과 자원

- 2GB VPS를 초기 기준 환경으로 사용합니다.
- direct Nginx 대비 edge p95 추가 지연과 처리량 감소에 release budget을 둡니다.
- edge, control, agent의 합산 RSS와 high-cardinality 안정성을 측정합니다.
- 메모리·map·queue·event와 UI 데이터는 무제한 성장할 수 없습니다.
- control restart와 policy reload 중 정상 proxy 오류 0건을 목표가 아니라 필수 gate로 둡니다.
- 성능 예산 변경은 benchmark artifact와 ADR을 요구합니다.
- 로컬·CI의 Cargo dev/test 산출물은 낮은 debug 정보와 incremental 비활성 profile로 디스크 누적을 제한합니다.
- 빌드 캐시 정리는 repository `target` 아래의 재생성 가능 항목만 삭제하며 release bundle과 검증 evidence는 보존합니다.

## 17. 외부 명령과 감사

- UFW, nftables, systemd, Nginx, Certbot과 OS 명령은 공통 command runner만 사용합니다.
- command, argv, 실행자, 시작·종료, exit code와 마스킹된 stderr를 기록합니다.
- stdin과 secret argument를 출력하지 않습니다.
- command runner는 fake와 failure injection을 지원합니다.
- shell, `sudo sh -c`와 임의 command template을 사용자 입력으로 만들지 않습니다.
- repository 거버넌스, fixture·fault·evidence 생성과 로컬·CI 오케스트레이션은 Python 3.11 이상 표준 라이브러리를 주력 언어로 사용합니다.
- public ingress, systemd, nftables와 root 소유 파일을 변경하는 production transaction은 Rust typed model과 `guard-system` adapter가 소유합니다. Python은 이를 직접 재구현하지 않습니다.
- Shell은 portable bootstrap, packaging hook과 기존 호환 adapter의 얇은 진입점으로 제한하고 line-count ratchet으로 신규 상태 머신과 문자열 command 조합의 증가를 차단합니다.
- 운영 VPS에는 Python package나 pip dependency를 설치하지 않으며 검증된 Rust release artifact만 production mutation을 수행합니다.

## 18. 설치·업데이트·릴리스

- 기존 운영 사이트에는 shadow mode로 먼저 설치합니다.
- public 80/443 cutover는 plan, 후보 설정 검사와 smoke 후 수행합니다.
- first install 기본값은 observe-only이며 자동 차단과 provider 전환은 명시적 opt-in입니다.
- x86_64와 aarch64 artifact, checksum, SBOM과 provenance를 배포합니다.
- update 전 현재 binary·config·state와 ingress snapshot을 저장합니다.
- update 실패 시 이전 binary와 정책으로 복구합니다.
- uninstall은 VPSGuard 소유 파일과 rule만 제거하고 사이트·인증서를 보존합니다.

## 19. 커밋과 변경 관리

- `spec`, `test`, `feat`, `fix`, `refactor`, `ops`, `release` 성격을 구분합니다.
- 한 커밋은 하나의 검증 가능한 목적을 가집니다.
- 단계별 exit gate가 통과할 때 커밋하며 마지막에 모든 작업을 한 커밋으로 묶지 않습니다.
- unrelated refactor, formatting churn과 생성물 변경을 섞지 않습니다.
- 기존 사용자의 변경과 관련 없는 dirty file을 되돌리지 않습니다.
- 공개 지원 범위, 보안 불변조건과 schema 변경은 별도 검토 대상으로 표시합니다.

## 20. 완료 정의

변경은 다음 조건을 모두 충족해야 완료입니다.

- 관련 요구사항 ID와 구현이 연결됨
- Rust module rustdoc와 contract 문서가 갱신됨
- unit, contract, integration과 필요한 E2E가 통과함
- 성능·보안·복구 불변조건 회귀가 없음
- 사용자 오류와 UI에 문제·원인·영향·다음 조치가 표시됨
- 실제 적용 상태를 read-back으로 검증함
- release 대상이면 2GB VPS 하네스와 아키텍처별 artifact 증거가 있음

## 21. 금지 사항

- 요구사항 ID 없는 기능 구현
- hot path의 동기 control·DB·외부 API 호출
- User-Agent만으로 검색봇 허용
- TTL 없는 자동 IP 차단
- proxy verify 전 origin lock
- SSH rule 자동 변경
- 비밀값·request body·cookie 원문 로그
- snapshot 없는 ingress·firewall·TLS 변경
- JW-agent 위임 mode의 UFW·nftables 직접 변경
- rollback 없는 update·bypass
- stale 데이터를 정상으로 표시
- 검증된 표준 protocol client가 있는데 근거 없이 wire protocol을 재구현
- 유지보수·license·advisory·자원 영향을 기록하지 않은 runtime dependency 추가
- 테스트 완화로 회귀 은폐
- G7 Installer에 VPSGuard runtime 책임 추가

## 22. 판단 순서

애매한 경우 다음 순서로 결정합니다.

1. 정상 사용자와 서버 접근을 보호하는가
2. edge hot path와 가용성을 지키는가
3. 실패 후 자동 또는 수동 복구가 가능한가
4. 판정 근거와 실제 적용 상태를 설명할 수 있는가
5. 요구사항과 테스트로 증명할 수 있는가
6. VPSGuard의 제품 경계 안에 있는가
