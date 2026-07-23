---
title: VPSGuard Security Completeness Audit
status: release-blocked
doc_type: security-audit
reviewed_at: 2026-07-22
source_revision: 024aad64fa8b0b9b3b8a0488ece8eea87f70bd65
---

# VPSGuard 보안 완성도 감사

## 결론

VPSGuard는 **pre-MVP 보안 파일럿**이며 보안 지시가 100% 완료된 상태가 아닙니다. 현재 정적 감사에서 즉시 악용 가능한 Critical 취약점은 확인하지 못했지만, 원격 `main` CI 실패와 미적용 branch protection을 포함한 High 출시 차단 항목이 남아 있습니다. 따라서 지금은 임의의 웹서비스 앞단에 무조건 설치 가능한 완성 제품이나, 모든 SQL injection·XSS·봇·DDoS를 차단하는 제품으로 홍보하면 안 됩니다.

현재 정본인 `verification-status.tsv` 기준 전체 119개 요구사항은 `PLANNED 10`, `CODE_ONLY 32`, `AUTO_PASS 62`, `VPS_PASS 15`입니다. 보안 요구사항 17개만 보면 `CODE_ONLY 3`, `AUTO_PASS 13`, `VPS_PASS 1`입니다. 자동 테스트를 통과한 것과 실제 VPS에서 복구·오탐까지 증명된 것은 같은 완료 단계가 아닙니다.

## 확인된 강점

- 관리자 경로는 고정 Host·Origin, session, CSRF와 same-origin 요청으로 보호되고 HTTPS cookie는 Secure·HttpOnly·SameSite=Strict를 사용합니다 (`crates/guard-control/src/api.rs:1308`, `crates/guard-control/src/auth.rs:692`, `web/src/lib/api.ts:30`).
- Linux-PAM, `vpsguard-admin` group, TOTP, 로그인 시도 제한과 session 폐기가 구현됐고 실제 VM PAM session이 검증됐습니다 (`SEC-015`).
- standalone UFW는 typed plan/apply/read-back으로 VPSGuard 소유 규칙만 다루며 기존 SSH·운영자 규칙 보존을 VM에서 확인했습니다 (`ACT-013`, `ACT-014`).
- GPTBot·Meta bot 차단, 위조 Googlebot 거부, client/route/global rate limit, HTTP/1.1 ambiguous framing 거부, CRS SQLi·XSS fixture 차단이 GnuBoard5 VM에서 확인됐습니다.
- 웹 소스에서 `dangerouslySetInnerHTML`, `innerHTML`, `eval`과 임의 외부 URL fetch를 확인하지 못했습니다. CSRF 값은 브라우저 저장소가 아니라 module memory에 유지하며 localStorage는 theme에만 사용합니다.
- 2026-07-22 감사 시 `bun audit`은 알려진 취약점 0건이었습니다. `cargo audit --ignore RUSTSEC-2024-0437`은 비예외 취약점 0건이지만 아래의 명시적 예외와 unmaintained 경고는 남아 있습니다.
- 추적 소스의 비밀값 패턴 검사에서 실제 key/token을 발견하지 못했습니다. 테스트용 password sentinel만 탐지됐으며 원본 request body와 운영 비밀값을 evidence에 보존하지 않는 계약이 있습니다.

## 출시 차단 및 개선 항목

### VG-AUD-001 — High — 실패한 CI를 기본 브랜치가 허용함

- 위치: `.github/workflows/ci.yml:19`, `scripts/build-release.sh:21`, GitHub `main` branch protection
- 증거: 원격 `main` SHA `024aad64...`의 [CI run 29906140022](https://github.com/jiwonpapa/vpsguard/actions/runs/29906140022)은 실패했습니다. unit/integration/coverage job은 Ubuntu runner의 `libclang` 부재로 `clang-sys` build에 실패했고 quality job은 `SC2086`으로 실패했습니다. GitHub branch protection API는 `Branch not protected`를 반환했습니다.
- 영향: 테스트가 실패해도 direct push로 기본 브랜치가 갱신될 수 있어 TDD·회귀 차단이 강제되지 않습니다.
- 조치: CI에 고정된 `libclang` 설치를 추가하고 shellcheck 오류를 수정한 뒤 전체 green을 복구합니다. `main`에는 `merge-gate` 필수 check, PR 승인, direct push 금지와 관리자 우회 제한을 적용합니다.
- 임시 완화: green CI SHA 외에는 release artifact를 만들거나 배포하지 않습니다.

### VG-AUD-002 — High — Cloudflare 실제 전환·원상복구 미검증

- 위치: `specs/product/verification-status.tsv:46`, `specs/product/verification-status.tsv:48`
- 증거: `ACT-006`, `ACT-008`, `SEC-001`, `SEC-004`가 `CODE_ONLY`이며 fake provider test만 존재합니다.
- 영향: 실제 zone/record 차이, dual-stack, origin lock, API 부분 실패에서 사이트 단절 또는 복구 실패가 발생할 수 있습니다.
- 조치: 전용 Cloudflare test zone에서 proxied 전환, `cf-ray` 확인, A·AAAA·CNAME read-back, origin firewall lock, token 폐기, 중간 단계 fault와 snapshot 역복구를 증거화합니다.
- 임시 완화: Cloudflare 자동 전환 기능은 기본 비활성·파일럿 전용으로 유지합니다.

### VG-AUD-003 — High — request smuggling과 WAF의 실제 앱 회귀가 불완전함

- 위치: `specs/product/evidence/gnuboard5-standalone-security-20260722.md:107`, `specs/product/verification-status.tsv:120`
- 증거: HTTP/1.1 중복 Host/CL·CL+TE는 VM에서 거부됐지만 HTTP/2·WebSocket smuggling E2E가 없습니다. anonymous GET 오탐은 0이었으나 로그인 후 글쓰기·관리·파일 업로드·plugin 경로 WAF 오탐 replay가 없습니다.
- 영향: protocol별 우회가 남거나 정상 관리·업로드 요청이 403으로 차단될 수 있습니다.
- 조치: h2/h2c downgrade, WebSocket upgrade, CL/TE corpus와 정상 연결 회귀를 같은 VM에서 실행합니다. 실제 PAM/GnuBoard session으로 글쓰기·수정·검색·업로드를 detection-only부터 replay하고 tuned exclusion 뒤 enforce합니다.
- 임시 완화: 새 앱 profile은 `protocol_only`, WAF는 `detection_only`로 시작하며 검증된 route만 enforce합니다.

### VG-AUD-004 — High — TLS·업데이트·제거 수명주기 증거가 없음

- 위치: `specs/product/verification-status.tsv:54`, `specs/product/verification-status.tsv:56`, `specs/product/verification-status.tsv:58`, `specs/product/verification-status.tsv:78`
- 증거: `TLS-002`, `TLS-006`, `OPS-005`~`OPS-007`은 `CODE_ONLY`, `TLS-004`는 `PLANNED`입니다.
- 영향: 인증서 갱신 후 실제 제공 인증서가 바뀌지 않거나, update/uninstall 실패 시 ingress·인증서·사이트 가용성을 손상할 수 있습니다.
- 조치: Certbot staging 발급·timer renew·deploy hook·served fingerprint 비교, 실패 binary 자동 rollback, uninstall 소유 파일 검증, x86_64/aarch64 artifact 실행 smoke를 완료합니다.
- 임시 완화: VPSGuard가 public TLS를 직접 소유하는 배포와 자동 update/uninstall은 인증된 파일럿 이외에는 제공하지 않습니다.

### VG-AUD-005 — High residual risk — 로컬 프록시만으로 volumetric DDoS와 완전 위장 봇을 막을 수 없음

- 위치: `specs/product/evidence/gnuboard5-standalone-security-20260722.md:109`
- 증거: 600건 burst와 위조 XFF는 제한됐지만 여러 실제 source IP의 high-cardinality botnet soak는 없습니다. slow-header 병행 probe에서는 251회 중 1회 2초 timeout이 관측됐습니다.
- 영향: 회선이나 VPS 앞단이 포화되면 VPSGuard에 도달하기 전에 장애가 발생합니다. 사람처럼 UA·쿠키·속도를 맞춘 봇은 확정 식별할 수 없습니다.
- 조치: 실제 다중 source A/B soak, direct-origin 대비 origin 도달률·CPU·RSS·오탐·회복시간 예산을 확정합니다. volumetric 공격은 upstream provider/CDN rate limiting과 함께 방어합니다.
- 임시 완화: 로컬 VPSGuard는 L7 자원 보호 역할로 한정하고 회선 DDoS 흡수 기능으로 홍보하지 않습니다.

### VG-AUD-006 — Medium — 관리자 역할과 민감 정보 권한 분리가 없음

- 위치: `specs/product/verification-status.tsv:70`, `web/src/lib/api.ts:53`, `web/src/pages/clients.tsx:79`
- 증거: `UI-012`는 `PLANNED`이며 session에는 actor/authentication method만 있고 role/permission이 없습니다. 인증된 관리자는 원시 client IP와 모든 운영 명령에 같은 권한을 가집니다.
- 영향: read-only 운영자 계정이 도입되면 개인정보 노출과 과권한 변경 위험이 생깁니다.
- 조치: server-side typed role/permission, raw-IP masking, export 권한, action matrix와 `web/tests/permissions.spec.ts`를 구현합니다.
- 임시 완화: 완료 전에는 단일 신뢰 관리자 설치로 범위를 제한하고 관리자 계정 공유를 금지합니다.

### VG-AUD-007 — Medium — legacy CSP의 `unsafe-inline`과 광범위한 `https:` 허용

- 위치: `crates/guard-profiles/src/lib.rs:69`
- 증거: PHP/GnuBoard5/WordPress compatibility CSP가 `script-src 'self' 'unsafe-inline' https:`를 사용합니다. 이는 OWASP가 설명하는 XSS 방어 강도를 낮추는 구성입니다.
- 영향: origin에 HTML/script injection이 존재하면 CSP가 기대한 2차 방어 역할을 충분히 하지 못합니다.
- 조치: report-only violation을 수집해 site별 nonce/hash 또는 고정 asset allowlist로 축소하고, 호환 확인 뒤 enforce합니다.
- 임시 완화: 이 CSP를 SQLi/XSS 차단 성공 근거로 사용하지 않으며 origin의 escaping, prepared query, CSRF를 필수로 유지합니다.

### VG-AUD-008 — Medium — 취약 advisory 예외와 unmaintained 전이 의존성

- 위치: `docs/security/advisory-exceptions.md:3`, `docs/security/advisory-exceptions.md:15`
- 증거: Pingora 전이 `protobuf 2.28.0`의 `RUSTSEC-2024-0437` DoS advisory를 도달 불가 판정으로 2026-08-14까지 예외 처리합니다. `daemonize`, `derivative`, `rustls-pemfile`의 unmaintained 경고 3건도 남아 있습니다.
- 영향: 향후 public protobuf decode 경로가 추가되면 즉시 DoS 노출이 생기며 유지보수 중단 의존성은 패치 지연 위험이 있습니다.
- 조치: Pingora upgrade를 추적하고 기한 전에 예외를 재심사합니다. protobuf decode API 추가를 repository contract로 금지하고 unmaintained crate 제거 가능 버전을 검증합니다.
- 임시 완화: 현재처럼 public protobuf parser를 제공하지 않고 Pingora daemon mode를 사용하지 않습니다.

### VG-AUD-009 — Medium — 성능·coverage release gate가 닫히지 않음

- 위치: `specs/product/verification-status.tsv:98`, `tools/coverage-baseline.toml:14`
- 증거: `NFR-001`이 `PLANNED`입니다. 로컬 coverage gate는 `guard-edge/src/proxy.rs 4.84% < 5.00%`로 실패했고 원격 coverage는 libclang 부재로 계측 전에 실패했습니다.
- 영향: 방어 로직 자체가 병목이나 장애원이 되는 회귀, 또는 핵심 proxy 예외 경로의 미검증 회귀를 배포 전에 막지 못합니다.
- 조치: 동일 VM/direct-origin 기준의 latency·throughput·CPU·RSS 예산을 확정하고 proxy 실패·timeout·WebSocket 테스트를 추가해 baseline을 실제로 통과시킵니다.
- 임시 완화: coverage floor를 낮추지 않고 green 전 release를 금지합니다.

### VG-AUD-010 — Low — 실제 공식 crawler allow와 상태 문서 동기화가 남음

- 위치: `specs/product/evidence/gnuboard5-standalone-security-20260722.md:109`, `specs/product/11-mvp-implementation-status.md:16`
- 증거: Google·Naver·Bing CIDR fixture와 위조 crawler 차단은 있으나 실제 공식 source allow E2E는 없습니다. 구현 현황 문서의 `CODE_ONLY 33/AUTO_PASS 61`은 현재 추적표의 `32/62`와 다릅니다.
- 영향: 정상 검색 노출을 해치는 오탐과 완료율 보고 오류가 생길 수 있습니다.
- 조치: 실제 crawler 검증 증거를 수집하고 상태 개수를 수동 복제하지 않도록 gate에서 생성·검증합니다.

## 배포 판정

현재 허용 가능한 범위는 **격리된 로컬/VM 파일럿과 제한된 GnuBoard5 staging**입니다. 공개 서비스 배포는 최소한 `VG-AUD-001`을 먼저 닫고, 선택 기능에 따라 `VG-AUD-002`~`VG-AUD-004`를 닫은 뒤 진행해야 합니다. `VG-AUD-005`는 코드로 완전히 제거할 수 없는 잔여 위험이므로 upstream 방어와 정확한 제품 문구가 필요합니다.

보안 완료 선언 조건은 다음과 같습니다.

1. 원격 `main`의 전체 CI와 local coverage가 green이고 branch protection이 실제 적용됩니다.
2. Cloudflare, TLS, update/uninstall은 실제 test zone/VM에서 실패 주입과 역복구까지 통과합니다.
3. HTTP/2·WebSocket, 인증 글쓰기·업로드, 다중 실제 source 부하의 오탐·우회 증거가 남습니다.
4. `UI-012` 권한 분리와 legacy CSP 축소가 완료됩니다.
5. 필수 요구사항의 `CODE_ONLY`·`PLANNED`가 남지 않고 release checklist가 해당 SHA의 artifact를 승인합니다.

## 감사 범위와 제한

이번 감사는 저장소 코드·문서·요구사항 추적표, 현재 로컬 gate 결과, GnuBoard5 VM 보존 증거, GitHub 기본 브랜치/CI 상태와 dependency advisory를 대상으로 했습니다. 실제 인터넷 공격, Cloudflare 실계정 변경, penetration test와 소스 전체에 대한 formal verification을 수행한 결과는 아닙니다. “보안 100%”는 현실적으로 보장할 수 없으며, 완료 판정은 위협 모델·지원 profile·운영 증거와 잔여 위험 수용을 함께 명시해야 합니다.
