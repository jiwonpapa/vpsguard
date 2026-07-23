---
title: gnuboard5 Standalone Security and 2GB VM Evidence
status: pilot-verified-with-bounded-gaps
doc_type: operational-evidence
requirements:
  - EDGE-014
  - DET-013
  - ACT-013
  - ACT-014
  - UI-016
  - UI-017
  - SEC-015
  - SEC-016
  - SEC-017
  - NFR-002
  - NFR-014
verified_at: 2026-07-22
target: gnuboard5
source_parent: 7bdc3cccca1be23f928401bcb48640c44f4e4a10
source_state: candidate-implementation
---

# gnuboard5 standalone 보안·2GB VM 증거

## 판정

2026-07-23 재감사에서 Linux-PAM+TOTP probe가 실제 운영자 QR 등록이 아니라 자동 생성된 사용자 home test seed를 읽어 통과한 사실을 확인했습니다. 따라서 이 문서의 PAM session은 코드·배포 경로 증거로만 남기고 `SEC-015`의 실제 사용자 등록 증거로는 폐기합니다. `SEC-015`는 **AUTO_PASS**로 되돌리며 새 운영자가 직접 QR을 등록한 뒤 재검증해야 합니다.

그 외 직접 HTTPS 관리자 경로, VPSGuard 소유 UFW 규칙 transaction, declared AI bot 차단, 계층형 rate limit, ambiguous request framing 거부와 선택형 ModSecurity·OWASP CRS의 Ubuntu VM 증거는 유지합니다. `ACT-013`, `ACT-014`, `UI-016`, `NFR-014`는 **VPS_PASS**입니다.

공식 crawler의 실제 source IP, authenticated upload WAF 오탐, HTTP/2·WebSocket smuggling, 실제 회전 source high-cardinality는 실환경 증거가 부족합니다. 관련 `EDGE-014`, `DET-013`, `UI-017`, `SEC-016`, `SEC-017`, `NFR-002`는 자동 회귀는 통과했지만 이 보고서만으로 release 완료를 주장하지 않습니다.

## 최종 구성과 관리 접속

| 항목 | 검증값 |
|---|---|
| VM | Ubuntu 24.04.4 LTS, 4 vCPU, 실행 중 8GB → 2GB → 8GB 복구 |
| 공개 경로 | Apache TLS `80/443` → VPSGuard `127.0.0.1:18080` → Apache `127.0.0.1:18081` |
| 관리자 | `https://192.168.0.143:7443`, Apache TLS → loopback Control `127.0.0.1:7727` |
| 인증 | Linux-PAM `vpsguard-admin` group + TOTP 코드 경로. 당시 seed 출처 문제로 실제 사용자 등록 증거는 무효 |
| 서비스 | Apache, edge, control, root privileged helper와 systemd socket 모두 active |
| 방화벽 | UFW active, default deny incoming, 기존 운영자 규칙 8개 보존 |
| 공개 listener | `22`, `80`, `443`, `7443` open |
| 차단 listener | `3306`, `7727`, `18080`, `18081` filtered 또는 비공개 |
| WAF | ModSecurity + OWASP CRS `tuned_enforce`, 실제 mode가 status API에 표시됨 |

당시 probe는 서버 계정명·비밀번호와 test seed에서 계산한 TOTP를 사용했습니다. 비밀번호·cookie·CSRF·원문 request body는 evidence에 저장하지 않았지만 test seed가 사용자 home에 존재했으므로 운영 credential 비저장 증거로 인정하지 않습니다.

## UFW와 권한 경계

- UFW가 비활성인 상태에서는 VPSGuard가 자동 활성화하지 않고 fail-closed로 거부했습니다.
- 운영자가 SSH `22`, HTTP `80`, HTTPS `443`, 관리자 `7443`을 먼저 허용한 뒤 UFW를 활성화했습니다.
- systemd socket은 `/run/vps-guard-privileged/control.sock`, parent `0750 root:vps-guard`, socket `0660 root:vps-guard`였습니다.
- root helper는 argv allowlist와 typed UFW 문법만 받고 `CAP_NET_ADMIN`, `CAP_DAC_READ_SEARCH`만 가집니다.
- 실제 PAM session으로 `192.0.2.1/32 deny`를 plan → dry-run → apply → read-back → remove → read-back 했습니다.
- 종료 시 VPSGuard 소유 규칙은 0개, 기존 운영자 규칙은 8개로 복구됐고 새 SSH 접속도 성공했습니다.
- `jw_agent_delegated` mode는 API·UI가 읽기 전용이며 mutation을 거부하는 자동 회귀로 검증했습니다.

통합 프로브 결과:

```text
pam_session=PASS actor=gnuboard5 method=pam_mfa
ufw_status=PASS active=true owned=0 foreign=8
edge_security_status=PASS inspection=profiled waf=tuned_enforce
ufw_add_readback=PASS
ufw_remove_readback=PASS
standalone_security_probe=PASS
```

## 공격·오탐 시나리오

| 시나리오 | 결과 | 판정 |
|---|---:|---|
| 정상 browser 15초, 5 req/s | 75 x 200, 평균 28.103ms, p95 37.222ms | 정상 응답 100% |
| 익명 burst 600건, concurrency 40 | 85 x 200, 515 x 429 | 85.8% origin 전 제한 |
| GPTBot declared UA | 10 x 403 | 10/10 차단 |
| Meta bot declared UA | 40 x 403 | 40/40 차단 |
| 위조 Googlebot UA | 10 x 403 | 공식 CIDR 밖 위조 10/10 차단 |
| browser UA 150건 | 120 x 200, 30 x 429 | client 한도 동작 |
| 회전 위조 `X-Forwarded-For` 10건 | 10 x 429 | 외부 XFF로 client 우회 불가 |
| auth route 10건 | 6 x 200, 4 x 429 | 별도 고비용 한도 동작 |
| 중복 Host | 400 | origin 전 거부 |
| 중복 Content-Length | 400 | origin 전 거부 |
| Content-Length + Transfer-Encoding | 400 | Pingora 정규화 전 raw framing 검사로 거부 |
| 정상 raw HTTP/1.1 | 200 | framing 회귀 없음 |
| CRS SQLi fixture | 403 | tuned enforce 차단 |
| CRS XSS fixture | 403 | tuned enforce 차단 |
| `/`, login, register, search, anonymous admin | 모두 200 | 관측한 GET baseline 오탐 0 |

ModSecurity detection-only 단계에서는 SQLi rule `942100`, XSS rules `941100`, `941110`, `941160`을 기록하되 200으로 통과시켰습니다. 그 뒤 정상 GET baseline을 확인하고 `tuned_enforce`로 올려 같은 fixture를 403으로 차단했습니다. app별 exclusions 파일은 현재 비어 있습니다.

## 실제 2GB 실행 증거

libvirt live balloon으로 `actual 2,097,152 KiB`를 확인했고 guest의 `MemTotal`은 `1,840,328 kB`, 시작 `MemAvailable`은 `843,120 kB`였습니다. swap은 없었습니다.

- 정상 15초 부하: 75 x 200, 평균 28.103ms, p95 37.222ms, 최대 195.001ms
- 600건 burst: 85 x 200, 515 x 429, 전송 오류 0
- GPTBot: 10 x 403
- 부하 후 guest `MemAvailable`: 827MB
- edge memory peak: 7,184,384 bytes
- control memory peak: 21,483,520 bytes
- privileged helper memory peak: 1,585,152 bytes
- Apache memory peak: 158,908,416 bytes
- 네 서비스의 cgroup `oom`, `oom_kill`, `oom_group_kill`: 모두 0
- Apache, edge, control, helper, socket: 모두 active

검증 뒤 VM은 `actual 8,388,608 KiB`, guest 7,941MB로 복구됐습니다.

## 남은 제한

- Google·Naver·Bing 공식 feed와 CIDR fixture는 자동 검증했지만 lab에서 실제 공식 crawler source를 만들 수 없으므로 verified allow E2E는 남았습니다.
- 사람처럼 UA·속도·쿠키를 완전히 위장한 자동화는 확정 식별할 수 없습니다. 그런 요청은 client·prefix·route·global 행동 한도로만 제한합니다.
- 위조 XFF 회전은 막았지만 여러 실제 source IP를 쓰는 high-cardinality botnet soak는 별도 환경이 필요합니다.
- authenticated 글쓰기·파일 업로드와 plugin 경로의 WAF 오탐 replay가 남아 있어 `SEC-017` 전체 VPS_PASS는 보류합니다.
- HTTP/2·WebSocket의 정상 회귀와 smuggling corpus는 자동 gate에는 있지만 이 VM의 raw E2E 증거는 아직 없습니다.
- slow-header 병행 100ms probe에서 251 samples 중 1회가 2초 timeout 뒤 회복됐습니다. link saturation형 volumetric DDoS는 VPS 내부 proxy만으로 방어할 수 없으며 upstream/CDN 방어가 필요합니다.
