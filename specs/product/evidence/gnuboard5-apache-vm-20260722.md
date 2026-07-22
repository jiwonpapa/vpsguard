---
title: gnuboard5 Apache VM Cutover and Security Harness Evidence
status: pilot-verified-with-crawler-gap
doc_type: operational-evidence
requirements:
  - OPS-011
  - NFR-014
verified_at: 2026-07-22
target: gnuboard5
source_commit: 4a531fb3aefc490fd794d30c254a5861ab8ec563
source_state: uncommitted-lab
---

# gnuboard5 Apache VM 전환·보안 하네스 증거

## 판정

`OPS-011`과 `NFR-014`는 **VPS_PASS**입니다. Ubuntu 24.04 `gnuboard5` 격리 VM에서 Apache public TLS -> VPSGuard loopback -> Apache loopback origin 전환, bypass, 실패 자동 rollback, 20회 왕복과 호스트 기반 direct/guarded A/B 시나리오를 완료했습니다.

> 이 문서의 crawler gap은 최초 Apache 파일럿 당시 결과입니다. 이후 standalone UFW·PAM·AI bot·WAF·2GB 검증은 [standalone 보안 증거](gnuboard5-standalone-security-20260722.md)가 이어받습니다.

Apache 파일럿은 승인하지만 전체 봇 방어 완료를 뜻하지 않습니다. 공개 Meta bot User-Agent 요청은 guarded에서도 40/40이 origin까지 통과했습니다. verified crawler 판별과 관리자가 허용한 검색봇 외 기본 거부는 `DET-003`, `DET-004` 후속 구현 대상입니다.

## 환경과 최종 구성

| 항목 | 검증값 |
|---|---|
| VM | `gnuboard5`, Ubuntu 24.04.4 LTS, 4 vCPU / 8GB / 60GB |
| baseline snapshot | `vpsguard-baseline-20260722` |
| 공개 경로 | Apache TLS `80/443` -> VPSGuard `127.0.0.1:18080` -> Apache origin `127.0.0.1:18081` |
| Control | `127.0.0.1:7727` |
| 공개 port scan | `22`, `80`, `443`만 open |
| 외부 차단 listener | `3306`, `7727`, `18080`, `18081` closed |
| 서비스 | `apache2`, `vps-guard-edge`, `vps-guard-control` active·enabled |
| 공개 페이지 | `/` 200, `/adm/` 200, `x-vps-guard: guard-edge` |
| 응답 보안 header | CSP report-only와 baseline header 적용 |
| client IP | Apache origin log에 실제 호스트 IP 보존, 외부 `X-Forwarded-For` 제거 후 trusted loopback chain에서 재생성 |
| CLI SHA-256 | `91256603a0dcbbb8fd796ada178374822dbd5fe10df905c79d78639febe39cdb` |
| 인증서 SHA-256 | `99c5bff44b53ab3fd20a92afaab895a40c1404d7a2414447bbf7c0755f53087c` |

배포 전 snapshot `/var/backups/vps-guard/deployments/deploy-20260722T040511Z-1585000000`의 protected read-back은 PASS였습니다. target VM에는 Rust toolchain을 설치하지 않았고 외부 Linux builder에서 만든 release binary만 배포했습니다.

## direct/guarded A/B 결과

동일 VM과 사이트를 대상으로 direct Apache와 guarded 경로를 비교했습니다. 실행기는 hypervisor의 digest 고정 container image를 사용했습니다.

| 시나리오 | Direct | Guarded | 판정 |
|---|---:|---:|---|
| 정상 browser, 15초 | 75 x 200, 평균 29.716ms | 74 x 200, 평균 62.746ms | 정상 요청 차단 0건 |
| 익명 burst, 600건 | 600 x 200 | 120 x 200, 480 x 429 | 80%를 origin 전 차단 |
| strict search, 180건 | 180 x 200 | 30 x 200, 150 x 429 | 고비용 경로 제한 동작 |
| Meta bot visible UA, 40건 | 40 x 200 | 40 x 200 | 봇별 default deny 미구현 |
| 고정 위조 XFF burst, 240건 | 240 x 200 | 120 x 200, 120 x 429 | 외부 XFF 불신·rate limit 동작 |
| `TRACE` | 405 | 405 | origin Apache도 이미 거부, guarded 회귀 없음 |
| slow headers, 40 connection / 20초 | service available | service available, 동시 공개 probe 200 | 가용성 유지 |

익명 burst 때 Apache origin access log는 정확히 120줄 증가했습니다. 따라서 600건 중 480건은 origin에 도달하기 전에 차단됐습니다. slow-header 실행 중 edge의 `MemoryCurrent` 증가는 540,672 bytes, 누적 `CPUUsageNSec` 증가는 25.273ms, task 수는 5에서 6이었습니다.

고정 XFF fixture는 forwarded header sanitization과 단일 client rate limit은 증명하지만, 공격자가 요청마다 값을 회전시키는 spoof replay 전체를 증명하지는 않습니다.

## 전환·복구 증거

- Apache -> edge -> Apache 왕복 20회를 완료했습니다.
- 최초 16번째 시도에서 systemd start-limit이 발생했지만 typed transaction 자동 rollback은 성공했습니다.
- unit을 `StartLimitIntervalSec=60s`, `StartLimitBurst=30`, `KillSignal=SIGINT`, `TimeoutStopSec=4s`로 보강한 뒤 16~20회를 재실행해 모두 성공했습니다.
- 의도적으로 public probe를 실패시킨 `apache-fault-probe-rollback-20260722` transaction은 예상대로 실패하고 `rollback_succeeded=true`를 기록했습니다. 인증서, SSH와 기존 Apache 공개 응답은 보존됐습니다.
- 100ms 공개 probe timeline은 총 652 samples 중 651 x 200, 1 x 502였습니다. 502는 단일 100ms sample이며 5초 public ingress budget 안에서 회복했지만, 이 결과로 무순단을 주장하지 않습니다.
- listener read-back은 프로세스 PID 변화가 아닌 canonical endpoint를 비교하며 VPSGuard 소유 web port `80`, `443`, `18080`, `18081`을 비-web 보존 대상에서 제외합니다.

## 하네스와 회귀 게이트

- Python unit: 35 PASS
- repository contract와 requirements traceability: PASS
- Rust: fmt, clippy `-D warnings`, rustdoc `-D warnings`, workspace all-features test PASS
- Web: Bun frozen install, production build, unit test 7 PASS
- dependency: `cargo deny check` PASS
- advisory: 저장소에 기록된 `RUSTSEC-2024-0437` Pingora 전이 의존성 예외를 명시적으로 적용한 `cargo audit --ignore RUSTSEC-2024-0437` PASS
- evidence는 status·latency·resource·listener 결과만 저장하며 cookie, credential, 원문 body를 저장하지 않습니다.

## 남은 제한과 다음 gate

- `DET-003`: reverse/forward DNS와 ASN 등으로 verified crawler를 판별하는 기능이 없습니다.
- `DET-004`: verified crawler의 고비용 경로 제한은 code-only이며 이 VM에서 crawler identity E2E를 통과하지 않았습니다.
- 지정한 검색봇 외 자동화 traffic default deny 정책과 위장·회전 replay가 필요합니다.
- CSP는 report-only이며 enforce 전환과 GnuBoard 화면 회귀 검증이 남았습니다.
- 이 증거의 source는 `uncommitted-lab`입니다. VM 운영 동작은 증명하지만 서명된 release artifact와 Git 이력 기반 배포 증거를 대신하지 않습니다.
- 4 vCPU / 8GB 파일럿은 `NFR-002`의 2GB VPS soak 승인 증거가 아닙니다.
