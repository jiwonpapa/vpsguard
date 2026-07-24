---
title: gnuboard5 UI-018 2GB Protection Policy Evidence
status: pilot-verified
doc_type: operational-evidence
requirements:
  - UI-018
  - OPS-005
  - OPS-010
verified_at: 2026-07-24
target: gnuboard5
source_commit: 9477e0a5432d8d16e95507e6c0347cbe054631a8
workflow_run: 30062627656
---

# gnuboard5 UI-018 2GB 보호 정책 증거

## 판정

`UI-018`은 **VPS_PASS**입니다. GitHub가 생성·서명한 x86_64 bundle을 격리
Ubuntu VM에 update하고, 실행 중 메모리를 8GB에서 2GB로 내린 상태에서 인증된
보호 설정 plan·apply, Edge policy version 관측과 원래 설정 복구를 완료했습니다.
종료 뒤 원래 release, 메모리, service와 balloon driver 상태도 복구했습니다.

`OPS-005`와 `OPS-010`에는 실제 update·snapshot restore 증거가 추가됐지만 이
문서는 1회 파일럿입니다. 20회 apply·restore와 100ms public probe timeline이
아니므로 두 요구사항은 **AUTO_PASS**를 유지합니다.

## 검증 대상

| 항목 | 검증값 |
|---|---|
| VM | Ubuntu 격리 VM `gnuboard5`, 4 vCPU |
| release artifact | `x86_64-unknown-linux-gnu`, source `9477e0a5432d8d16e95507e6c0347cbe054631a8` |
| release workflow | [run 30062627656](https://github.com/jiwonpapa/vpsguard/actions/runs/30062627656), SUCCESS |
| 원래 release | `96fc3401347759dc00575b8629ae99f565bdbf6b` |
| candidate release | `9477e0a5432d8d16e95507e6c0347cbe054631a8` |
| 메모리 | libvirt `8,388,608 KiB` → `2,097,152 KiB` → `8,388,608 KiB` |
| 2GB guest read-back | `MemTotal 1,840,328 kB` |
| 실행 시간 | `32,768 ms` |
| 인증 | root-only local admin socket의 일회용 break-glass code |

bundle의 전체 `SHA256SUMS`, x86_64 ELF 네 개, `BUILD-INFO.txt` source commit과
GitHub SLSA provenance를 실행 전에 검증했습니다. credential, cookie, CSRF token과
원본 request body는 출력·증거 파일에 저장하지 않았습니다.

## 보호 설정과 Edge read-back

| 항목 | 시작 | candidate | 원복 |
|---|---:|---:|---:|
| policy version | `510` | `511` | `512` |
| Edge version 관측 | - | `observed` | `observed` |
| normal route | `200` | `200` | `200` |
| strict route | `200` | `200` | `429` |
| upload route | `404` | `404` | `404` |

candidate는 현재 typed 설정에서 WATCH strict 한도 하나만 유효 범위 안에서
변경했습니다. fingerprint·plan hash·CSRF·idempotency 조건을 거쳐 적용한 뒤
Control의 policy version과 Edge telemetry의 observed version이 일치할 때까지
bounded polling했습니다. 이어 같은 절차로 시작 시점의 다섯 제한값을 복구했고,
최종 API read-back이 원본 설정과 정확히 일치했습니다.

원복 후 strict `429`는 같은 probe client가 누적 rate window를 소비한 결과입니다.
설정 복구 판정은 응답 status 동일성이 아니라 typed 설정 다섯 값의 정확 비교와
새 policy version `512`의 Edge 관측으로 수행했습니다.

## 실패에서 추가한 회귀 차단

첫 파일럿들은 다음 문제를 실제 VM에서 발견했고 자동 복구 후 수정했습니다.

- deployment snapshot restore가 기존 parent directory mode를 정확히 복구하지
  못하던 회귀를 차단했습니다.
- 구 release Control이 policy version은 전진시키고 새 settings metadata sidecar는
  갱신하지 않는 호환 문제를 확인했습니다. route 규칙이 저장 설정과 정확히
  일치할 때만 metadata version을 전진시키고, 불일치는 fail-closed로 거부합니다.
- update health probe를 총 약 15초로 제한하고, QGA guest command를
  `/bin/timeout`으로 감싸 timeout 뒤 자식 process가 남지 않도록 했습니다.

수정 commit `9477e0a5432d8d16e95507e6c0347cbe054631a8`의 CI
[run 30062621780](https://github.com/jiwonpapa/vpsguard/actions/runs/30062621780)은
quality, coverage, load regression, integration, web, unit contract와 merge gate가
모두 성공했습니다.

## 종료 보존 확인

- 현재 release link: 원래 `96fc3401347759dc00575b8629ae99f565bdbf6b`
- libvirt live memory: `8,388,608 KiB`
- guest `MemTotal`: `8,131,784 kB`
- Apache, Edge, Control, privileged service와 socket: 모두 `active`
- Control·Edge health: 모두 `live`
- 파일럿 stage: 0개
- 파일럿 candidate release `2018e3d…`, `9477e0a…`: 제거
- 기존의 다른 versioned release: 변경하지 않음

`g7devops.com`에는 이 bundle이나 설정을 배포하지 않았습니다. 서버는 원래
`Nginx public 80/443 -> PHP-FPM` topology를 유지합니다.

## 제한

- 한 번의 x86_64 update·policy·restore 파일럿이며 20회 반복, 장시간 soak와
  100ms public probe timeline은 아직 없습니다.
- aarch64 artifact는 native GitHub runner에서 실행·서명 검증했지만 이 VM에서는
  실행하지 않았습니다.
- 이 증거는 보호 설정 hot reload를 검증하며 Cloudflare, TLS renewal, uninstall과
  public VPS cutover를 검증하지 않습니다.
