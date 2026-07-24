---
title: gnuboard5 DET-014 2GB Host Pressure Evidence
status: partial-pilot-verified
doc_type: operational-evidence
requirements:
  - DET-014
verified_at: 2026-07-24
target: gnuboard5
bundle_source_commit: f630185df2a67015b4cff8e6d0a4ba941f3b0cf6
harness_commit: 8fca54e1805d109f7d29152cb3133f6bbc478d06
release_workflow_run: 30066614807
harness_ci_run: 30067197777
---

# gnuboard5 2GB host pressure 증거

## 판정

`DET-014`는 **AUTO_PASS 유지**입니다. 검증된 x86_64 bundle을 격리 Ubuntu
24.04 VM에 실제 적용하고 2GiB로 축소한 뒤 CPU pressure를 주입했습니다.
방어 상태는 `NORMAL → WATCH → LOCAL_GUARD → RECOVERING → NORMAL`로
전이했고 `/proc` 직접값과 Control API 값이 일치했습니다.

Cloudflare provider는 이 VM에서 `unavailable`이므로 `EMERGENCY_PROXY` 실제
전환은 수행하지 않았습니다. provider 실패 시 `LOCAL_GUARD`를 유지하는
fail-safe는 확인했지만, 요구사항의 provider 전환까지 VPS 증명하지 않았으므로
`VPS_PASS`로 올리지 않습니다.

## 실행 대상

| 항목 | 검증값 |
|---|---|
| VM | 격리 VM `gnuboard5`, Ubuntu 24.04.4 LTS, 4 vCPU |
| bundle | `x86_64-unknown-linux-gnu`, source `f630185df2a67015b4cff8e6d0a4ba941f3b0cf6` |
| release workflow | [run 30066614807](https://github.com/jiwonpapa/vpsguard/actions/runs/30066614807), SUCCESS |
| harness | `8fca54e1805d109f7d29152cb3133f6bbc478d06` |
| harness CI | [run 30067197777](https://github.com/jiwonpapa/vpsguard/actions/runs/30067197777), SUCCESS |
| 원래 release | `96fc3401347759dc00575b8629ae99f565bdbf6b` |
| memory | libvirt `8,388,608 KiB` → `2,097,152 KiB` → `8,388,608 KiB` |
| 2GB guest read-back | `MemTotal 1,840,328 kB` |
| 총 실행 시간 | `103,622 ms` |

bundle의 `SHA256SUMS`, x86-64 ELF와 `BUILD-INFO.txt` source commit을 실행
전에 검증했습니다. 후보 적용 전 deployment snapshot을 만들고 모든 검증 뒤
원래 release와 memory로 자동 복원했습니다.

## 압력·상태 timeline

| 항목 | 결과 |
|---|---:|
| `/proc`·Control API 표본 | `70` |
| pressure와 정렬된 표본 | `34` |
| 최대 `/proc` CPU | `100%` |
| 최대 Control API CPU | `100%` |
| 최대 CPU 차이 | `0%p` |
| 최대 memory total 차이 | `0 bytes` |
| 상태 전이 | `NORMAL → WATCH → LOCAL_GUARD → RECOVERING → NORMAL` |
| 내부 Edge 요청 | `36/36 HTTP 200` |
| provider | `unavailable`, `LOCAL_GUARD` 유지 |

CPU worker는 고정된 `/usr/bin/sha256sum /dev/zero` 네 개만 40초 실행하고
`finally`에서 종료했습니다. pressure 종료 뒤 연속 정상 window로
`RECOVERING`과 최종 `NORMAL`을 확인했습니다. credential, cookie, response
body와 request body는 증거에 저장하지 않았습니다.

## public HTTPS

| 항목 | 결과 |
|---|---:|
| 간격 | `1,000 ms` |
| 표본 | `75` |
| HTTP `200` | `75` |
| 실패 | `0` |
| 최장 연속 순단 | `0 ms` |
| 최대 schedule lag | `5 ms` |
| 마지막 status | `200` |

이 enforce profile의 정상 client 한도는 `120 rpm`입니다. 최초 100ms probe는
분당 600회 요청으로 자기 자신을 정상적으로 429 차단했으므로 증거로 채택하지
않았습니다. 최종 하네스는 60rpm인 1초 간격을 fail-closed로 고정해 정책을
우회하지 않으면서 5초 순단 예산을 관찰합니다.

로컬 원본 evidence checksum은 다음과 같습니다.

- summary JSON: `73c387fd69405389aebfb4c8937d89b3e14185b82b14a6f8ec2ce74c3621448c`
- 1초 JSONL: `f51f66e05e9fbac46d5a861b7231aff878df8334491617a319d78826ce8732d0`

## 종료 보존과 정리

- 현재 release: 원래 `96fc3401347759dc00575b8629ae99f565bdbf6b`
- guest `MemTotal`: `8,131,784 kB`
- Apache, Edge, Control, privileged service와 socket: 모두 `active`
- Edge 별도 probe: `HTTP 200`
- CPU worker: 없음
- 후보 release `f630185…`, commit stage와 이번 실행 snapshot 6개: 제거
- 기존의 다른 release와 snapshot: 변경하지 않음
- `g7devops.com` 운영 서버: 배포하지 않음

## 남은 검증

격리된 Cloudflare test zone과 public origin을 준비한 뒤 sustained pressure의
`EMERGENCY_PROXY`, provider read-back, origin lock, `RECOVERY_READY`와 관리자
승인 복구를 같은 timeline으로 증명해야 `DET-014`를 `VPS_PASS`로 올릴 수
있습니다.
