---
title: gnuboard5 OPS-005 OPS-010 2GB Release Endurance Evidence
status: pilot-verified
doc_type: operational-evidence
requirements:
  - OPS-005
  - OPS-010
verified_at: 2026-07-24
target: gnuboard5
bundle_source_commit: 9477e0a5432d8d16e95507e6c0347cbe054631a8
harness_commit: ab89fece9d70f20c879cafc06d0a25662caefb64
workflow_run: 30064895620
---

# gnuboard5 2GB release 내구성 증거

## 판정

`OPS-005`와 `OPS-010`은 **VPS_PASS**입니다. 검증된 x86_64 release bundle을
격리 Ubuntu 24.04 VM에 20회 실제 update하고 매회 candidate release와 다섯
systemd unit을 확인한 뒤 deployment snapshot으로 원복했습니다. 전체 구간에
100ms HTTPS probe를 유지했고 최장 연속 순단은 `2,002 ms`로 `5,000 ms`
예산 안이었습니다.

실증 종료 뒤 원래 release, 8GB memory, service, SSH와 public HTTPS를
재확인했습니다. `g7devops.com` 운영 서버에는 배포하지 않았습니다.

## 실행 대상

| 항목 | 검증값 |
|---|---|
| VM | 격리 VM `gnuboard5`, Ubuntu 24.04.4 LTS, 4 vCPU |
| bundle | `x86_64-unknown-linux-gnu`, source `9477e0a5432d8d16e95507e6c0347cbe054631a8` |
| release workflow | [run 30062627656](https://github.com/jiwonpapa/vpsguard/actions/runs/30062627656), SUCCESS |
| endurance harness | `ab89fece9d70f20c879cafc06d0a25662caefb64` |
| harness CI | [run 30064895620](https://github.com/jiwonpapa/vpsguard/actions/runs/30064895620), SUCCESS |
| 원래 release | `96fc3401347759dc00575b8629ae99f565bdbf6b` |
| 메모리 | libvirt `8,388,608 KiB` → `2,097,152 KiB` → `8,388,608 KiB` |
| 2GB guest read-back | `MemTotal 1,840,328 kB` |
| 실행 | 실제 update·candidate read-back·snapshot restore `20/20` |
| 총 실행 시간 | `240,080 ms` |

bundle은 `SHA256SUMS`, ELF target과 `BUILD-INFO.txt` source commit을 실행 전에
검증했습니다. 하네스는 private guest IP, exact HTTPS Host, 20회 상한,
100ms 간격과 5초 순단 예산을 manifest에서 fail-closed로 강제했습니다.

## 교체·복원 시간

| 단계 | 최소 | 중앙값 | 평균 | 최대 | hard limit |
|---|---:|---:|---:|---:|---:|
| update | `2,772 ms` | `3,059 ms` | `3,032 ms` | `3,187 ms` | `60,000 ms` |
| snapshot restore | `2,584 ms` | `2,690 ms` | `2,722 ms` | `2,984 ms` | `10,000 ms` |

각 회차에서 candidate symlink가 bundle source commit으로 바뀐 것과 Apache,
Edge, Control, privileged service·socket이 모두 `active`인 것을 확인했습니다.
이어 해당 회차가 생성한 deployment snapshot으로 복원하고 원래 release
symlink와 시작 service map이 정확히 일치해야 다음 회차로 진행했습니다.

## 100ms public HTTPS timeline

| 항목 | 결과 |
|---|---:|
| samples | `2,180` |
| transport·status 동시 성공 | `1,608` |
| HTTP status `200` | `1,609` |
| 전환 중 `502` | `6` |
| 전환 중 `503` | `565` |
| 실패 sample | `572` |
| 최장 연속 순단 | `1,842 ms` |
| 최대 probe schedule lag | `415 ms` |
| 마지막 status | `200` |

`502`와 `503`은 성공으로 숨기지 않고 모두 실패 sample로 계산했습니다.
한 sample은 HTTP `200`을 받았지만 partial transfer `curl exit 18`이므로 실패로
계산했습니다.
순단은 첫 실패 probe의 실제 시작부터 다음 정상 probe 완료까지 연속 시간으로
계산했습니다. response body, request body, credential과 cookie는 수집하지
않았습니다.

로컬 원본 evidence checksum은 다음과 같습니다.

- summary JSON: `d6f497690e6d8a4ac6b891b8c7e5cebea9d513806594f74812485041d4e592f5`
- 100ms JSONL: `401118e0877f5d0a12a1490ef2ee2bc4f096c0a17bb6e78af8151effe2054f34`

## 종료 보존과 정리

- 현재 release: 원래 `96fc3401347759dc00575b8629ae99f565bdbf6b`
- guest `MemTotal`: `8,131,784 kB`
- Apache, Edge, Control, privileged service와 socket: 모두 `active`
- Control `/health/live`, Edge `/health/live`: 모두 `live`
- public HTTPS: `200`, 최종 별도 probe `142 ms`
- guest SSH: 성공
- harness stage와 candidate release `9477e0a…`: 제거
- 20회 실증이 생성한 update·rollback snapshot 40개: exact path 확인 후 제거
- 기존의 다른 release와 snapshot: 변경하지 않음

## 범위

이 증거는 격리된 Apache public path의 x86_64 update·restore 내구성을
검증합니다. uninstall, aarch64 target, Cloudflare, Certbot renewal,
WebSocket과 `g7devops.com` public cutover는 별도 요구사항 증거가 필요합니다.
