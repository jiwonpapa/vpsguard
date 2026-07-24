---
title: gnuboard5 TLS-002 2GB Graceful Reload Evidence
status: pilot-verified
doc_type: operational-evidence
requirements:
  - TLS-002
verified_at: 2026-07-24
target: gnuboard5
bundle_source_commit: 612be02dbb5551e9ddeb7e6067ba6a5141483517
harness_commit: 8eae11aa362ee69e0cd4080e2a87b2e99bbf4a4c
release_workflow_run: 30069335989
---

# gnuboard5 2GB TLS graceful reload 증거

## 판정

`TLS-002`는 **VPS_PASS**입니다. 검증된 x86_64 bundle을 격리 Ubuntu 24.04
VM에 실제 적용하고 memory를 2GiB로 제한한 뒤, 새 certificate와 private key를
root-owned runtime bundle로 stage했습니다. supervisor PID를 유지한 채 새
Pingora worker에 listener FD를 인계했고, 갱신 전에 시작한 연결은 같은 TLS
socket에서 응답을 마친 뒤 기존 worker가 종료됐습니다.

이 실증은 합성한 정상 PEM을 사용해 VPSGuard의 stage·사전검증·FD 인계·기존
연결 drain을 검증했습니다. 실제 ACME staging 발급, `certbot.timer` renew와
deploy hook 전체 경로는 `TLS-006`의 별도 release gate로 남깁니다.

## 실행 대상

| 항목 | 검증값 |
|---|---|
| VM | 격리 VM `gnuboard5`, Ubuntu 24.04.4 LTS, 4 vCPU |
| bundle | `x86_64-unknown-linux-gnu`, source `612be02dbb5551e9ddeb7e6067ba6a5141483517` |
| release workflow | [run 30069335989](https://github.com/jiwonpapa/vpsguard/actions/runs/30069335989), SUCCESS |
| harness | `8eae11aa362ee69e0cd4080e2a87b2e99bbf4a4c` |
| memory | libvirt `8,388,608 KiB` → `2,097,152 KiB` → `8,388,608 KiB` |
| 2GB guest read-back | `MemTotal 1,840,328 kB` |
| 총 실행 시간 | `75,388 ms` |

bundle은 `SHA256SUMS`, x86-64 ELF와 `BUILD-INFO.txt` source commit을 실행
전에 검증했습니다. 하네스는 guest firewall을 변경하지 않고 소유한 SSH
loopback forward로 시험 TLS listener만 관측했습니다.

## 인증서·worker 전환

| 항목 | 결과 |
|---|---|
| supervisor PID | `113725` → `113725`, 보존 |
| 기존 leaf SHA-256 | `deaa6921d2b653f303db02b28a178a12e375ba3e5caad1d401f166512ccade23` |
| 갱신 leaf SHA-256 | `eafe36dd406ee9aa374b8c1f9b09d85e087ee56f2f9ee96ab280386a5e866193` |
| listener leaf SHA-256 | 갱신 leaf와 exact 일치 |
| 갱신 전 시작 요청 | 동일 TLS socket 재사용, 갱신 뒤 origin `404` 응답 완료 |
| 기존 worker drain | `41,025 ms` |

in-flight 검증은 부작용이 없는 존재하지 않는 경로에 complete header와 일부
32-byte POST body만 먼저 보내고, reload 뒤 같은 socket에서 body를 완료하는
방식입니다. `404`는 연결 중단이 아니라 origin application 응답이며, request
body 자체는 artifact에 저장하지 않았습니다.

## 가용성 timeline

| 항목 | 시험 TLS listener | 기존 public HTTPS |
|---|---:|---:|
| 간격 | `100 ms` | `1,000 ms` |
| 표본 | `439` | `44` |
| HTTP `200` | `439` | `44` |
| transport·status 실패 | `0` | `0` |
| 최장 연속 순단 | `0 ms` | `0 ms` |
| 최대 응답 시간 | `1,737 ms` | `1,244 ms` |
| 최대 schedule lag | `2,933 ms` | `249 ms` |

실패가 없었다는 판정은 latency가 없었다는 뜻이 아닙니다. 100ms 순차 probe
중 한 응답이 느려 후속 schedule이 최대 `2,933 ms` 밀렸으며 이를 숨기지
않았습니다. 실제 status와 transport failure는 두 경로 모두 0건입니다.

로컬 원본 evidence checksum은 다음과 같습니다.

- summary JSON: `6c491b7985d4cb4a0d3d40e5e78589f38b82196823681877b20123560147708b`
- 100ms TLS JSONL: `5251a21a201ceeaf46ef3a7bdce4b5e87511eb8ee75aad4d6ad4a2734c85f7c7`
- 1초 public JSONL: `b5e47318440b8ff2ed05d364e9de8e355ff9c777a67035bc416886b8d87994fd`

## 종료 보존과 정리

- guest memory와 balloon driver: 시작 상태로 복원
- Apache, Edge, Control, privileged service와 socket: 모두 `active`
- 시험 binary·config·systemd unit·runtime stage: 제거
- SSH loopback forward와 local listener: 종료 확인
- public HTTPS: 최종 별도 probe `HTTP 200`
- credential과 request body: 증거에 저장하지 않음
- `g7devops.com` 운영 서버: 배포하지 않음

## 남은 검증

public test domain과 ACME staging 환경에서 `certbot renew`, deploy hook, served
leaf exact 비교와 `certbot.timer` 관측을 동일 timeline으로 실행해야
`TLS-006`을 올릴 수 있습니다. 이 단계는 사용자 DNS나 운영 도메인을
묵시적으로 변경하지 않습니다.
