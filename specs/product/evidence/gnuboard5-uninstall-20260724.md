---
title: gnuboard5 OPS-006 2GB Owned-only Uninstall Evidence
status: pilot-verified
doc_type: operational-evidence
requirements:
  - OPS-006
verified_at: 2026-07-24
target: gnuboard5
bundle_source_commit: 5dc8eba4992070637d340196cbcab4a407f0da04
harness_commit: 4a058212d2dbd41bba3e91961512bc4146c11958
release_workflow_run: 30075198366
---

# gnuboard5 2GB owned-only uninstall 증거

## 판정

`OPS-006`은 **VPS_PASS**입니다. 검증된 x86_64 bundle과 격리 Ubuntu 24.04
VM에서 Apache public HTTPS를 직접 경로로 전환한 뒤 VPSGuard 소유 binary,
release, systemd unit과 PAM 파일을 실제 제거했습니다. 사이트·인증서·SSH·
방화벽·설정·runtime state를 유지한 상태에서 versioned release와 deployment
snapshot을 복구하고 guarded topology를 재활성화했습니다.

## 실행 대상

| 항목 | 검증값 |
|---|---|
| VM | 격리 VM `gnuboard5`, Ubuntu 24.04.4 LTS, 4 vCPU |
| bundle | `x86_64-unknown-linux-gnu`, source `5dc8eba4992070637d340196cbcab4a407f0da04` |
| release workflow | [run 30075198366](https://github.com/jiwonpapa/vpsguard/actions/runs/30075198366), SUCCESS |
| harness | `4a058212d2dbd41bba3e91961512bc4146c11958` |
| memory | libvirt `8,388,608 KiB` → `2,097,152 KiB` → `8,388,608 KiB` |
| 2GB guest read-back | `MemTotal 1,840,328 kB` |
| release 보존 | 40-hex release directory `4`, allowlist binary `16` |

bundle은 `SHA256SUMS`, x86-64 ELF, 네 packaged binary 실행과
`BUILD-INFO.txt` source commit을 검증했습니다. 자체 서명 시험 인증서는
명시한 guest CA를 `curl --cacert`에 전달했으며 TLS 검증을 비활성화하지
않았습니다.

## 제거·복구 결과

| 단계 | 결과 |
|---|---:|
| Apache direct bypass | `1,201 ms` |
| owned-only uninstall | `1,577 ms` |
| deployment restore | `2,418 ms` |
| guarded re-enable | `1,857 ms` |
| 전체 실행 | `58,453 ms` |

uninstall 직후 Apache는 `active`, Edge는 inactive이며 제거 대상 path는 모두
부재했습니다. public HTTPS는 `200`을 유지했고 `x-vps-guard` header는 direct
bypass 동안 부재했습니다. 그 뒤 release tree, owned deployment와 guarded
Apache topology를 순서대로 복구했습니다.

## 가용성·보존

| 항목 | 결과 |
|---|---|
| 100ms public probe | `211/211` HTTP `200` |
| transport·status 실패 | `0` |
| 최장 연속 순단 | `0 ms` |
| 최대 schedule lag | `101 ms` |
| 사이트 sentinel | exact 보존 |
| 인증서와 private-key metadata | exact 보존 |
| SSH listener와 UFW rules | exact 보존 |
| non-web listeners | exact 보존 |
| config와 runtime state | exact 보존 |
| request·response body / credential 저장 | 없음 |

로컬 원본 evidence checksum은 다음과 같습니다.

- summary JSON: `806384e67493a3a4842184ed64a428a874727a1d5d93441f46fc3ea9c4f50598`
- 100ms probe JSONL: `b3318b96d70c94a0ba4a356024aa79e593320103f62137464c383768c7687a1f`

## 실패에서 고정한 회귀

- Apache가 public 80/443을 소유한 상태에서 Edge를 먼저 시작하지 않도록
  deployment snapshot을 typed Apache bypass 완료 뒤 생성합니다.
- 자체 서명 시험 인증서는 explicit guest CA가 없으면 uninstall을 거부합니다.
- 제거된 systemd unit의 정상 read-back인 `not-found` exit를 허용합니다.
- 실패 실행도 release·deployment·Apache topology와 VM memory를 자동 복구하며,
  최종 성공 실행은 recovery snapshot 7개를 보존했습니다.

## 종료 상태

- Apache, Edge, Control, privileged service와 socket: 모두 `active`
- guest memory: `MemTotal 8,131,784 kB`
- public HTTPS: `HTTP 200`, `x-vps-guard: guard-edge`
- 원래 release symlink와 protected fingerprint: exact 일치
- run-created Apache stage, guest bundle stage와 release snapshot: 제거
- `g7devops.com` 운영 서버: 배포하지 않음
