---
title: x86_64 and aarch64 Release Matrix Evidence
status: auto-verified
doc_type: automated-evidence
requirements:
  - OPS-007
verified_at: 2026-07-24
source_commit: 9477e0a5432d8d16e95507e6c0347cbe054631a8
workflow_run: 30062627656
---

# x86_64·aarch64 릴리스 매트릭스 증거

## 판정

`OPS-007`은 **AUTO_PASS**입니다. 동일 commit을 x86_64와 aarch64 Ubuntu 24.04
네이티브 runner에서 빌드했고 checksum, ELF architecture, 세 개 CycloneDX SBOM,
패키지 실행 파일 네 개의 실제 실행과 example config 검사를 모두 통과했습니다.
성공한 실행 파일 8개는 정확한 repository·workflow·source commit 조건으로 GitHub
SLSA provenance를 다시 검증했습니다.

이 증거는 Actions의 자동 검증입니다. 실제 2GB VPS 설치·update 증거는 아니므로
`VPS_PASS`로 승격하지 않습니다.

## 실행

- workflow: `Release artifacts`
- run: <https://github.com/jiwonpapa/vpsguard/actions/runs/30062627656>
- source: `9477e0a5432d8d16e95507e6c0347cbe054631a8`
- toolchain: Rust `1.96.0`, LLVM `22.1.2`
- aarch64 job `89387157833`: PASS, 4분 26초
- x86_64 job `89387157826`: PASS, 3분 7초

| 대상 | artifact ID | 압축 크기 | 판정 |
|---|---:|---:|---|
| aarch64-unknown-linux-gnu | `8585136103` | 14,743,099 bytes | PASS |
| x86_64-unknown-linux-gnu | `8585118264` | 15,581,118 bytes | PASS |

두 artifact의 `SHA256SUMS` 전체 검증과 세 SBOM의 CycloneDX JSON 구조 검사를
다운로드 후 다시 통과했습니다. `BUILD-INFO.txt`의 target, host와 source commit도
각 artifact와 일치했습니다.

## 실행 파일 SHA-256

| 대상 | vps-guard | control | edge | privileged |
|---|---|---|---|---|
| aarch64 | `4936514d5070…a444` | `a6294a9281b6…9381` | `feaa1a9897cf…aefe` | `f4ab64e27eb1…0f16` |
| x86_64 | `c5ab389d60e2…e2aa` | `d92305e011c5…cfbd` | `5d5290f888cd…190b` | `f5402ccd5a63…8278` |

GitHub CLI 검증은 각 파일에 다음 조건을 강제했습니다.

```text
repository=jiwonpapa/vpsguard
signer_workflow=jiwonpapa/vpsguard/.github/workflows/release.yml
source_digest=9477e0a5432d8d16e95507e6c0347cbe054631a8
predicate_type=https://slsa.dev/provenance/v1
result=PASS (8/8)
```

## 제한

- x86_64 artifact는 격리 Ubuntu VM의 2GB 보호 정책 파일럿에서도 실행했습니다.
  결과와 원복 증거는 [UI-018 2GB 보호 정책 증거](gnuboard5-ui018-policy-20260724.md)에
  분리했습니다.
- `NFR-008`의 2GB VPS binary·RSS dependency 비교는 이 증거 범위가 아닙니다.
