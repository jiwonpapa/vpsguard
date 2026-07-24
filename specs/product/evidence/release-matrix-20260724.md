---
title: x86_64 and aarch64 Release Matrix Evidence
status: auto-verified
doc_type: automated-evidence
requirements:
  - OPS-007
verified_at: 2026-07-24
source_commit: 2018e3d7a7f1c1480841035174d6de5d551ed62a
workflow_run: 30059131425
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
- run: <https://github.com/jiwonpapa/vpsguard/actions/runs/30059131425>
- source: `2018e3d7a7f1c1480841035174d6de5d551ed62a`
- toolchain: Rust `1.96.0`, LLVM `22.1.2`
- aarch64 job `89376971534`: PASS, 3분 53초
- x86_64 job `89376971574`: PASS, 5분 19초

| 대상 | artifact ID | 압축 크기 | 판정 |
|---|---:|---:|---|
| aarch64-unknown-linux-gnu | `8583923970` | 14,736,090 bytes | PASS |
| x86_64-unknown-linux-gnu | `8583944797` | 15,574,862 bytes | PASS |

두 artifact의 `SHA256SUMS` 전체 검증과 세 SBOM의 CycloneDX JSON 구조 검사를
다운로드 후 다시 통과했습니다. `BUILD-INFO.txt`의 target, host와 source commit도
각 artifact와 일치했습니다.

## 실행 파일 SHA-256

| 대상 | vps-guard | control | edge | privileged |
|---|---|---|---|---|
| aarch64 | `a9a0c8dc0c64…e8ff1` | `36c6dd240cd7…28786` | `353930795e12…c62b` | `152df5ee4923…b2ee` |
| x86_64 | `18f70e8deba6…a4625` | `31344b22d6e1…dc07` | `a708e8f946fb…dda2` | `30a6d4c22446…51e7` |

GitHub CLI 검증은 각 파일에 다음 조건을 강제했습니다.

```text
repository=jiwonpapa/vpsguard
signer_workflow=jiwonpapa/vpsguard/.github/workflows/release.yml
source_digest=2018e3d7a7f1c1480841035174d6de5d551ed62a
predicate_type=https://slsa.dev/provenance/v1
result=PASS (8/8)
```

## 제한

- GitHub Actions의 Node.js 20 호환 경고가 있었지만 step 실패나 artifact·attestation
  검증 실패는 없었습니다. pin된 action의 Node 24 전환 release가 확인되면 별도
  유지보수 배치에서 갱신합니다.
- `NFR-008`의 2GB VPS binary·RSS dependency 비교는 이 증거 범위가 아닙니다.
