# 인프라 거버넌스·하네스 언어 경계

이 문서는 `NFR-009`, `NFR-010`, `OPS-008`, `OPS-010`, `SEC-005`의 실행 경계를 정의합니다. 언어를 하나로 통일하는 것이 목적이 아니라 실패 비용과 권한에 맞는 주력 언어를 사용합니다.

## 소유권

| 영역 | 주력 언어 | 실행 위치 | 불변조건 |
|---|---|---|---|
| 요구사항·Rustdoc·repository 정책 | Python 3.11+ 표준 라이브러리 | 개발 환경·CI | 외부 package와 network 불필요 |
| fixture·fault·evidence·ops plan 조율 | Python 3.11+ 표준 라이브러리 | 개발 환경·CI | argv-only, timeout, redaction, bounded output |
| operation plan·lock·ledger·rollback | Rust | release artifact | typed model과 원자 state |
| systemd·Nginx·nftables·root 파일 변경 | Rust `guard-system` adapter | 운영 VPS | 공통 command audit와 read-back |
| bootstrap·packaging hook·기존 호환 adapter | Shell | CI 또는 운영 VPS | 신규 40줄 이하, 기존 파일 line-count 비증가 |

Python은 운영 VPS의 필수 runtime dependency가 아닙니다. 배포 bundle은 검증된 Rust binary와 필요한 기존 호환 Shell만 포함하며 pip install을 실행하지 않습니다.

## Python command runner

`tools.vpsguard_harness.runner.CommandRunner`는 다음을 강제합니다.

- command string 대신 `tuple[str, ...]` argv만 허용
- `shell=True`, `os.system`과 직접 `subprocess` 호출 금지
- 모든 명령에 label, scope와 최대 3,600초 timeout 요구
- stdout·stderr secret redaction
- 실패를 code, problem, cause, impact와 next action으로 분리
- evidence stdout을 같은 directory의 임시 파일에 fsync한 뒤 원자 교체

Python package에는 production root path와 직접 mutation 명령을 넣지 않습니다. 실제 apply·restore는 Rust `OperationDriver`가 담당하고 Python은 plan·fixture·evidence와 로컬 오케스트레이션만 담당합니다.

## Shell ratchet

[`harness-shell-baseline.json`](../tools/harness-shell-baseline.json)은 현재 Shell 파일별 최대 line 수입니다. 기존 파일은 baseline보다 커질 수 없고 신규 Shell은 40줄을 넘을 수 없습니다. 이전 완료로 줄어든 파일은 낮아진 line 수를 같은 변경에서 baseline에 반영합니다.

baseline 수정은 우회 수단이 아닙니다. 요구사항 또는 wrapper 추가로 불가피한 경우 이유와 줄어든 다른 Shell 범위를 같은 변경에서 기록합니다.

## 빌드 저장공간

Cargo의 dev/test profile은 `debug = 1`, `incremental = false`를 사용하고 외부 dependency debug 정보는 생성하지 않습니다. `build-storage.sh`는 repository의 실제 `target` directory만 검사하며 debug, release, rustdoc, coverage, target-triple과 CI download cache를 재생성 가능 항목으로 분류합니다.

정리 시 `target/release-bundle`, `target/evidence`와 분류되지 않은 파일은 보존합니다. target 자체가 symlink이면 실패하고 어떤 외부 경로도 따라가 삭제하지 않습니다.

초기 적용 측정은 전체 repository gate의 clean rebuild 기준 35.1GiB에서 1.4GiB로 감소했습니다. 정리 plan의 용량 계산은 hard-link inode를 중복 합산하지 않으며 보존 항목과 공유된 inode를 회수 가능 용량으로 표시하지 않습니다.

## 실행

```bash
python3 -W error::ResourceWarning -m unittest discover -s tools/tests -p 'test_*.py'
bash scripts/harness-language-gate.sh
bash scripts/build-storage.sh --check-config
bash scripts/docs-gate.sh
bash scripts/requirements-gate.sh
bash scripts/ops-harness.sh
```

기존 Shell 명령은 호환성을 위해 유지하지만 `docs-gate.sh`, `requirements-gate.sh`, `ops-harness.sh`는 Python module을 호출하는 얇은 wrapper입니다.

## 후속 이전

현재 `deployment-state.sh`, `g7devops-direct-state.sh`와 cutover remote adapter에는 privileged mutation이 남아 있습니다. 이를 Python으로 번역하지 않고 `guard-system`의 실제 `OperationDriver`로 이전합니다. 기존 fixture와 실제 VPS round trip을 old/new parity oracle로 사용하고 단계별 증거가 통과한 뒤 Shell 구현을 제거합니다.
