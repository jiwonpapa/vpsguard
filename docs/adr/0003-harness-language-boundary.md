# ADR 0003: 인프라 거버넌스·하네스 주력 언어 경계

- 상태: 승인
- 날짜: 2026-07-17
- 요구사항: NFR-009, OPS-008, OPS-010, SEC-005

## 문맥

저장소에는 29개, 3,696줄의 Shell 하네스가 있었고 snapshot manifest, checksum, SSH quoting, fixture, plan과 rollback 검증이 여러 파일에 분산돼 있었습니다. 반면 Rust에는 typed operation plan·lock·ledger·timeout·rollback engine이 있으나 실제 privileged adapter 일부는 Shell에 남아 있었습니다.

모든 하네스를 Python으로 번역하면 두 번째 production transaction engine이 생기고 운영 VPS의 Python·pip 상태가 새 배포 의존성이 됩니다. Shell을 계속 주력 언어로 사용하면 구조화 오류, typed fixture와 세밀한 fault test 비용이 계속 증가합니다.

## 결정

- Python 3.11+ 표준 라이브러리를 repository governance, fixture·evidence와 로컬·CI orchestration의 주력 언어로 사용합니다.
- production root mutation, operation lock·ledger·rollback과 OS adapter는 Rust가 소유합니다.
- Shell은 bootstrap, package hook과 기존 compatibility adapter에 한정합니다.
- Python은 argv-only 공통 runner를 사용하고 timeout, output redaction과 구조화 오류를 강제합니다.
- 외부 Python package는 추가하지 않습니다. Ubuntu CI의 Python과 개발 환경만 사용하며 운영 bundle에 Python package를 설치하지 않습니다.
- 기존 Shell은 file별 line-count baseline을 넘길 수 없고 신규 Shell은 40줄 이하로 제한합니다.

## 결과

- `docs-gate.sh`, `requirements-gate.sh`, `ops-harness.sh`는 Python 구현을 호출하는 얇은 wrapper가 됩니다.
- Shell 총량은 3,696줄에서 3,543줄로 감소합니다.
- Python unit와 language policy가 `shell=True`, `os.system`, 공통 runner 우회, hard-coded production root path, 비표준 library와 Shell 증가를 거부합니다.
- Python startup과 memory는 개발·CI gate에만 영향을 주므로 edge/control binary와 2GB VPS runtime RSS에는 변화가 없습니다.
- privileged Shell 제거는 실제 Rust `OperationDriver`와 VPS parity 증거가 준비되는 후속 배치에서 수행합니다.
