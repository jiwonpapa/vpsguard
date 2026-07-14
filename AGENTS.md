# VPSGuard Agent Instructions

## 필수 선행 읽기

코드나 문서를 변경하기 전에 다음 순서로 읽습니다.

1. `DEVELOPMENT_CONSTITUTION.md`
2. `specs/product/MASTER_SDD.md`
3. `specs/product/06-requirements-contracts.md`
4. 관련 요구사항의 `specs/product/07-verification-traceability.md` 항목
5. `specs/product/08-implementation-backlog.md`의 현재 배치

## 구현 규칙

- 요구사항 ID 없는 기능 구현을 시작하지 않습니다.
- 관련 테스트를 먼저 추가하거나 함께 추가합니다.
- 모든 Rust module 상단에 `//!` rustdoc를 작성합니다.
- 상태, 정책, 오류와 provider 단계는 typed model로 구현합니다.
- `guard-edge` hot path에 동기 IPC, DB, disk write와 외부 API를 넣지 않습니다.
- SSH, 인증서, 기존 ingress와 사용자 데이터 보존 불변조건을 우선합니다.
- 비밀값과 원본 request body를 fixture, log와 artifact에 넣지 않습니다.
- 구현과 문서가 달라지면 같은 변경에서 함께 수정합니다.

## 작업 범위

- 이 저장소는 VPSGuard만 소유합니다.
- G7 Installer나 GnuBoard 원본 저장소를 이 작업의 일부로 수정하지 않습니다.
- 기존 월척 Pingora 코드는 기준 commit과 라이선스 기록 후 가져옵니다.
- unrelated change를 되돌리거나 한 커밋에 섞지 않습니다.

## 검증

새 저장소의 gate가 준비되면 최소 다음을 실행합니다.

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items
cargo test --workspace --all-features
cargo audit
cargo deny check
bun install --frozen-lockfile
bun run build
bun test
```

TLS, provider, ingress, bypass와 성능 변경은 단위 테스트만으로 완료하지 않고 관련 E2E·fault·2GB VPS 증거를 요구합니다.

## 문체

- 코드 식별자는 영어를 사용합니다.
- 사용자 UI와 사용자 문서는 자연스러운 한국어를 기본으로 합니다.
- 오류는 문제, 원인, 영향과 다음 조치를 분리합니다.
- 의미 없는 설명 주석 대신 rustdoc와 불변조건을 기록합니다.
