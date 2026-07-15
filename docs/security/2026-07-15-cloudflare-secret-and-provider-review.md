# Cloudflare 비밀값·provider 보안 개선 보고서

- 날짜: 2026-07-15
- 범위: `SEC-001`, `SEC-004`, `ACT-006`~`ACT-010`, `NFR-008`
- 판정: 로컬 코드·fake API 검증 통과, 실제 Cloudflare test zone release 증거는 미수집
- 외부 읽기 검증: 2026-07-15T10:52:26+09:00 `GET /user/tokens/verify` active 통과. DNS 조회·변경은 수행하지 않음

## 요약

Cloudflare User API Token은 `.env`나 TOML에 저장하지 않습니다. 운영 원본은 `/etc/vps-guard/secrets/cloudflare-token`의 `root:root 0600` 파일이며, 권한을 낮춘 control service에는 Cloudflare 활성화 시에만 systemd credential로 전달합니다. 로컬 작업 사본은 Git에서 제외된 `secrets/` 아래 `0600` 파일만 허용합니다.

## 조치 결과

### SEC-CF-001: token의 `Debug` 노출 가능성 — 해결

- 원인: backend가 평문 `String` token을 가진 채 `Debug`를 파생하면 구조체 debug 출력에 비밀값이 포함될 수 있었습니다.
- 조치: `SecretString`, sensitive Authorization header와 임시 문자열 zeroize를 적용했습니다.
- 검증: `debug_output_redacts_token`, group-readable·symlink·형식 검증과 repository secret 계약을 실행합니다.

### SEC-CF-002: root-only 원본과 unprivileged service의 읽기 불일치 — 해결

- 원인: `root:root 0600` 파일은 `User=vps-guard` service가 직접 읽을 수 없습니다.
- 조치: 원본 권한은 유지하고 선택적 `LoadCredential=` drop-in으로 service별 임시 credential을 전달합니다. 상대 `token_file`은 `$CREDENTIALS_DIRECTORY`에서만 해석합니다.
- 검증: tmpfiles mode와 systemd credential drop-in을 repository contract에 고정했습니다.

### SEC-CF-003: 같은 이름의 임의 첫 record 선택 — 해결

- 원인: name 검색 결과 첫 항목은 A·AAAA·CNAME 중 잘못된 record를 선택할 수 있습니다.
- 조치: 설정에 zone ID와 최대 16개의 정확한 record ID·name·type을 요구하고, API 응답의 ID·name·type·`proxiable`을 모두 read-back합니다.
- 검증: 다중 hostname·중복 ID·wildcard·혼합 CNAME 거부와 정확 record preflight를 테스트합니다.

### SEC-CF-004: 다중 record의 부분 변경·복구 실패 — 해결

- 원인: A 변경 뒤 AAAA 변경이 실패하면 일부만 proxied 상태가 될 수 있고, 완료 전 transaction은 복구할 수 없었습니다.
- 조치: 후속 PATCH 실패 시 이미 변경한 record를 역순 즉시 rollback하고, durable snapshot 이후 모든 중간 단계에서 restore를 허용합니다.
- 검증: 두 번째 record 5xx와 첫 record rollback, 중간 checkpoint restore 테스트를 실행합니다.

## 남은 release gate

- 대화나 issue에 노출된 token은 폐기하고 새 token으로 원본 파일을 원자 교체해야 합니다.
- 실제 test zone에서 User token scope, A·AAAA 전환·복구, 401·403·429·5xx·timeout을 검증해야 합니다.
- `cf-ray` 외부 경유 확인 전에는 origin lock을 적용하지 않았다는 VPS 증거가 필요합니다.
- nftables 적용 전후 SSH와 비웹 port가 변하지 않았다는 kernel read-back 증거가 필요합니다.
