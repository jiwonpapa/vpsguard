# VPSGuard 애플리케이션 보안 경계

VPSGuard의 내장 보안 계층은 origin 애플리케이션을 대체하는 범용 WAF가 아닙니다. edge는 확실히 판정할 수 있는 HTTP metadata·framing·행동 한도와 응답 header를 처리합니다. SQLi·XSS signature가 필요하면 별도 Apache/Nginx ModSecurity·OWASP CRS adapter를 detection-only부터 선택 적용합니다.

| 보호 | VPSGuard | G7·origin |
|---|---|---|
| HTTP protocol·Host·forwarded header·body·timeout | 소유 | 신뢰된 proxy 경계와 실제 client IP 사용 |
| `CONNECT`·`TRACE`·`TRACK` | origin 전 거부 | 필요 없음 |
| CSP·HSTS·`nosniff`·referrer policy | typed header와 report-only 관찰 | 외부 CDN·WebSocket·nonce에 맞춘 최종 policy 승인 |
| 인증 공격 | profile auth 경로의 bounded client별 분당 한도 | 계정·session·device별 한도, MFA, 잠금·알림 |
| VPSGuard 관리자 인증 | Ubuntu 기본은 Linux-PAM `vpsguard-admin`+TOTP, 호환 mode는 전용 ID·Argon2id+TOTP, bounded 영속 session | 서버 계정 수명주기 또는 local 복구 code 운영 |
| SQL injection | 선택형 CRS adapter로 알려진 fixture 보조 차단 | ORM binding·prepared query, schema validation, DB 최소 권한 |
| XSS | 선택형 CRS adapter와 CSP로 차단·영향 완화 | context-aware escaping, HTML sanitizer, nonce 기반 script 정책 |
| CSRF·session | 관리 UI만 VPSGuard가 소유 | G7 CSRF token, cookie scope·rotation·logout 무효화 |

## 적용 순서

1. `csp_mode = "report_only"`로 정상 브라우저·관리자·업로드·Reverb·외부 asset을 관찰합니다.
2. 필요한 source를 `csp_policy` site override에 최소 범위로 추가합니다. policy는 4KiB ASCII이며 CR/LF를 허용하지 않습니다.
3. public HTTPS와 bypass 양쪽이 정상일 때만 HSTS를 켭니다.
4. 인증 분당 한도는 shared IP 오탐을 확인한 뒤 조정합니다. 이 값은 계정별 credential stuffing 방어를 대체하지 않습니다.
5. CSP 위반 0과 G7 origin의 입력 검증·escaping·prepared query 검토가 끝난 뒤에만 `enforce`로 전환합니다.
6. 외부 WAF는 `off` → `detection_only` → app별 exclusion → `tuned_enforce` 순서로 올리고 로그인·검색·글쓰기·업로드를 실제 browser로 회귀 검증합니다.

`protocol_only`에서는 app CSP overlay와 인증 행동 제한을 적용하지 않습니다. 위험 method 거부와 request 비밀값 미저장 같은 protocol 불변조건은 유지합니다.

## 관리 콘솔 인증

- Ubuntu 단독 설치의 기본 provider는 Linux-PAM입니다. `pam_authenticate`, `pam_acct_mgmt`와 `vpsguard-admin` group 검사를 모두 통과한 non-root 사용자만 허용하며 별도 root-only TOTP credential을 요구합니다.
- PAM 비밀번호는 bounded blocking worker의 인증 호출에만 전달하고 DB·journal·artifact에 저장하지 않습니다. UI에는 인증 실패 원인을 계정 존재 여부와 무관한 일반 오류로 반환합니다.
- JW-agent 연동 여부와 무관하게 VPSGuard 일상 관리는 직접 HTTPS UI에서 수행하며 SSH·terminal은 설치·비상 복구 경로입니다.
- 아래 local provider는 PAM을 사용할 수 없는 호환 설치에서만 사용합니다.
- 최초 설정은 peer credential을 확인한 local admin socket의 64자리 단회 code로 시작합니다. code는 계정·TOTP 등록에 한 번 소비되며 일상 로그인에는 사용하지 않습니다.
- 관리자 ID는 Linux·SSH·root 계정과 연결하지 않습니다. 비밀번호는 Argon2id PHC verifier만 저장하고 미등록 ID도 dummy verifier를 거쳐 일반화된 오류를 반환합니다.
- TOTP seed는 비밀번호 유래 Argon2id key와 XChaCha20-Poly1305로 봉인합니다. 복구 code 10개는 최초 등록 직후 한 번만 표시하고 HMAC digest만 저장합니다.
- session과 CSRF 원문은 저장하지 않습니다. 12시간 session digest를 SQLite에 최대 128개 보존해 Control 재시작 후 복원하고 logout 또는 actor 전체 폐기를 지원합니다.
- 인증 SQLite 작업과 Argon2id는 async request executor를 막지 않도록 blocking task에서 실행하며 edge request hot path에는 들어가지 않습니다.
