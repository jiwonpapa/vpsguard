# VPSGuard 애플리케이션 보안 경계

VPSGuard의 보안 계층은 origin 애플리케이션을 대체하는 범용 WAF가 아닙니다. 확실히 판정할 수 있는 HTTP metadata와 응답 header만 edge에서 처리하고, request body·query의 문자열 일치만으로 XSS·SQL injection을 자동 차단하지 않습니다.

| 보호 | VPSGuard | G7·origin |
|---|---|---|
| HTTP protocol·Host·forwarded header·body·timeout | 소유 | 신뢰된 proxy 경계와 실제 client IP 사용 |
| `CONNECT`·`TRACE`·`TRACK` | origin 전 거부 | 필요 없음 |
| CSP·HSTS·`nosniff`·referrer policy | typed header와 report-only 관찰 | 외부 CDN·WebSocket·nonce에 맞춘 최종 policy 승인 |
| 인증 공격 | profile auth 경로의 bounded client별 분당 한도 | 계정·session·device별 한도, MFA, 잠금·알림 |
| SQL injection | 성공 주장 안 함 | ORM binding·prepared query, schema validation, DB 최소 권한 |
| XSS | CSP로 영향 완화 | context-aware escaping, HTML sanitizer, nonce 기반 script 정책 |
| CSRF·session | 관리 UI만 VPSGuard가 소유 | G7 CSRF token, cookie scope·rotation·logout 무효화 |

## 적용 순서

1. `csp_mode = "report_only"`로 정상 브라우저·관리자·업로드·Reverb·외부 asset을 관찰합니다.
2. 필요한 source를 `csp_policy` site override에 최소 범위로 추가합니다. policy는 4KiB ASCII이며 CR/LF를 허용하지 않습니다.
3. public HTTPS와 bypass 양쪽이 정상일 때만 HSTS를 켭니다.
4. 인증 분당 한도는 shared IP 오탐을 확인한 뒤 조정합니다. 이 값은 계정별 credential stuffing 방어를 대체하지 않습니다.
5. CSP 위반 0과 G7 origin의 입력 검증·escaping·prepared query 검토가 끝난 뒤에만 `enforce`로 전환합니다.

`protocol_only`에서는 app CSP overlay와 인증 행동 제한을 적용하지 않습니다. 위험 method 거부와 request 비밀값 미저장 같은 protocol 불변조건은 유지합니다.
