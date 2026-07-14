# 아키텍처와 기존 소스 재사용

## 결론

새 프록시를 처음부터 만들지 않습니다. 월척웹에서 구현했던 Pingora `edge_proxy`를 복구·분리하고, 가드 제품에 필요한 탐지와 자동 대응을 확장합니다.

## 기존 자산

활성 `rest-middleware`에서는 `87c0f0e61` 커밋으로 PoC가 제거됐지만 이전 Git 이력에 구현이 남아 있습니다.

```bash
git show 87c0f0e61^:crates/edge_proxy/src/main.rs
```

확인된 기존 기능:

- Pingora 0.8 기반 reverse proxy
- HTTP와 TLS listener
- upstream 연결과 timeout
- trusted proxy·forwarded header 정규화
- canonical host redirect와 허용 host 검사
- IP·CIDR 차단
- 관리자 경로 ACL
- 일반·업로드·고위험 경로별 rate limit
- 요청 body 크기 제한
- request ID, 응답 필터와 운영 로그
- systemd 배포와 staging smoke 절차

기존 코드는 PoC였으므로 그대로 공개 운영에 투입하지 않습니다. 필요한 부분을 새 저장소로 옮긴 뒤 의존성, 라이선스, 테스트와 실패 정책을 다시 감사합니다.

## 목표 구조

```text
                         +----------------------+
                         | guard-control        |
                         | score / state / UI   |
                         +----+------------+----+
                              |            |
                         local IPC     provider API
                              |            |
사용자 -> guard-edge(Pingora) |       Cloudflare/VPS
             :80/:443         |            |
                 |            |            |
                 +------------+------------+
                 |
                 v
        Nginx/Apache 127.0.0.1:8080
                 |
                 v
        PHP-FPM -> MySQL / Redis
                 ^
                 |
           guard-agent
```

## 컴포넌트

### `guard-edge`

항상 요청 경로에 존재하는 데이터 플레인입니다.

- TLS 종료
- 모든 요청의 최소 비용 측정
- 마지막으로 승인된 정책을 메모리에서 실행
- 속도 제한, 차단, 검증과 upstream 전달
- control 장애 시 정상 요청을 통과시키고 정적 안전 한도는 유지
- 정책 계산, 외부 API와 웹 UI는 포함하지 않음

### `guard-control`

- 봇·비용 점수 계산
- 방어 상태 머신과 히스테리시스
- Cloudflare DNS와 방화벽 어댑터
- 정책 서명과 edge 반영
- 사건 타임라인, 설정과 웹 UI

### `guard-agent`

- OS, 네트워크와 프로세스 상태
- PHP-FPM status
- MySQL의 제한된 관측 계정
- Redis와 웹서버 상태
- 민감한 애플리케이션 데이터는 수집하지 않음

초기 구현은 `guard-control`과 `guard-agent`를 한 프로세스로 묶을 수 있지만 `guard-edge`는 분리합니다. 분석기나 UI의 장애가 요청 처리 장애로 전파되면 안 됩니다.

## 인증서

Pingora가 80/443을 직접 받으면 TLS 인증서를 사용하는 주체도 Pingora가 됩니다.

초기 정책:

1. Certbot 또는 검증된 ACME 클라이언트가 발급·갱신합니다.
2. HTTP-01 검증 경로를 edge가 안전하게 전달하거나 DNS-01을 사용합니다.
3. edge는 PEM 인증서와 키를 읽고 무중단 reload합니다.
4. 인증서와 개인키는 reset·업데이트 과정에서 보존합니다.
5. 만료 임박, 갱신 실패와 실제 제공 인증서를 별도로 검사합니다.

자체 ACME 클라이언트 구현은 MVP 범위에서 제외합니다.

## 아직 필요한 기능

- 실제 80/443 direct termination 운영 검증
- 다중 도메인 SNI와 인증서 선택
- WebSocket·대용량 업로드 회귀 테스트
- 봇 행동·자원 비용 점수
- 동적 정책 배포와 만료
- PHP-FPM·MySQL·Redis 수집기
- Cloudflare 프록시 ON/OFF와 상태 확인
- 원본 방화벽 잠금과 안전한 복구
- 웹 관리 화면과 사건 리포트
- edge 장애 시 Nginx/Apache 직접 공개로 전환하는 비상 bypass

## 장애 원칙

- control 장애: edge는 마지막 정상 정책과 정적 안전 한도로 계속 서비스합니다.
- agent 장애: 자원 연계 자동 조치를 멈추고 요청 기반 제한만 유지합니다.
- provider API 장애: 로컬 보호를 유지하고 외부 전환 실패를 명시합니다.
- edge 반복 장애: 검증된 bypass 절차로 기존 웹서버가 80/443을 회수합니다.
- 정책 오류: 새 정책을 거부하고 마지막 정상 정책으로 되돌립니다.
- SSH와 관리 접속: 자동 방화벽 변경의 보호 대상에서 제외합니다.

## 별도 프로젝트 경계

`g7-installer`는 새 VPS를 설치하는 역할만 유지합니다. 새 프로젝트가 안정화된 뒤 선택 설치 항목으로 연결할 수는 있지만, 가드의 런타임 상태·업데이트·방어 정책을 installer가 소유하면 안 됩니다.

참고 자료:

- Pingora: <https://github.com/cloudflare/pingora>
- 기존 제거 커밋: `rest-middleware`의 `87c0f0e61`
