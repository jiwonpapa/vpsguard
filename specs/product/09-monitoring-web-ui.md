---
title: VPS Guard Monitoring Web UI
status: draft-implementation-ready
doc_type: contract
source_of_truth: true
spec_version: 1
last_reviewed: 2026-07-14
---

# 독립 모니터링 웹 UI

## 1. 역할

웹 UI는 VPS Guard의 독립 운영 콘솔입니다. 단순 로그 뷰어나 설치 화면이 아니라 다음 세 질문에 즉시 답해야 합니다.

1. 지금 사이트가 정상인가
2. 누가 어떤 요청으로 자원을 사용하고 있는가
3. 현재 어떤 방어가 왜 적용됐고 어떻게 복구하는가

## 2. 범위 경계

### 포함

- HTTP 요청과 연결 상태
- 외부 IP·prefix·ASN·국가·User-Agent family
- 경로·메서드·status·latency·bytes·cache 결과
- 봇 가능성, 신뢰도와 자원 비용
- CPU, memory, swap, network와 disk wait
- Nginx, PHP-FPM, MySQL과 Redis 상태
- 로컬 제한·차단·challenge
- Cloudflare, 원본 방화벽과 TLS 실제 상태
- 사건 타임라인, 자동 조치와 복구

### 제외

- tcpdump 같은 원시 패킷 캡처
- 전체 systemd·process 관리자
- 파일 관리자와 터미널
- 범용 로그 검색·SIEM
- DB 쿼리 실행기
- 애플리케이션 회원·게시물 관리
- VPS 요금 청구 시스템

이 경계를 넘는 기능은 운영 위험과 지원 범위를 키우므로 별도 제품 요구가 확인되기 전에는 추가하지 않습니다.

## 3. 화면 구조

```text
+------------------------------------------------------------------+
| VPS Guard | 현재 모드 | 연결 상태 | 마지막 갱신 | 빠른 명령       |
+------------+-----------------------------------------------------+
| 개요       |                                                     |
| 실시간     |                 작업 영역                            |
| 외부 접속  |                                                     |
| 경로/자원  |                                                     |
| 사건       |                                                     |
| 정책       |                                                     |
| 설정       |                                                     |
+------------+--------------------------------------+--------------+
| 상태 표시줄: edge / origin / agent / CF / TLS / data freshness   |
+------------------------------------------------------------------+
```

- 데스크톱은 고정 app shell과 밀도 높은 표·그래프를 사용합니다.
- 모바일은 상태 확인과 긴급 중지만 우선 제공하고 복잡한 정책 편집은 데스크톱으로 안내합니다.
- 마케팅형 hero, 장식용 카드 반복과 중첩 카드를 사용하지 않습니다.
- 상세 정보는 우측 inspector 또는 전체 화면 detail로 표시합니다.

## 4. 개요

### 4.1 최상단 상태

- 현재 mode와 시작 시각
- 자동 대응 활성·수동 고정 여부
- 현재 가장 중요한 판정 근거 3개
- 정상 복구에 남은 안정 시간
- edge, origin, agent, provider와 TLS 상태

단순 `주의`, `대기`만 표시하지 않습니다.

```text
주의
검색 경로 비용이 평시보다 4.8배 증가했습니다.
PHP-FPM active 78%, MySQL p95 420ms이며 6개 IP가 요청의 71%를 차지합니다.
현재 검색 경로에 30 req/min 제한을 적용 중입니다.
```

### 4.2 핵심 실시간 지표

- requests/sec
- active connections
- inbound/outbound throughput
- p50, p95, p99 latency
- upstream p95
- 2xx, 3xx, 4xx, 5xx 비율
- allowed, throttled, challenged, denied 요청
- PHP-FPM pressure
- MySQL pressure

각 지표는 현재값, 직전 비교 구간과 상태 색상을 함께 제공합니다. 숫자만 빨간색으로 만들지 않고 임계치와 원인을 tooltip에서 설명합니다.

### 4.3 비용 절감 요약

- upstream에 전달하지 않은 고비용 요청
- 보호 전후 PHP-FPM·DB pressure 변화
- 자동 대응으로 줄인 사건 지속시간
- Cloudflare 비상 모드 사용시간
- 추정 절감액과 계산 근거

추정값에는 `추정` 표시와 산정식을 반드시 붙입니다.

## 5. 실시간 트래픽

### 5.1 그래프

동일 시간축에서 다음 series를 선택해 비교합니다.

- RPS와 active connections
- inbound/outbound bytes/sec
- edge와 upstream latency
- response status
- allow/throttle/challenge/deny
- unique client와 unique route

기본 구간은 15분이며 1분, 1시간, 24시간과 30일 집계로 전환합니다. zoom과 특정 시점 사건 표시를 지원합니다.

### 5.2 실시간 요청 표본

전체 요청을 DOM과 DB에 무한 저장하지 않습니다. 민감값을 제거한 bounded sample만 표시합니다.

| 필드 | 표시 원칙 |
|---|---|
| 시각 | millisecond는 상세에서만 표시 |
| client | IP 또는 권한에 따른 마스킹 값 |
| 위치 | local DB가 있을 때 국가·ASN |
| method/path | query 값은 기본 제거 |
| status | edge 응답과 upstream 응답 구분 |
| latency | edge total과 upstream 분리 |
| bytes | request와 response 분리 |
| decision | allow, throttle, challenge, deny |
| reason | 대표 reason code와 한글 설명 |

실시간 표본은 디버깅 보조이며 통계의 정본으로 사용하지 않습니다.

## 6. 외부 접속 IP

### 6.1 목록

| 열 | 내용 |
|---|---|
| 상태 | 정상·관찰·제한·검증·차단 |
| IP | IPv4·IPv6, 권한별 마스킹 가능 |
| 국가/ASN | local DB 근거, 없으면 알 수 없음 |
| 처음/마지막 접속 | 선택 구간 기준 |
| 요청 | 전체 요청과 RPS |
| 경로 | 고유 경로 수와 상위 경로 |
| 전송량 | 요청·응답 bytes |
| 오류 | 4xx·5xx·timeout |
| 봇 가능성 | 점수와 신뢰 수준 |
| 자원 비용 | weighted cost와 실제 upstream time |
| 검증 | 검색봇·guard session·challenge 상태 |
| 조치 | 적용 정책과 남은 TTL |

지원 필터:

- 상태와 조치
- 국가·ASN
- IP·CIDR
- route class
- bot likelihood와 resource cost 범위
- response status
- verified crawler 여부
- 선택 시간 구간

정렬은 요청량, 비용, 전송량, 오류율, 마지막 접속과 봇 가능성을 지원합니다.

### 6.2 IP 상세

- 시간별 요청·bytes·latency
- 상위 method/path와 route class
- 요청 간격, unique URL과 asset 요청 비율
- cookie/session 연속성 여부
- User-Agent family와 변화
- robots 정책 위반 신호
- PHP·DB pressure와의 시간 상관관계
- trust·bot·cost 점수의 근거별 기여
- 과거 사건과 조치 이력
- 현재 TTL 차단·제한·검증 상태

IP 상세에서는 다음 명령을 제공합니다.

- 10분·1시간·24시간 TTL 차단
- 선택 route만 제한
- 관찰 대상 등록
- 오탐으로 표시하고 차단 해제
- verified crawler 재검증

영구 차단은 MVP UI에서 제공하지 않습니다.

## 7. 경로와 자원

### 7.1 경로 목록

- normalized route
- route class
- 요청량과 unique clients
- p95 edge/upstream latency
- response bytes
- 오류·timeout
- cache hit/miss
- weighted resource cost
- 현재 보호 정책

원본 query 전체를 route key로 사용해 cardinality 공격을 허용하지 않습니다. 숫자 ID, UUID와 검색어는 profile 규칙으로 정규화합니다.

### 7.2 자원 상관 화면

동일 시간축으로 다음을 겹쳐 봅니다.

- route class RPS
- PHP-FPM active·queue·max children
- MySQL connections·slow query·lock wait
- Redis hit/miss·memory
- CPU·load·memory·swap·disk wait

사용자는 특정 spike를 선택해 해당 시간에 비용을 만든 IP와 경로로 이동할 수 있어야 합니다.

## 8. 사건과 대응

### 8.1 사건 목록

- 시작·종료 시각
- 최고 심각도
- 대표 원인
- 영향받은 route·resource
- 자동·수동 조치
- Cloudflare 사용 여부
- 현재 복구 상태
- 정상화까지 걸린 시간

### 8.2 사건 상세

```text
탐지 -> 근거 확보 -> 로컬 제한 -> 효과 확인
     -> 외부 전환 요청 -> 실제 경유 확인 -> 원본 보호
     -> 안정화 -> 제한 해제 -> DNS only 복구
```

각 단계에 입력값, 실행자, 시작·종료, API 결과, read-back 결과와 실패 시 다음 조치를 표시합니다.

### 8.3 명령 잠금

Cloudflare 전환, 원본 방화벽 변경과 복구 중에는 충돌하는 다른 명령을 비활성화합니다. 현재 실행 중인 단계와 진행률을 표시하며 새로고침 후에도 서버 state에서 복원합니다.

## 9. 정책 화면

- 현재 mode와 자동 전이 여부
- route profile과 비용 가중치
- 정적 body·timeout 한도
- watch·local guard·emergency 조건
- 복구 안정 구간
- 허용·관찰·차단 규칙과 TTL
- verified crawler 상태
- policy version, 생성 시각, 적용 edge와 hash

정책 편집은 다음 절차를 따릅니다.

1. 수정
2. 변경 diff
3. schema·semantic validation
4. 예상 영향 preview
5. 적용 확인
6. edge dry-load
7. 원자 반영
8. 실제 version read-back

## 10. 설정 화면

- origin과 domain
- TLS 인증서 상태
- collector 연결 상태
- Cloudflare zone·record와 token 권한 검사
- retention과 IP 표시 정책
- 알림과 수동 고정
- update·backup·bypass 상태

token과 private key 본문은 표시하지 않습니다. 비밀값 변경은 별도 일회성 입력과 즉시 마스킹을 사용하며 브라우저 저장소에 저장하지 않습니다.

## 11. 도움말

어려운 용어 옆에는 `?` 도움말을 제공합니다.

도움말은 다음 네 항목을 짧게 설명합니다.

1. 무엇을 측정하는가
2. 왜 중요한가
3. 현재 값이 어떤 의미인가
4. 어떤 자동 조치에 사용되는가

tooltip은 viewport 밖으로 잘리지 않아야 하고, 긴 설명은 click 가능한 help popover 또는 우측 도움말 panel로 전환합니다. 용어 전체 목록은 UI 안의 도움말에서 검색할 수 있어야 합니다.

## 12. 데이터 상태 표시

다음 상태를 숫자와 분리해 명확히 표시합니다.

- live: 정상 갱신
- delayed: 예상 주기보다 늦음
- stale: 판단에 사용할 수 없음
- unavailable: collector 또는 provider 미설정
- error: 수집·검증 실패

stale 값을 최신 정상값처럼 보여주는 것을 금지합니다. 서버 시각과 브라우저 시각 차이도 표시합니다.

## 13. 접근과 보안

- 기본 URL은 `http://127.0.0.1:7727`입니다.
- SSH tunnel을 기본 접속 방식으로 사용합니다.
- public bind는 공개 기능으로 제공하지 않습니다.
- one-time bootstrap token은 짧게 만료되고 재사용할 수 없습니다.
- session cookie는 HttpOnly, SameSite=Strict를 사용합니다.
- 모든 변경 명령에 CSRF와 idempotency 검사를 수행합니다.
- 읽기, 차단, provider 변경과 복구 권한을 분리합니다.
- root 비밀번호와 SSH private key를 웹에서 받지 않습니다.

## 14. 프런트엔드 기술

운영 UI는 CSR SPA로 구현합니다. 선택 근거와 대안은 `docs/adr/0001-operations-console-spa.md`를 따릅니다.

- Rust 서버가 검증된 SPA build asset을 binary에 포함
- React와 strict TypeScript
- Bun package manager와 고정된 `bun.lock`
- Vite static build와 Tailwind CSS CLI
- 필요한 shadcn/ui source component만 선별 도입
- TanStack Router와 Query로 URL·REST snapshot 상태 관리
- light/dark theme
- SVG 직접 작성 대신 검증된 icon set 사용
- 서버 -> 브라우저 실시간 갱신은 SSE
- 변경 명령은 versioned JSON HTTP API

대량 테이블은 pagination 또는 virtualization을 사용하고 그래프는 bounded data만 렌더링합니다. 브라우저 tab이 hidden 상태이면 갱신 빈도를 낮춥니다.

SSR은 SEO와 public first-render 이점이 없는 loopback 운영 콘솔에 도입하지 않습니다. Bun·Vite는 build-time 도구이며 운영 서버에는 설치하지 않습니다.

## 15. 시각 원칙

- 프로그램형 app shell과 명확한 상태 표시 사용
- 한국어 기본 문구와 숫자 단위 통일
- 의미 색상은 정상·주의·위험·실패에만 사용
- 색상만으로 상태를 전달하지 않음
- 고정 크기 toolbar와 안정적인 grid 사용
- 표와 그래프가 상태 변화로 흔들리거나 겹치지 않음
- desktop과 mobile에서 도움말·modal이 viewport 밖으로 잘리지 않음
- 연결 끊김과 복구 중에는 조작 가능 여부를 명확히 표시

## 16. UI 수용 기준

1. 정상·주의·로컬 방어·비상·복구 fixture가 각각 설명 가능한 화면으로 렌더링됩니다.
2. 10,000개 client fixture에서 검색·정렬·페이지 이동이 UI를 멈추지 않습니다.
3. SSE 중단·재연결·event gap을 감지하고 누락 구간을 다시 조회합니다.
4. API 값과 화면의 RPS·bytes·latency 집계가 일치합니다.
5. external IP 상세에서 판정 근거와 자원 상관관계를 확인할 수 있습니다.
6. provider 부분 실패가 성공 색상이나 완료 문구로 표시되지 않습니다.
7. 권한이 없는 사용자는 원시 IP export와 방어 명령을 실행할 수 없습니다.
8. light/dark, desktop/mobile Playwright screenshot 회귀를 통과합니다.
9. tooltip, modal, table과 실시간 log에 잘림·겹침·수평 overflow가 없습니다.
10. UI를 닫아도 edge·control의 방어와 사건 기록은 계속 동작합니다.
