---
title: edge_proxy MASTER SDD
status: deprecated
doc_type: contract
owner: edge-proxy
source_of_truth: false
last_reviewed: 2026-04-19
review_cycle_days: 30
supersedes: ""
related_crates:
  - edge_proxy
  - irongate
bounded_context: edge_proxy
ai_default_include: false
---

# edge_proxy MASTER SDD

## 현재 상태

`edge_proxy` PoC는 현재 **폐기(deprecated)** 상태다. 운영 방향은 `Apache -> irongate` 직접 연결을 기본으로 유지하고, `Pingora` 기반 edge 계층은 더 이상 신규 개발/운영 대상으로 삼지 않는다.

이 문서는 현재 구현을 재개발하라는 지침이 아니라, 왜 복잡성과 운영 단계가 늘어났는지와 어떤 판단 끝에 **폐기**했는지를 남기는 reference SSOT로 읽는다.

> 경고: 이 문서는 active 설계 문서가 아니라 **폐기된 PoC 기록**이다. 별도 승인 없이는 `edge_proxy` 재도입, cutover rehearsal, 신규 기능 구현의 근거로 사용하지 않는다.

## 1. 목적

`edge_proxy`는 워크스페이스에 **신규 추가된** `AWS Lightsail Load Balancer` 뒤에서 동작하는 `Pingora` 기반 edge proxy PoC 크레이트를 정의했다.

도메인 해석 규칙:

- 실서비스 canonical 도메인 SSOT는 `wolchuck.co.kr`이다.
- `wolchuck.cc`는 현재 staging Rust middleware 통합 테스트용 임시 도메인이다.
- `wol.cc`는 레거시 source staging 호환 도메인이다.
- 이 문서의 `wolchuck.cc` 표기는 staging/local test 경로 설명으로만 해석한다.

여기서 `PoC (Proof of Concept)`는 운영 메인 프록시를 바로 교체하는 단계가 아니라, 실제 프록시 계층이 프로젝트 요구를 소화할 수 있는지 검증하는 시험 구현을 뜻한다.

이 문서의 목적은 다음과 같다.

1. `Pingora`를 이 프로젝트에 어떤 역할로 도입할지 고정한다.
2. `Lightsail Load Balancer`가 제공하지 않는 세밀한 edge 정책을 무엇으로 보완할지 명시한다.
3. 향후 `crates/edge_proxy` 구현 시 필요한 최소 기능과 비범위를 정한다.

## 2. 현재 배경

PoC 당시 프로젝트는 다음 구조를 목표로 검토했다.

```text
Client
  -> AWS Lightsail Load Balancer
  -> edge proxy
  -> irongate
```

또한 미디어 기능은 이미 `irongate`에 직접 통합되었다.

- `POST /upload`
- `GET /thumb/*`
- `GET /thumbserver/*`
- `GET /bbs/data/file/*`

따라서 `edge_proxy`는 예전처럼 `upload_server:8081`, `thumb_server:9090` 같은 내부 포트 분기 프록시가 아니다.
`edge_proxy`의 범위는 **오직 `irongate` 앞단 edge 계층**이다.

## 3. 문제 정의

`AWS Lightsail Load Balancer`는 기본적인 L7 기능은 제공하지만, 다음 영역은 얇다.

- 호스트 정규화
- 경로별 세밀한 정책
- 애플리케이션 맞춤 ACL
- request/response 헤더 정제
- 구조화된 edge 로그
- 추후 canary/weighted routing 실험

이 프로젝트는 SSR, API, upload, thumbnail, admin path를 한 프로세스에 수렴시키고 있으므로, `LB`와 앱 사이에 프로젝트 맞춤형 edge 계층이 있으면 운영상 이점이 있다.

## 4. 목표

현재 목표 상태:

- 신규 edge 기능 추가 중단
- Apache direct 운영 단순화 유지
- 기존 PoC 코드와 문서는 보안/운영 판단 참고자료로만 유지
- `edge_proxy`는 폐기 상태로 고정하고, 별도 재승인 없이는 active 후보로 되돌리지 않음

### 4.1 1차 목표

- `Pingora`로 단일 upstream reverse proxy를 구현한다.
- upstream은 `irongate` 하나만 둔다.
- upload/thumb/WS/SSR/API가 모두 edge를 경유해 정상 동작하는지 확인한다.

### 4.2 2차 목표

- `Lightsail LB`가 제공하지 않는 edge 정책을 코드로 구현 가능한 구조를 확보한다.
- 추후 `nginx -> Pingora` 전환 판단 근거를 만든다.

## 5. 비목표

초기 `edge_proxy` PoC는 아래를 하지 않는다.

- 캐시 서버 역할
- CDN 대체
- mTLS 종단
- WAF 대체
- 다중 upstream load balancing 본격 운영
- direct static file serving
- `db_proxy`(MySQL protocol) 프록시

## 6. 목표 아키텍처

### 6.1 로컬 PoC

```text
curl/browser
  -> edge_proxy
  -> irongate (127.0.0.1:9080)
```

### 6.2 staging 목표

```text
Client
  -> Lightsail Load Balancer
  -> edge_proxy
  -> irongate (127.0.0.1:9080)
```

### 6.3 staging 시험 배치

초기 staging 시험은 `Lightsail Load Balancer` 경로를 아직 갈아끼우지 않는다.

```text
ssh on staging host
  -> curl -H "Host: wolchuck.cc" http://127.0.0.1:9081
  -> edge_proxy (systemd)
  -> irongate (127.0.0.1:9080)
```

원칙:

- `edge_proxy`는 staging에서 `127.0.0.1:9081`로만 기동한다.
- public cutover 전에는 루프백 smoke 검증만 수행한다.
- canonical host와 허용 host는 `configs.staging/edge_proxy.yaml`에서 관리하고, staging 배포 시 활성 파일 `configs/edge_proxy.yaml`로 materialize한다.

### 6.4 staging 실제 진입 전환

staging의 실제 공개 경로는 현재 `Apache :443 -> irongate :9080`이다.
따라서 1차 실제 전환은 `Lightsail LB`를 건드리지 않고 Apache upstream만 바꾼다.

```text
Lightsail LB
  -> Apache :80/:443
    -> edge_proxy :9081
      -> irongate :9080
```

예외 경로:

- `/swfs`, `/s3`: Apache 기존 upstream 유지
- `/bbs/data/file`: Apache 기존 direct/static 처리 유지
- `/upload`: 별도 alias 없이 edge 경유

### 6.5 direct Lightsail termination 제약

`Lightsail LB -> edge_proxy` 직접 종단은 목표 방향으로는 맞다.
다만 `AWS Lightsail` 공식 문서 기준 2026-03-08 현재:

- `HTTP` traffic instance port: `80`
- `HTTPS` traffic instance port: `443`

따라서 다음 둘 중 하나다.

1. `LB=HTTP only`
   - `edge_proxy :80`
   - 내부 plain HTTP
   - 외부 HTTPS 없음
2. `LB=HTTP_HTTPS`
   - `edge_proxy :443`
   - `edge_proxy` downstream TLS 필요

즉 `Lightsail HTTPS를 유지하면서 edge_proxy 80 only direct termination`은 불가하다.

현재 staging은 Apache가 여러 도메인에 대해 `*:443`을 점유하고 있으므로, direct termination은 즉시 public `443`로 붙이지 않는다.
대신 `edge_proxy.tls_listener`로 별도 TLS rehearsal listener를 띄우고, 전용 인스턴스 또는 Apache `443` 해제 후 `443`으로 승격한다.

## 7. upstream 설계

1차 upstream은 하나만 둔다.

- upstream name: `irongate`
- upstream addr: `127.0.0.1:9080`
- protocol: `HTTP`

이유:

- `Lightsail LB`가 front-end TLS를 담당할 수 있다.
- `edge_proxy -> irongate`는 같은 호스트 또는 신뢰구간으로 가정한다.
- `Pingora` 공식 README 기준 `rustls`는 아직 `experimental`이므로 1차 PoC에서 TLS 복잡도를 의도적으로 제외한다.

## 8. 경로 처리 요구사항

`edge_proxy`는 아래 경로를 모두 `irongate`로 프록시해야 한다.

### 8.1 일반 경로

- `/`
- `/api/*`
- `/login`
- `/ops/*`
- `/ws/*`

### 8.2 미디어 경로

- `/upload`
- `/thumb/*`
- `/thumbserver/*`
- `/bbs/data/file/*`

### 8.3 운영 경로

- `/health/live`
- `/health/ready`
- `/metrics`

## 9. edge 정책 요구사항

### 9.1 헤더 정책

- `X-Forwarded-For`
- `X-Forwarded-Proto`
- `X-Real-IP`
- 필요 시 request ID 헤더 부여

원칙:

- `edge_proxy`가 trusted proxy chain의 마지막 애플리케이션 edge라는 전제로 헤더를 정규화한다.
- `irongate`는 이 헤더를 기반으로 실제 클라이언트 IP를 판단한다.

### 9.2 호스트 정책

- 허용 `Host` allowlist
- exact host + wildcard/suffix host rule
- canonical host redirect hook
- 비정상 host 요청 차단
- `X-Forwarded-*`는 `trusted_proxy_cidrs`에 포함된 peer에서만 신뢰

### 9.3 경로별 정책

- `/upload`: 큰 body 허용, 긴 timeout 허용, 메서드 제한
- `/thumb/*`, `/thumbserver/*`: cache-friendly header 부여 가능성 확보
- `/metrics`: edge infra ACL hook
- `/ops/admin/*`: edge IP allowlist가 아니라 애플리케이션 인증/권한으로 보호
- `/health/*`: `Lightsail LB`/운영 헬스체크용 공개 probe 경로

### 9.4 보안/방어 정책

- IP allow/deny hook
- 간단한 rate limit hook
- 비정상 header/host sanity check
- request logging

보수적 baseline:

- `allowed_hosts`: 실제 서비스 도메인만 허용
- `passthrough_hosts`: canonical redirect 없이 그대로 통과시킬 host allowlist
- `trusted_proxy_cidrs`: 신뢰된 프록시에서만 `X-Forwarded-*` 수용
- `admin_allowed_ips`: `/metrics` 같은 infra-only 운영 경로에만 적용
- `blocked_ips`, `blocked_cidrs`: 명시적 공격자 차단
- `upload_path_prefixes`: `/upload` 같은 업로드 경로를 일반 페이지 정책과 분리
- `thumb_path_prefixes`, `thumb_rate_limit_requests_per_minute`: `/thumb`, `/thumbserver` 같은 썸네일 경로를 일반 공개 브라우징과 분리하되, 운영 근거가 생기기 전까지 기본 RPM은 `unset`으로 둔다.
- `rate_limit_requests_per_minute`: 공개 브라우징 false positive를 피하기 위해 shared IP/NAT 환경에서는 기본 `unset`을 유지한다. 전역 IP cap이 꼭 필요하면 별도 근거와 함께 단계적으로 도입한다.
- `upload_max_body_bytes`, `upload_rate_limit_requests_per_minute`: 업로드 전용 제한
- `strict_rate_limit_path_prefixes`, `strict_rate_limit_requests_per_minute`: `/login`, `/search` 같은 고비용 경로 전용 제한
- `downstream_read_timeout_ms`, `upload_downstream_read_timeout_ms`: 느린 요청/업로드를 분리해 제어
- `upstream_connect_timeout_ms`, `upstream_read_timeout_ms`, `upload_upstream_read_timeout_ms`: upstream 보호와 업로드 정상 처리의 균형

초기 baseline에서 제외:

- regex 기반 WAF 시그니처 차단
- 전역 사용자 IP allowlist
- `Referer` 기반 핫링크 차단
- 공격 근거 없는 광범위 국가/ASN 차단

### 9.5 프로토콜 요구사항

- WebSocket upgrade 유지
- upload streaming 지원
- binary/image response pass-through

## 10. 구성 요소

현재 추가된 `crates/edge_proxy`는 최소 단일 upstream reverse proxy 스켈레톤을 제공한다.
향후에는 아래 역할까지 확장한다.

### 10.1 설정 모델

- listen address
- upstream address
- host allowlist
- passthrough host allowlist
- canonical host
- admin allowed IPs
- blocked IPs / CIDRs
- trusted proxy CIDRs
- admin path prefixes
- upload path prefixes
- thumb path prefixes
- strict rate-limit path prefixes
- request size / rate limit 기본값
- upload request size / rate limit override
- thumb path rate limit override
- strict path rate limit override
- downstream / upstream timeout 기본값
- upload timeout override

### 10.2 proxy service

- 모든 요청을 `irongate` upstream으로 전달
- 경로별 pre-check 수행
- 공통 헤더 주입

현재 구현 상태:

- `GET /edge/health` 직접 응답
- `Host` allowlist
- canonical host redirect
- `trusted_proxy_cidrs` 기반 forwarded header 신뢰 경계
- 설정 기반 infra path prefix + admin IP ACL hook
- `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`, request-id 주입
- `Content-Length` + `chunked body` 기반 request size 제한
- 고정 윈도우 rate limit hook
- 기본 access log와 request latency 로그
- staging loopback 배치용 `systemd` 템플릿과 전용 배포 스크립트

### 10.3 observability

- access log
- upstream error log
- request latency
- health endpoint

## 11. 설정 초안

예상 설정 예시는 다음과 같다.

```yaml
edge_proxy:
  enabled: false
  bind_address: "127.0.0.1"
  port: 9081
  upstream_irongate: "127.0.0.1:9080"
  allowed_hosts:
    - "www.wolchuck.cc"
    - "wolchuck.cc"
  passthrough_hosts:
    - "wolchuck.co.kr"
    - "*.wolchuck.co.kr"
  canonical_host: "wolchuck.cc"
  admin_allowed_ips: []
  request_id_header: "x-request-id"
  max_body_bytes: 52428800
  enable_rate_limit: false
  rate_limit_requests_per_minute: null
```

주의:

- 이 설정은 PoC용 초안이며 아직 코드 SSOT가 아니다.
- 현재 코드에서 확정된 환경변수 키는 아래와 같다.

현재 구현 설정 SSOT:

- 서비스 파일: [configs/edge_proxy.yaml](/Users/neojins/workspace/rest-middleware/configs/edge_proxy.yaml)
- 공통 모델: [edge_proxy_config.rs](/Users/neojins/workspace/rest-middleware/crates/common/src/config/model/edge_proxy_config.rs)
- 환경변수 오버라이드: `IRON__EDGE_PROXY__*`

현재 구현 설정 경로:

- `edge_proxy.bind_address`
- `edge_proxy.port`
- `edge_proxy.upstream_host`
- `edge_proxy.upstream_port`
- `edge_proxy.upstream_tls`
- `edge_proxy.upstream_sni`
- `edge_proxy.allowed_hosts`
- `edge_proxy.passthrough_hosts`
- `edge_proxy.canonical_host`
- `edge_proxy.admin_allowed_ips`
- `edge_proxy.admin_path_prefixes`
- `edge_proxy.upload_path_prefixes`
- `edge_proxy.thumb_path_prefixes`
- `edge_proxy.strict_rate_limit_path_prefixes`
- `edge_proxy.request_id_header`
- `edge_proxy.max_body_bytes`
- `edge_proxy.rate_limit_requests_per_minute`
- `edge_proxy.upload_rate_limit_requests_per_minute`
- `edge_proxy.thumb_rate_limit_requests_per_minute`
- `edge_proxy.strict_rate_limit_requests_per_minute`

staging 운영값:

- `allowed_hosts`: `www.wolchuck.cc`, `wolchuck.cc`
- `passthrough_hosts`: `wolchuck.co.kr`, `*.wolchuck.co.kr`
- `canonical_host`: `wolchuck.cc`
- `admin_allowed_ips`: `127.0.0.1`, `::1`, `192.168.0.0/24`
- `rate_limit_requests_per_minute`: `unset` (공개 브라우징 전역 IP cap 비활성)
- `upload_rate_limit_requests_per_minute`: `30`
- `thumb_rate_limit_requests_per_minute`: `unset`
- `strict_rate_limit_requests_per_minute`: `60`
- `tls_listener`: `127.0.0.1:9444` + staging cert/key

주의:

- 위 staging host/canonical 값은 local/staging 검증용 임시 설정이다.
- 실서비스 도메인 정책 SSOT는 `wolchuck.co.kr` 쪽 문서를 우선한다.

로컬 개발 오버라이드 주의:

- `upload_server.url_prefix`는 절대 URL이 아니라 `irongate`에 직접 붙는 경로형 값이어야 한다.
- `upload_server.port`, `thumb_server.port` 같은 standalone listener 잔존 키는 현재 구조에서 유효하지 않다.

## 12. 수용 기준

PoC는 아래를 만족해야 한다.

1. `GET /health/live` 정상 응답
2. `GET /` SSR 응답 정상
3. `POST /upload` 본문 손실 없이 통과
4. `GET /thumb/*`, `GET /thumbserver/*` 이미지 응답 정상
5. `/bbs/data/file/*` 원본 파일 응답 정상
6. WebSocket upgrade 유지
7. canonical host redirect 동작
8. `Content-Length` 초과 요청이 차단됨
9. `chunked body` 초과 요청이 차단됨
10. `/login`, `/search`, `/upload`와 필요 시 `/thumb*` 전용 슬롯 같은 고비용 경로의 rate limit 초과 요청이 차단됨
11. edge 로그에서 요청/응답 지연과 upstream 오류 식별 가능

## 13. 보류 기준

아래가 확인되면 운영 전환은 보류한다.

- upload/WS 경로에서 안정성 이슈 반복
- header/IP 처리 정합성 불안정
- `Pingora` API/의존성 변동 비용 과다
- 운영 복잡도가 `nginx` 대비 이득을 압도하지 못함

## 14. 현재 판단

현재 판단은 다음과 같다.

- `edge_proxy`는 만들 가치가 있다.
- 다만 1차 목적은 운영 교체가 아니라 PoC다.
- 운영 기본안은 여전히 `nginx`다.
- `Pingora`는 전환 후보를 검증하는 수단이다.

## 15. 참고 문서

- [Pingora edge PoC spec](/Users/neojins/workspace/rest-middleware/specs/review/2026-03-08_pingora_edge_poc_spec.md)
- [nginx edge policy](/Users/neojins/workspace/rest-middleware/specs/review/2026-03-07_nginx_edge_policy.md)
- [Pingora feasibility](/Users/neojins/workspace/rest-middleware/specs/review/2026-03-07_pingora_feasibility.md)
