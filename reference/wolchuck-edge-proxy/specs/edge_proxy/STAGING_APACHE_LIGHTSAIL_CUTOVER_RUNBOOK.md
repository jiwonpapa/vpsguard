---
title: edge_proxy staging Apache Lightsail cutover runbook
status: deprecated
doc_type: runbook
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

# edge_proxy staging Apache/Lightsail cutover runbook

> 경고: 이 문서는 과거 `edge_proxy` cutover 실험용 **historical runbook**이다. 현재 `edge_proxy`는 폐기 상태이므로 이 절차를 실행하지 않는다.

## 1. 목적

이 문서는 과거 staging의 실제 진입 경로를 `Apache -> irongate`에서 `Apache -> edge_proxy -> irongate`로 전환하려던 절차를 기록합니다.

현재 운영 SSOT는 `Apache -> irongate` direct이며, `Lightsail Load Balancer` 자체 설정도 `edge_proxy` cutover를 전제로 바꾸지 않습니다.

도메인 전제:

- 실서비스 canonical 도메인 SSOT는 `wolchuck.co.kr`입니다.
- 이 문서에서 쓰는 `wolchuck.cc`, `wol.cc`는 staging/local test 도메인입니다.
- 따라서 본 문서의 host/canonical 규칙은 staging 검증 절차에만 적용됩니다.

## 2. 현재 상태

현재 staging 서버의 실제 리스너는 다음과 같습니다.

- `Apache`: `*:80`, `*:443`
- `irongate`: `0.0.0.0:9443`, `127.0.0.1:9080`
- `edge_proxy`: `127.0.0.1:9081`
- `edge_proxy direct TLS rehearsal`: `127.0.0.1:9444`

현재 public 경로는 아래와 같습니다.

```text
Lightsail LB
  -> Apache :80/:443
    -> /swfs, /s3 : 별도 upstream 유지
    -> /bbs/data/file : Apache 직접 처리
    -> / : 127.0.0.1:9080
```

## 3. 과거 목표 상태

```text
Lightsail LB
  -> Apache :80/:443
    -> /swfs, /s3 : 기존 유지
    -> /bbs/data/file : 기존 유지
    -> /static, /assets, / : 127.0.0.1:9081
      -> edge_proxy :9081
        -> irongate :9080
```

핵심 이유:

- `Lightsail LB`는 기존처럼 `80/443`만 본다.
- 현재 staging 공개 진입점은 Apache이므로, LB 설정을 건드리지 않고도 `edge_proxy`를 실 경로에 삽입할 수 있다.
- `edge_proxy`는 loopback만 열어도 된다.

## 4. Apache 변경 규칙

적용 파일(현재는 reference 전용):

- [wolchuck.cc.edge-proxy.staging.conf](/Users/neojins/workspace/rest-middleware/scripts/apache/wolchuck.cc.edge-proxy.staging.conf)
- [host-passthrough.edge-proxy.staging.conf.template](/Users/neojins/workspace/rest-middleware/scripts/apache/host-passthrough.edge-proxy.staging.conf.template)

변경 요점:

1. `*:80` canonical redirect를 `https://wolchuck.cc/`로 통일
2. `ProxyPreserveHost On` 유지
3. inbound `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host`, `X-Forwarded-Proto`는 `early` 단계에서 unset
4. `ProxyAddHeaders On`으로 Apache proxy header를 재생성
5. `RequestHeader set X-Forwarded-Proto "https"` 추가
6. `/upload`는 별도 alias 없이 `/ -> edge_proxy -> irongate` 경로로 처리
7. `/static`, `/assets`, `/`를 `127.0.0.1:9081`로 변경
8. `/swfs`, `/s3`, `/bbs/data/file`는 기존 Apache 처리 유지
9. `upload_go` legacy alias는 더 이상 운영 대상이 아니므로 Apache/edge 규칙에서 제거
10. `w3.wolchuck.co.kr`처럼 외부 NAT가 staging `:80`으로 직접 붙는 host는 canonical redirect vhost에 섞지 말고, 별도 passthrough vhost로 유지
11. passthrough vhost는 브라우저 host를 그대로 유지하고, `edge_proxy.passthrough_hosts` + 앱 `CANONICAL_EXEMPT_HOSTS`가 그 host를 허용하도록 맞춘다

### 4.1 Passthrough Host 규칙

- 대상:
  - 외부 도메인 또는 사내 라우터 포워딩이 staging `:80`으로 직접 연결되는 host
- 예:
  - `w3.wolchuck.co.kr -> office NAT :8081 -> staging :80`
- 적용 스크립트:
  - [install-staging-apache-passthrough-host.sh](/Users/neojins/workspace/rest-middleware/scripts/install-staging-apache-passthrough-host.sh)
- 템플릿:
  - [host-passthrough.edge-proxy.staging.conf.template](/Users/neojins/workspace/rest-middleware/scripts/apache/host-passthrough.edge-proxy.staging.conf.template)
- 원칙:
  - canonical host redirect 금지
  - `ProxyPreserveHost On`
  - `X-Forwarded-*`는 기존 staging Apache와 동일하게 sanitize
  - `/img/*`를 포함한 앱 자산 경로는 정적 확장자 bypass로 Apache에 남기지 않고, Rust middleware owner route로 통과시킨다.

## 5. edge_proxy 운영값

staging 운영값은 다음으로 고정합니다.

- `allowed_hosts`:
  - `www.wolchuck.cc`
  - `wolchuck.cc`
- `passthrough_hosts`:
  - `wolchuck.co.kr`
  - `*.wolchuck.co.kr`
- `canonical_host`:
  - `wolchuck.cc`
- `admin_allowed_ips`:
  - `127.0.0.1`
  - `::1`
  - `192.168.0.0/24`
- `admin_path_prefixes`:
  - `/metrics`
- `rate_limit_requests_per_minute`:
  - `unset`

근거:

- SSOT 테스트 도메인: `wolchuck.cc`
- staging 서버 IP: `192.168.0.127`
- staging 내부 운영 클라이언트는 현재 `192.168.0.x` 사설망 기준으로 문서화되어 있다.
- 관리자 웹(`/ops/admin/*`)은 edge IP ACL이 아니라 애플리케이션 인증/권한으로 보호하고, `/metrics`만 infra ACL로 남긴다.
- 공개 브라우징은 shared IP/NAT false positive를 피하기 위해 전역 IP cap을 기본 `unset`으로 유지한다.

## 6. 적용 순서

1. `edge_proxy`가 `127.0.0.1:9081`에서 `200/308` 스모크를 통과한 상태인지 확인
2. Apache `headers` 모듈 활성화
3. Apache vhost를 `wolchuck.cc.edge-proxy.staging.conf`로 교체
4. `apachectl -t` 통과 확인
5. Apache graceful reload
6. `https://127.0.0.1` 기준 스모크 수행

## 7. 필수 스모크

1. `curl -k -H 'Host: wolchuck.cc' https://127.0.0.1/health/live` -> `200`
2. `curl -k -H 'Host: wolchuck.cc' https://127.0.0.1/metrics` -> `200`
3. `curl -k -I -H 'Host: www.wolchuck.cc' https://127.0.0.1/health/live` -> `308`
4. `curl -k -X POST -H 'Host: wolchuck.cc' https://127.0.0.1/upload` -> route reachable
5. spoofed `X-Forwarded-For`를 넣어도 `edge_proxy` 로그의 `client_ip`가 Apache peer 기준으로 유지되는지 확인

## 8. 비범위

이번 단계는 아래를 하지 않습니다.

- `Lightsail LB -> edge_proxy` 직접 종단
- Apache 제거
- `edge_proxy`의 `:80/:443` 직접 바인딩
- `/swfs`, `/s3`, `/bbs/data/file`의 Apache 제거

## 9. direct termination 제약

`Lightsail LB -> edge_proxy` 직접 종단은 다음 조건에서만 가능하다.

1. `HTTP only` LB:
   - instance port `80`
   - `edge_proxy` plain HTTP 가능
2. `HTTP_HTTPS` LB:
   - instance port `443`
   - `edge_proxy` downstream TLS 필요

즉 `HTTPS를 유지하면서 edge_proxy를 80 only로 직접 받는` 구성은 `Lightsail` 공식 제약과 맞지 않는다.

현재 staging은 Apache가 여러 vhost의 `*:443`을 점유하고 있으므로, `wolchuck.cc`만 즉시 `edge_proxy:443`로 분리할 수 없다.
따라서 direct termination은 아래 순서로 검증한다.

1. `edge_proxy.tls_listener`로 `127.0.0.1:9444` TLS 리스너를 기동
2. `curl --resolve wolchuck.cc:9444:127.0.0.1 https://wolchuck.cc:9444/...`로 TLS/SNI/redirect를 검증하고, 필요 시 `www.wolchuck.cc` alias redirect를 별도로 확인
3. Apache `*:443` 해제 또는 도메인 전용 인스턴스 분리 후 `edge_proxy.tls_listener.port=443`로 승격
