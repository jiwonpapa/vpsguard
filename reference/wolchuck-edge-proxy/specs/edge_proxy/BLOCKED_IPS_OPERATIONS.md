---
title: edge_proxy blocked IP 운영 절차
status: deprecated
doc_type: runbook
owner: edge-proxy
source_of_truth: false
last_reviewed: 2026-04-19
review_cycle_days: 30
supersedes: ""
related_crates:
  - edge_proxy
bounded_context: edge_proxy
ai_default_include: false
---

# edge_proxy blocked IP 운영 절차

> 경고: 이 문서는 `edge_proxy`가 active 후보였을 때의 **historical runbook**이다. 현재 `edge_proxy`는 폐기 상태이므로 이 절차를 운영에 실행하지 않는다.

## 1. 목적

`blocked_ips`, `blocked_cidrs`는 과거 `Lightsail LB`가 직접 제공하지 않는 애플리케이션 계층 차단을 `Pingora edge_proxy`에서 보수적으로 수행하기 위해 정의했던 최소 운영 장치다.

원칙:

- 일반 사용자 전체를 막는 전역 allowlist는 사용하지 않는다.
- 차단은 `확인된 악성 행위`에 대해서만 수행한다.
- 가능하면 `단일 IP`부터 사용하고, `CIDR`은 근거가 충분할 때만 사용한다.

## 2. 설정 위치

- 기본 설정: [edge_proxy.yaml](/Users/neojins/workspace/rest-middleware/configs/edge_proxy.yaml)
- staging 운영값: [edge_proxy.yaml](/Users/neojins/workspace/rest-middleware/configs.staging/edge_proxy.yaml)

필드:

- `edge_proxy.blocked_ips`
- `edge_proxy.blocked_cidrs`

## 3. 허용 포맷

단일 IP:

```yaml
edge_proxy:
  blocked_ips:
    - "203.0.113.10"
    - "2001:db8::10"
```

CIDR:

```yaml
edge_proxy:
  blocked_cidrs:
    - "198.51.100.0/24"
    - "2001:db8:abcd::/48"
```

## 4. 차단 기준

추가 가능한 경우:

- 반복적인 `Host` 공격, 스캐닝, 비정상 요청 폭주
- 운영 경로 `/metrics`, `/ops/*` 반복 접근 시도
- 업로드 abuse, body flood, 인증 우회 시도
- 로그와 재현으로 확인된 특정 공격원

추가하면 안 되는 경우:

- 근거 없는 일회성 404/403
- 사용자 NAT 전체를 막을 가능성이 큰 광범위 CIDR
- 단순 오입력 또는 정상 브라우저 동작 가능성이 있는 요청

## 5. 적용 절차

1. 이 문서는 historical reference로만 유지한다.
2. 현재 운영 차단 정책은 `edge_proxy`가 아니라 active ingress/애플리케이션 경로에서 다시 정의해야 한다.
3. 과거 `deploy-staging-edge-proxy.sh` 실행 파일은 제거됐고, `journalctl -u edge-proxy` 절차도 더 이상 실행하지 않는다.

## 6. 제거 절차

1. staging/운영 설정에서 해당 IP 또는 CIDR을 삭제한다.
2. 동일한 배포 절차로 반영한다.
3. 차단 해제 후 재발 여부를 로그로 확인한다.

## 7. 보수적 운영 가드레일

- `CIDR`보다 `단일 IP`를 우선한다.
- `/24`, `/48`보다 더 넓은 대역 차단은 기본적으로 금지한다.
- 차단 사유 없는 상시 누적 리스트는 만들지 않는다.
- 반복적이고 구조적인 공격이면 애플리케이션 차단보다 상위 계층 방화벽 이전을 검토한다.
