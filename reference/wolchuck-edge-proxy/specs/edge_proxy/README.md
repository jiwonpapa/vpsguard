---
title: edge_proxy 문서군 인덱스
status: deprecated
doc_type: entrypoint
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

# edge_proxy 문서 분류표

이 디렉터리는 워크스페이스에 남아 있는 `Pingora` 기반 `edge_proxy` PoC의 **폐기된(deprecated) reference 문서**를 보관합니다.

## 현재 상태

- `edge_proxy`는 **폐기(deprecated)** 상태입니다.
- 운영 SSOT는 `Apache -> irongate` 직접 연결이며, `edge_proxy`는 더 이상 active 운영/개발 후보가 아닙니다.
- 워크스페이스 빌드/스테이징 배포 경로에서도 이미 제외되었습니다. `crates/edge_proxy` 코드는 archive/reference로만 남기고, staging Apache vhost는 `127.0.0.1:9080`의 `irongate`를 직접 upstream으로 사용합니다.
- 앞으로는 보안상 필요한 최소 유지보수, 문서 보존, 폐기 상태 명시 외의 신규 기능 추가를 금지합니다.
- 별도 재승인 없이는 `edge_proxy` 재개, 재도입, cutover rehearsal 재실행을 하지 않습니다.

## 0. 용어

- `PoC (Proof of Concept)`
  - 운영 메인 프록시 전환을 즉시 선언하는 구현이 아니라, 실제로 붙는지와 운영 리스크가 무엇인지 검증하는 시험 구현입니다.

## 1. 핵심 설계 SSOT

- [MASTER_SDD.md](/Users/neojins/workspace/rest-middleware/specs/edge_proxy/MASTER_SDD.md)
  - `Lightsail Load Balancer` 뒤에서 동작하는 `Pingora` edge proxy PoC의 목적, 범위, 라우팅, 정책, 비범위 기준 문서

## 2. 참조 문서

- [2026-03-08_pingora_edge_poc_spec.md](/Users/neojins/workspace/rest-middleware/specs/review/2026-03-08_pingora_edge_poc_spec.md)
  - PoC 착수 판단과 `Lightsail LB` 제약 기반 추가 기능 식별 메모
- [STAGING_APACHE_LIGHTSAIL_CUTOVER_RUNBOOK.md](/Users/neojins/workspace/rest-middleware/specs/edge_proxy/STAGING_APACHE_LIGHTSAIL_CUTOVER_RUNBOOK.md)
  - 현재는 **실행 금지된 historical runbook**이며, 과거 `Apache -> edge_proxy -> irongate` cutover 절차 기록으로만 남긴다
- [BLOCKED_IPS_OPERATIONS.md](/Users/neojins/workspace/rest-middleware/specs/edge_proxy/BLOCKED_IPS_OPERATIONS.md)
  - 현재는 **실행 금지된 historical 운영 절차**이며, 과거 `blocked_ips`, `blocked_cidrs` 포맷 기록으로만 남긴다

## 3. 기록 문서

- [HISTORY.md](/Users/neojins/workspace/rest-middleware/specs/edge_proxy/HISTORY.md)
  - `edge_proxy` 문서군 변경 이력

## 4. 현재 원칙

1. `edge_proxy`의 범위는 1차적으로 `Pingora` 기반 edge proxy PoC였고, 현재는 **폐기된 보관 대상**이다.
2. 공개 운영 경로는 `Apache -> irongate` 직접 연결을 기본으로 하며, `edge_proxy`는 신규 전환 대상 SSOT가 아니다.
3. `edge_proxy` 문서는 PoC 기록과 운영 판단 근거를 보존하기 위한 reference로 유지한다.
4. 라우팅/헤더/ACL/업로드/썸네일/WS 처리 요구사항을 재검토할 때는 먼저 `Apache direct` 구성이 충분한지 확인하고, `edge_proxy` 재개는 별도 승인 없이는 하지 않는다.
5. 코드 기준으로는 `crates/edge_proxy/`가 실제로 남아 있지만, 현재 구현은 보관 대상이다. 기존 `main.rs`, `proxy_flow.rs`, `runtime_config.rs`, `rate_limit.rs`, `request_policy.rs`, `app_policy.rs`, `context.rs`, `response.rs`, `startup.rs` 분해 상태는 후속 평가를 위한 reference로만 유지한다.
6. 설정 SSOT와 staging Apache reference는 당분간 기록 보존용으로 유지하되, 신규 운영은 `configs/edge_proxy.yaml`, edge 전용 systemd/unit을 사용하지 않는다. 과거 `deploy-staging-edge-proxy.sh` 실행 파일은 제거됐다.
7. `EdgeProxyConfig`, `EdgeProxyTlsListenerConfig` 같은 설정 계약 타입 정의 본체는 [edge_proxy_contract](/Users/neojins/workspace/rest-middleware/specs/edge_proxy_contract/README.md)가 소유하고, `common`은 로더/재수출 shell만 유지한다.
