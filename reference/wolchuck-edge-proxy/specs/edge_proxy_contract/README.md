---
doc_type: entrypoint
title: edge_proxy_contract 모듈 개요
description: edge_proxy 설정 계약 타입
status: active
owner: edge-proxy
source_of_truth: true
last_reviewed: 2026-04-22
review_cycle_days: 180
bounded_context: edge_proxy_contract
ai_default_include: true
---
# edge_proxy_contract

`edge_proxy_contract`는 deprecated `edge_proxy` PoC가 여전히 필요로 하는 `EdgeProxyConfig`, `EdgeProxyTlsListenerConfig` 같은 얇은 설정 계약 타입만 보관하는 crate입니다.

> **SDD 부재 선언**: 이 모듈은 설정 DTO 중심의 계약 crate이므로 별도 SDD를 두지 않습니다.

## 1. 개요
- `EdgeProxyConfig`
- `EdgeProxyTlsListenerConfig`

이 crate는 `Pingora` 런타임, request policy, startup orchestration을 소유하지 않습니다. `common`은 최상위 `Config` 로더/검증 shell을 유지하고, `edge_proxy` owner crate는 이 계약 타입을 소비해 deprecated reference 구현을 유지합니다.

## 2. 현재 원칙
- `edge_proxy` 전용 설정 DTO는 `common::config::model` 안에 다시 정의하지 않습니다.
- `common`은 이 crate를 재수출할 수 있지만, 타입 정의 본체는 여기 둡니다.
- `edge_proxy_contract`는 `serde + ipnet + std` 수준의 얇은 계약만 유지합니다.
- deprecated `edge_proxy` reference 구현 외의 새 소비자를 늘리지 않습니다.

## 3. 참조
- [변경 이력](HISTORY.md)
- [edge_proxy README](/Users/neojins/workspace/rest-middleware/specs/edge_proxy/README.md)
