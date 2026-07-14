---
doc_type: history
title: edge_proxy_contract 변경 이력
description: edge_proxy 설정 계약 crate 변경 추적
status: active
owner: edge-proxy
source_of_truth: true
last_reviewed: 2026-04-22
review_cycle_days: 180
bounded_context: edge_proxy_contract
ai_default_include: false
---

# edge_proxy_contract 변경 이력

## 2026-04-22: edge_proxy 설정 계약 타입을 common 밖 얇은 crate로 추출했다
- 새 [edge_proxy_contract](/Users/neojins/workspace/rest-middleware/crates/edge_proxy_contract/src/lib.rs) crate를 추가해 `EdgeProxyConfig`, `EdgeProxyTlsListenerConfig` 정의 본체와 validation 로직을 이쪽으로 옮겼다.
- [common](/Users/neojins/workspace/rest-middleware/crates/common/src/config/model/edge_proxy_config.rs)은 이 타입들을 재수출만 유지하고, 최상위 `Config` 검증에서는 새 contract crate의 validation 결과를 `IronError::Validation`으로 감싼다.
- Why: `edge_proxy`는 이미 deprecated reference 구현이지만 설정 DTO 정의 본체까지 giant `common::config::model`에 남겨둘 이유는 없고, 소비자가 좁은 owner-specific 설정 타입이므로 공용부 fan-in을 더 줄이는 안전한 분리 대상으로 적합했기 때문이다.
