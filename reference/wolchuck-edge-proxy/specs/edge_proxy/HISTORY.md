---
title: edge_proxy HISTORY
status: deprecated
doc_type: history
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

# edge_proxy History

## 2026-04-22: 설정 계약 타입을 edge_proxy_contract로 추출했다
- `EdgeProxyConfig`, `EdgeProxyTlsListenerConfig` 정의 본체와 validation 로직을 새 [edge_proxy_contract](/Users/neojins/workspace/rest-middleware/crates/edge_proxy_contract/src/lib.rs) crate로 옮겼다.
- [common::config::model::edge_proxy_config.rs](/Users/neojins/workspace/rest-middleware/crates/common/src/config/model/edge_proxy_config.rs)는 이제 재수출 shell만 남기고, `edge_proxy` runtime/readiness 코드는 계속 기존 re-export를 통해 같은 계약 타입을 소비한다.
- Why: `edge_proxy`가 deprecated reference 상태여도 owner-specific 설정 타입 정의가 giant `common`에 남아 있으면 공용부 fan-in만 불필요하게 유지되므로, deprecated 도메인이라도 설정 계약은 공용부 밖 얇은 crate로 내려 두는 편이 구조상 더 맞기 때문이다.

## 2026-04-19: edge_proxy 문서군을 폐기 상태로 명시
- [README.md](/Users/neojins/workspace/rest-middleware/specs/edge_proxy/README.md), [MASTER_SDD.md](/Users/neojins/workspace/rest-middleware/specs/edge_proxy/MASTER_SDD.md), [BLOCKED_IPS_OPERATIONS.md](/Users/neojins/workspace/rest-middleware/specs/edge_proxy/BLOCKED_IPS_OPERATIONS.md), [STAGING_APACHE_LIGHTSAIL_CUTOVER_RUNBOOK.md](/Users/neojins/workspace/rest-middleware/specs/edge_proxy/STAGING_APACHE_LIGHTSAIL_CUTOVER_RUNBOOK.md)의 메타데이터 `status`를 `deprecated`로 내리고, `ai_default_include`를 끄고, 모든 문서 첫머리에 `edge_proxy`가 더 이상 active 운영/개발 대상이 아니라는 경고를 추가했다.
- Why: 기존 문구는 `paused`와 `reference` 수준이라 여지를 남겼고, 형님 지시대로 이제는 `edge_proxy`가 **폐기된 도메인/PoC**라는 사실을 문서 메타데이터와 본문 양쪽에서 명시적으로 고정해야 한다.

## 2026-04-07: archive 전환 1차로 active build/deploy 경로에서 제외
- [Cargo.toml](/Users/neojins/workspace/rest-middleware/Cargo.toml) workspace member에서 `crates/edge_proxy`를 제거해 기본 workspace build 대상에서 뺐다.
- [scripts/deploy-staging-edge-proxy.sh](/Users/neojins/workspace/rest-middleware/scripts/deploy-staging-edge-proxy.sh)는 이제 즉시 실패하며 `Apache -> irongate` direct 운영 SSOT만 안내한다.
- [scripts/apache/wolchuck.cc.edge-proxy.staging.conf](/Users/neojins/workspace/rest-middleware/scripts/apache/wolchuck.cc.edge-proxy.staging.conf), [scripts/apache/host-passthrough.edge-proxy.staging.conf.template](/Users/neojins/workspace/rest-middleware/scripts/apache/host-passthrough.edge-proxy.staging.conf.template)는 upstream을 `127.0.0.1:9081 edge_proxy`가 아니라 `127.0.0.1:9080 irongate` direct로 바꿨다.
- Why: archive 전환의 핵심은 reference 코드를 지우기 전에 active build/deploy/staging 경로에서 먼저 떼어내는 것이고, 이 단계만 해도 운영 복잡도를 즉시 줄일 수 있기 때문이다.

## 2026-04-07: `edge_proxy` 개발 중단과 Apache direct 운영 원칙을 SSOT에 반영
- [README.md](/Users/neojins/workspace/rest-middleware/specs/edge_proxy/README.md)와 [MASTER_SDD.md](/Users/neojins/workspace/rest-middleware/specs/edge_proxy/MASTER_SDD.md)에 `edge_proxy`를 **개발 중단(paused)** 상태로 명시하고, 운영 기본 경로를 `Apache -> irongate` direct 연결로 유지한다고 못 박았다.
- Why: `edge_proxy`는 PoC로서 의미 있는 정책 검증은 끝났지만, 실제 운영에 넣으면 Apache 외에 또 하나의 edge 계층을 장기 유지해야 해서 복잡성과 관리 단계가 늘어난다. 현재 프로젝트 우선순위는 프록시 스택 확대보다 운영 단순화와 본체 부채 정리다.

## 2026-04-07: `main.rs` inline 런타임 설정 테스트를 `main/tests.rs`로 분리
- [main.rs](/Users/neojins/workspace/rest-middleware/crates/edge_proxy/src/main.rs)는 런타임 셸만 남기고, `EdgeRuntimeConfig` 변환/host normalize 회귀 테스트는 [main/tests.rs](/Users/neojins/workspace/rest-middleware/crates/edge_proxy/src/main/tests.rs)로 옮겼다.
- Why: runtime governance 하드코딩 debt 리포트가 production runtime 셸과 `127.0.0.1` 기반 inline 테스트 fixture를 같이 세고 있었고, 테스트 owner를 파일 밖으로 빼야 `edge_proxy` 런타임 debt 수치가 실제 본체 중심으로 더 정확하게 내려가기 때문이다.

## 2026-04-07: `request_policy.rs`, `rate_limit.rs` inline 테스트를 각 `tests.rs`로 분리
- [request_policy.rs](/Users/neojins/workspace/rest-middleware/crates/edge_proxy/src/request_policy.rs)와 [rate_limit.rs](/Users/neojins/workspace/rest-middleware/crates/edge_proxy/src/rate_limit.rs)는 policy/limiter 본체만 남기고, canonical redirect/IP fixture와 `127.0.0.1` 기반 회귀 테스트는 각각 [request_policy/tests.rs](/Users/neojins/workspace/rest-middleware/crates/edge_proxy/src/request_policy/tests.rs), [rate_limit/tests.rs](/Users/neojins/workspace/rest-middleware/crates/edge_proxy/src/rate_limit/tests.rs)로 옮겼다.
- Why: runtime governance 하드코딩 debt 리포트가 production request policy/rate limiter와 inline 테스트 literal을 같이 세고 있었고, 같은 `edge_proxy` 도메인 안에서 테스트 owner를 파일 밖으로 빼야 상위 debt가 실제 runtime 본체 기준으로 더 정확하게 내려가기 때문이다.

## 2026-04-07: `app_policy.rs` inline 테스트를 `app_policy/tests.rs`로 분리
- [app_policy.rs](/Users/neojins/workspace/rest-middleware/crates/edge_proxy/src/app_policy.rs)는 host/IP/path 정책 본체만 남기고, fixture host/IP literal이 많은 회귀 테스트는 [app_policy/tests.rs](/Users/neojins/workspace/rest-middleware/crates/edge_proxy/src/app_policy/tests.rs)로 옮겼다.
- Why: runtime governance 하드코딩 debt 리포트에서 `edge_proxy::app_policy`가 실제 런타임 정책보다 inline 테스트 fixture 때문에 과대 집계되고 있었고, 테스트를 owner 파일 밖으로 분리해야 보고서가 runtime debt를 더 정확하게 가리키기 때문이다.

## 2026-04-07: `ProxyHttp` request flow를 `proxy_flow.rs`로 분리
- [main.rs](/Users/neojins/workspace/rest-middleware/crates/edge_proxy/src/main.rs)는 이제 `ProxyHttp` trait wiring과 `upstream_peer` shell만 남기고, `request_filter`, `request_body_filter`, `upstream_request_filter`, `response_filter`, `fail_to_proxy`, `request_summary` 본체는 [proxy_flow.rs](/Users/neojins/workspace/rest-middleware/crates/edge_proxy/src/proxy_flow.rs)가 직접 소유한다.
- Why: request context/response/startup shell까지 분리한 뒤 `main.rs`에 남은 가장 큰 natural seam은 `ProxyHttp` flow 본체였고, broad redesign 없이 trait impl을 thin delegator로 낮추며 root concentration을 더 줄일 수 있기 때문이다.

## 2026-04-07: request context/response/startup shell을 `context.rs`, `response.rs`, `startup.rs`로 분리
- [main.rs](/Users/neojins/workspace/rest-middleware/crates/edge_proxy/src/main.rs)는 이제 `ProxyHttp` request/response flow와 `EdgeProxyApp` orchestration만 남기고, `RequestCtx`는 [context.rs](/Users/neojins/workspace/rest-middleware/crates/edge_proxy/src/context.rs), edge plain-text/redirect/common-header helper는 [response.rs](/Users/neojins/workspace/rest-middleware/crates/edge_proxy/src/response.rs), rustls provider/config loading/server bootstrap은 [startup.rs](/Users/neojins/workspace/rest-middleware/crates/edge_proxy/src/startup.rs)가 직접 소유한다.
- Why: `edge_proxy` giant `main.rs`에서 policy/helper를 분리한 뒤 남은 다음 자연 seam은 request context, response helper, startup shell이었고, broad redesign 없이 request flow 본체와 shell/support 관심사를 더 분리할 수 있기 때문이다.

## 2026-04-07: `EdgeProxyApp` host/IP/path policy를 `app_policy.rs`로 분리
- [main.rs](/Users/neojins/workspace/rest-middleware/crates/edge_proxy/src/main.rs)는 proxy app/request filter/Pingora runtime flow와 orchestration만 남기고, `EdgeProxyApp::host_allowed`, `host_passthrough`, `admin_ip_allowed`, `blocked_ip_denied`, `forwarded_headers_trusted`, `is_*_path` 계열 정책 메서드와 관련 회귀 테스트는 [app_policy.rs](/Users/neojins/workspace/rest-middleware/crates/edge_proxy/src/app_policy.rs)가 직접 소유한다.
- Why: request helper를 떼어낸 뒤 남은 `main.rs`의 다음 자연 seam은 host/IP/path 판정 정책 메서드 묶음이었고, broad redesign 없이 app orchestration과 policy ownership을 분리할 수 있기 때문이다.

## 2026-04-07: request/proto/path helper를 `request_policy.rs`로 분리
- [main.rs](/Users/neojins/workspace/rest-middleware/crates/edge_proxy/src/main.rs)는 proxy app/request filter/Pingora runtime flow와 app orchestration만 남기고, request header/path/forwarded proto 해석, canonical redirect location, path-based rate-limit selector와 관련 회귀 테스트는 [request_policy.rs](/Users/neojins/workspace/rest-middleware/crates/edge_proxy/src/request_policy.rs)가 직접 소유한다.
- Why: `edge_proxy` giant `main.rs`에서 request/proto/path helper 묶음은 `EdgeProxyApp` orchestration과 분리 가능한 다음 self-contained seam이었고, broad redesign 없이 root concentration을 추가로 낮출 수 있기 때문이다.

## 2026-04-07: 고정 윈도우 rate limiter를 `rate_limit.rs`로 분리
- [main.rs](/Users/neojins/workspace/rest-middleware/crates/edge_proxy/src/main.rs)는 proxy app/request filter/Pingora runtime flow만 남기고, `FixedWindowRateLimiter` 상태/윈도우/poison recovery와 관련 회귀 테스트는 [rate_limit.rs](/Users/neojins/workspace/rest-middleware/crates/edge_proxy/src/rate_limit.rs)가 직접 소유한다.
- Why: `edge_proxy` giant `main.rs` 안에서 rate limiter는 request filtering 본체와 분리 가능한 self-contained owner seam이었고, broad redesign 없이 root concentration을 추가로 낮출 수 있는 다음 자연 tranche였기 때문이다.

## 2026-04-07: 런타임 설정 변환과 정규화 helper를 `runtime_config.rs`로 분리
- [main.rs](/Users/neojins/workspace/rest-middleware/crates/edge_proxy/src/main.rs)는 proxy app, request filter, Pingora runtime flow만 남기고, `EdgeRuntimeConfig`와 `EdgeProxyConfig -> runtime config` 변환, host/path 정규화 helper는 [runtime_config.rs](/Users/neojins/workspace/rest-middleware/crates/edge_proxy/src/runtime_config.rs)가 직접 소유한다.
- Why: `edge_proxy`는 여전히 giant 단일 파일이지만, 상단의 설정 계약/정규화 로직은 request filtering/runtime 본체와 owner seam이 분명했고, broad redesign 없이 `main.rs` 집중도를 낮출 수 있는 가장 자연스러운 첫 tranche였기 때문이다.

## 2026-03-31: staging passthrough host를 wildcard host rule + app auth 기준으로 재정렬
- [configs.staging/edge_proxy.yaml](/Users/neojins/workspace/rest-middleware/configs.staging/edge_proxy.yaml)의 `passthrough_hosts`를 `wolchuck.co.kr`, `*.wolchuck.co.kr` 패턴으로 올리고, `admin_path_prefixes`에서는 `/ops`를 제거해 `/metrics`만 edge infra ACL로 남겼다.
- [main.rs](/Users/neojins/workspace/rest-middleware/crates/edge_proxy/src/main.rs)는 이제 `allowed_hosts`/`passthrough_hosts`에서 exact host와 `*.example.com`/`.example.com` suffix rule을 같이 해석한다.
- [domain_redirect.rs](/Users/neojins/workspace/rest-middleware/crates/web_runtime/src/domain_redirect.rs)도 `CANONICAL_EXEMPT_HOSTS`에서 wildcard/suffix rule을 지원하게 바꿨다.
- Why: `w3.wolchuck.co.kr/ops/admin/*`가 도메인 보안 문제가 아니라 edge `/ops` IP 차단 때문에 `403 forbidden`을 반환하고 있었고, 향후 `wolchuck.co.kr`와 `*.wolchuck.co.kr`가 staging passthrough/신인프라 컷오버에서 같은 규칙을 타려면 exact host 하드코딩이 아니라 reusable host rule과 app-auth 기준으로 정리해야 했기 때문이다.

## 2026-03-31: staging 외부 passthrough host Apache 템플릿/설치 스크립트 추가
- [host-passthrough.edge-proxy.staging.conf.template](/Users/neojins/workspace/rest-middleware/scripts/apache/host-passthrough.edge-proxy.staging.conf.template)와 [install-staging-apache-passthrough-host.sh](/Users/neojins/workspace/rest-middleware/scripts/install-staging-apache-passthrough-host.sh)를 추가했다.
- `w3.wolchuck.co.kr`처럼 외부 포워딩으로 staging `:80`에 직접 붙는 host는 canonical staging alias가 아니라, 브라우저 host를 유지하는 Apache passthrough vhost + 앱 `.env`의 `CANONICAL_EXEMPT_HOSTS` 등록을 한 번에 처리하는 정책으로 정리했다.
- Why: canonical host(`wolchuck.cc`) redirect 정책을 유지하면서도, 외부 포트포워딩 host는 리다이렉트 없이 Rust middleware를 태워야 하기 때문이다.

## 2026-03-25: staging edge_proxy 배포를 원격 build 금지 경로로 전환
- [deploy-staging-edge-proxy.sh](/Users/neojins/workspace/rest-middleware/scripts/deploy-staging-edge-proxy.sh)가 더 이상 staging 서버에 소스 전체를 rsync한 뒤 `cargo build`하지 않는다.
- 이제 edge_proxy staging 배포도 맥미니 로컬에서 `TARGET_TRIPLE` 기준 cross-build한 `edge_proxy` 바이너리와 설정 묶음만 업로드하고, 원격에서는 설정 materialize와 systemd 재기동만 수행한다.
- Why: staging 사양이 로컬보다 느린 상태에서 서버 직접 빌드 경로를 남겨두면 긴급 복구 때도 같은 실수를 반복하게 되므로, edge_proxy도 irongate와 같은 배포 원칙으로 통일해야 했다.

## 2026-03-21: staging/local test 도메인과 실서비스 도메인 해석을 문서에 명시
- [MASTER_SDD.md](/Users/neojins/workspace/rest-middleware/specs/edge_proxy/MASTER_SDD.md), [STAGING_APACHE_LIGHTSAIL_CUTOVER_RUNBOOK.md](/Users/neojins/workspace/rest-middleware/specs/edge_proxy/STAGING_APACHE_LIGHTSAIL_CUTOVER_RUNBOOK.md)에 도메인 전제를 명시했다.
- 실서비스 canonical 도메인 SSOT는 `wolchuck.co.kr`이고, `wolchuck.cc`는 staging Rust middleware 테스트 도메인, `wol.cc`는 legacy source staging 도메인으로 다시 고정했다.
- Why: 최근 staging canonical host를 `wolchuck.cc`로 맞춘 뒤 edge 문서만 읽으면 이 값을 실서비스 canonical처럼 오해할 수 있었으므로, staging/local test host와 실제 서비스 도메인 SSOT를 문서에서 먼저 분리해야 했다.

## 2026-03-20: staging canonical host를 `wolchuck.cc`로 임시 전환
- [configs.staging/edge_proxy.yaml](/Users/neojins/workspace/rest-middleware/configs.staging/edge_proxy.yaml), [deploy-staging-edge-proxy.sh](/Users/neojins/workspace/rest-middleware/scripts/deploy-staging-edge-proxy.sh), [wolchuck.cc.edge-proxy.staging.conf](/Users/neojins/workspace/rest-middleware/scripts/apache/wolchuck.cc.edge-proxy.staging.conf)를 `wolchuck.cc` 기준 canonical로 맞췄다.
- `www.wolchuck.cc`는 더 이상 staging canonical host가 아니라 legacy alias/redirect 경로로 내렸다.
- Why: 현재 스테이징 공개 검증 기준을 `wolchuck.cc`로 통일하기로 했으므로, Apache shim/edge_proxy redirect/deploy smoke가 같은 canonical host를 가리켜야 public 경로 drift가 줄어든다.

## 2026-03-19: thumb 경로 전용 rate-limit 슬롯 추가
- `edge_proxy` 설정 모델과 runtime 분류에 `thumb_path_prefixes`, `thumb_rate_limit_requests_per_minute`를 추가했다.
- `/thumb/*`, `/thumbserver/*`가 더 이상 일반 public 브라우징 bucket에 섞이지 않고, 필요 시 업로드/strict와 별개 전용 minute bucket을 사용할 수 있도록 `select_rate_limit()`과 helper 테스트를 보강했다.
- 기본 서비스 파일과 staging override에는 썸네일 경로 prefix만 고정하고, 운영 RPM은 근거 없는 숫자를 넣지 않도록 `unset`으로 유지했다.
- Why: 현재 썸네일 요청은 `edge_proxy`에서 일반 공개 경로와 같은 rate-limit 축을 타고 있어 `/upload`처럼 별도 보호를 걸 수 없었고, 형님 요구대로 하드코딩 없이 배선만 먼저 열어두려면 경로군과 RPM 슬롯을 설정 기반으로 분리하는 것이 가장 보수적이기 때문이다.

## 2026-03-19: staging edge_proxy 배포가 common/runtime drift 없이 current crate 전체를 올리도록 수정
- `deploy-staging-edge-proxy.sh`가 `crates/edge_proxy` 일부 파일만 올리던 방식을 버리고 `crates/` 전체와 `configs/common.yaml`, `configs.staging/common.yaml`, `configs.staging/edge_proxy.yaml`을 함께 동기화하도록 바꿨다.
- 원격에서는 `configs.staging/common.yaml -> configs/common.yaml`, `configs.staging/edge_proxy.yaml -> configs/edge_proxy.yaml`를 함께 materialize한 뒤 빌드하도록 바꿨다.
- 배포 직후 startup log에서 `rate_limit_rpm=None`, `upload_rate_limit_rpm=Some(30)`, `strict_rate_limit_rpm=Some(60)`를 강제 확인하도록 검증 단계를 추가했다.
- Why: staging edge_proxy가 2026-03-12 구버전 바이너리로 남아 공개 브라우징 `120 RPM` 전역 cap을 계속 적용했고, 배포 스크립트도 최신 common schema를 따라가지 못해 재기동만으로는 drift를 해소할 수 없었기 때문이다.

## 2026-03-17: strict rate-limit path 분류 helper 고정
- `/login`, `/search`가 여전히 stricter rate-limit 경로로 분류되는지 helper와 테스트를 다시 고정했다.
- Why: 최근 공개 브라우징 전역 IP cap을 비활성화한 뒤에도 고비용 인증/검색 경로까지 같이 풀리면 edge 정책의 핵심 guard rail이 무너질 수 있으므로, path 분류 자체를 테스트 가능한 helper로 남겨두는 편이 안전하기 때문이다.

## 2026-03-16: 공개 브라우징 전역 IP rate limit 비활성화
- staging `edge_proxy`의 `rate_limit_requests_per_minute`를 `unset`으로 내려, 일반 HTML/게시판 브라우징은 더 이상 전역 IP minute bucket으로 묶지 않도록 정리했다.
- `/login`, `/search`, `/upload`의 stricter/upload limit은 그대로 유지하고, `select_rate_limit()` helper와 회귀 테스트를 추가해 일반 경로는 global limit이 비어 있으면 제한이 걸리지 않는다는 현재 정책을 코드로 고정했다.
- `README.md`, `MASTER_SDD.md`에도 shared IP/NAT false positive를 막기 위해 공개 브라우징에는 전역 IP cap을 기본으로 두지 않는다는 원칙을 반영했다.

## 2026-03-13: entrypoint/contract/runbook/history 메타데이터 이행
- `README`, `MASTER_SDD`, `BLOCKED_IPS_OPERATIONS`, `STAGING_APACHE_LIGHTSAIL_CUTOVER_RUNBOOK`, `HISTORY`에 메타데이터를 적용했다.
- `MASTER_SDD`는 active contract, 운영 절차 문서는 active runbook, `HISTORY`는 active history로 역할을 고정했다.

## 2026-03-11: rate limiter mutex poison 복구 추가
- `FixedWindowRateLimiter`가 `Mutex::lock().unwrap()`로 poison 시 프록시 전체 패닉 가능하던 지점을 복구형 lock helper로 교체했다.
- poison 상태에서도 내부 윈도우를 이어받아 rate limit을 계속 적용하는 회귀 테스트를 추가했다.

## 2026-03-08: staging Apache가 inbound forwarded header를 sanitization 하도록 정리
- `Apache -> edge_proxy` 경로에서 client-supplied `X-Forwarded-For`가 그대로 살아 있으면 trusted proxy 체인이 무력화된다.
- staging Apache vhost에 `ProxyAddHeaders On`을 명시하고 inbound `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host`, `X-Forwarded-Proto`를 `early` 단계에서 unset 하도록 정리했다.
- 이후 `X-Forwarded-Proto=https`만 Apache가 다시 부여하고, 나머지 proxy header는 Apache/mod_proxy가 재생성하는 구조로 맞췄다.

## 2026-03-09: `upload_go` 활성 참조 제거
- 실서비스에서 더 이상 사용하지 않는 `upload_go`를 현재 설정/런북/스모크에서 제거했다.
- `edge_proxy`의 `gone_paths` 기본값과 staging 값에서 `upload_go`를 제거했다.
- Apache staging vhost와 배포 스크립트에서 `upload_go` 전용 규칙/검증을 제거했다.

## 2026-03-09: 보수적 최소 보안 설정축 추가
- `edge_proxy` 설정 모델에 `blocked_ips`, `blocked_cidrs`, `upload_path_prefixes`, `upload_max_body_bytes`, `upload_rate_limit_requests_per_minute`를 추가했다.
- `Pingora` request filter/request body filter에서 명시적 공격자 차단과 `/upload` 전용 body/rate limit 분리를 적용했다.
- `MASTER_SDD.md`와 `README.md`에 Lightsail 보완용 보수적 baseline을 명시했다.

## 2026-03-09: timeout 설정축 추가
- `edge_proxy` 설정 모델에 downstream/upstream timeout과 upload timeout override를 추가했다.
- `Pingora` request filter에서 downstream read/write/drain timeout을 적용하고, upstream peer 생성 시 connect/read/write/idle timeout을 설정한다.
- staging 설정에는 일반 페이지와 `/upload` 경로를 분리한 기본 timeout 값을 반영했다.
- staging 설정에 `max_body_bytes=1MiB`, `upload_max_body_bytes=50MiB`, `upload_rate_limit_requests_per_minute=30`을 고정했다.

## 2026-03-09: blocked IP 운영 문서화와 고비용 경로 rate limit 분리
- `BLOCKED_IPS_OPERATIONS.md`를 추가해 `blocked_ips`, `blocked_cidrs`의 포맷, 추가/제거 절차, 보수적 가드레일을 문서화했다.
- `edge_proxy` 설정 모델과 Pingora 정책에 `strict_rate_limit_path_prefixes`, `strict_rate_limit_requests_per_minute`를 추가했다.
- staging 기본값으로 `/login`, `/search`에 대한 stricter rate limit을 설정했다.

## 2026-03-08: staging 배포 스크립트 포트 하드코딩 제거
- `deploy-staging-edge-proxy.sh`가 더 이상 `9081`, `9444`를 고정값으로 쓰지 않는다.
- staging 설정 파일 `configs.staging/edge_proxy.yaml`에서 HTTP/TLS 포트를 읽어 smoke 검증에 사용하도록 정리했다.
- `/upload_go -> 410`도 배포 스크립트의 기본 smoke 계약에 포함했다.

## 2026-03-08: trusted proxy 경계 및 rate limiter 정리
- `X-Forwarded-*`를 무조건 신뢰하지 않도록 `trusted_proxy_cidrs` 설정을 추가했다.
- `edge_proxy`는 이제 direct peer가 `trusted_proxy_cidrs`에 포함될 때만 forwarded header를 클라이언트 IP/프로토콜 판단에 사용한다.
- minute bucket이 바뀔 때 stale rate-limit entry를 정리하도록 수정해 tracked IP state가 무한히 누적되지 않게 했다.
- `MASTER_SDD.md`의 `/health/*` 정책을 실제 운영 설계에 맞게 공개 probe 경로로 정정했다.

## 2026-03-08: edge 경로 정책 하드코딩 제거
- `admin path`와 `gone path`를 코드 상수에서 `edge_proxy` 설정 모델로 승격했다.
- `configs/edge_proxy.yaml`, `configs.staging/edge_proxy.yaml`에 `admin_path_prefixes`, `gone_paths`를 추가했다.
- direct edge의 `/upload_go -> 410 Gone` 정책을 설정 기반으로 유지하도록 정리했다.

## 2026-03-08: direct edge 경로에서 `/upload_go` legacy 차단 반영
- Apache 없이 `edge_proxy` direct TLS rehearsal로 진입하면 `/upload_go`가 더 이상 Apache `410` 차단을 거치지 않는 문제가 있었다.
- direct termination 기준 계약을 맞추기 위해 `edge_proxy` request filter에서 `/upload_go`를 `410 Gone`으로 직접 종료하도록 보정했다.
- `MASTER_SDD.md`와 `README.md`에 direct edge 기준 `/upload_go` 차단 정책을 반영했다.

## 2026-03-08: edge_proxy 문서군 초기 생성
- `Pingora` 기반 edge proxy PoC를 크레이트 단위로 다루기 위해 문서군 생성
- `MASTER_SDD.md` 추가
- 루트 `specs/README.md`와 전역 `specs/HISTORY.md`에 등록

## 2026-03-08: edge_proxy 워크스페이스 크레이트 추가
- `crates/edge_proxy/` 신규 추가
- 최소 단일 upstream reverse proxy 바이너리 스켈레톤 구현
- 환경변수 기반 listen/upstream 설정 로딩 추가
- `MASTER_SDD.md`와 `README.md`에 실제 추가된 크레이트 상태 반영

## 2026-03-08: edge_proxy 1차 PoC 기능 추가
- `/edge/health` 직접 응답 추가
- `Host` allowlist, admin IP ACL hook 추가
- `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`, request-id 주입 추가
- 기본 access log와 응답 지연 로그 추가
- `PoC (Proof of Concept)` 용어 정의를 문서군에 명시

## 2026-03-08: edge_proxy 정책 훅 확장
- canonical host redirect 추가
- `Content-Length` 기반 request size 제한 추가
- 고정 윈도우 rate limit hook 추가
- 실제 환경변수 키를 `MASTER_SDD.md`에 반영

## 2026-03-08: local end-to-end 연동 정합성 복구
- `configs.local/common.yaml`의 `upload_server.port`, `thumb_server.port` 잔존 키 제거
- `upload_server.url_prefix`를 절대 URL에서 경로형 값으로 교정
- `irongate -> edge_proxy` 로컬 smoke 검증 가능 상태로 정리

## 2026-03-08: edge_proxy 공통 설정 모델 승격 및 chunked body 제한 구현
- `common::config` top-level `edge_proxy` 설정 모델 추가
- 서비스 설정 파일 `configs/edge_proxy.yaml` 추가
- `edge_proxy` 바이너리를 env 임시파싱에서 공통 설정 로더로 전환
- `request_body_filter` 기반 `chunked body` 크기 제한 추가
- admin ACL을 단일 IP뿐 아니라 CIDR 규칙까지 해석하도록 확장

## 2026-03-08: edge_proxy 스테이징 배치 아티팩트 추가
- `configs.staging/edge_proxy.yaml` 추가
- `configs.staging/common.yaml`에서 제거된 standalone `upload/thumb` 포트 구조를 staging override에도 반영
- `scripts/systemd/edge_proxy.service.template` 추가
- `scripts/deploy-staging-edge-proxy.sh` 추가
- `MASTER_SDD.md`와 `README.md`에 staging loopback 시험 배치 원칙과 `configs.staging/edge_proxy.yaml -> configs/edge_proxy.yaml` materialize 규칙 반영
- Pingora 기본 graceful shutdown으로 재배포가 장시간 묶이지 않도록 `TimeoutStopSec=15`와 강제 재기동 경로를 추가

## 2026-03-08: staging Apache/Lightsail cutover runbook 및 운영값 고정
- `scripts/apache/wolchuck.cc.edge-proxy.staging.conf` 추가
- `STAGING_APACHE_LIGHTSAIL_CUTOVER_RUNBOOK.md` 추가
- staging 실제 공개 경로를 `Apache -> edge_proxy -> irongate`로 전환하는 절차를 문서화
- 당시 staging 운영값으로 `allowed_hosts`, `canonical_host`, `admin_allowed_ips`, `rate_limit_requests_per_minute=120`을 고정

## 2026-03-08: 공개 업로드 경로 `/upload` 기준으로 정리
- Apache staging vhost에서 `/upload_go` legacy alias 제거
- `/upload_go` 요청은 `410 Gone`으로 종료하도록 명시
- `STAGING_APACHE_LIGHTSAIL_CUTOVER_RUNBOOK.md`와 `MASTER_SDD.md`를 `/upload` 기준으로 정정
- `Lightsail HTTPS -> instance port 443` 제약을 문서에 명시해 `80 only direct termination` 오해를 제거

## 2026-03-08: edge_proxy direct TLS listener 설정 추가
- `edge_proxy` 설정 모델에 `tls_listener` 추가
- `edge_proxy`가 HTTP 리스너와 별도로 TLS 리스너를 함께 열 수 있도록 확장
- staging은 `127.0.0.1:9444` direct TLS rehearsal 포트로 고정
- direct TLS에서는 `x-forwarded-proto`가 없어도 downstream TLS 여부로 canonical redirect scheme을 결정하도록 수정
- 2026-03-14: staging Apache vhost에서 `/thumbserver`를 legacy `gobot_proxy.conf -> 127.0.0.1:9090` 브리지에 맡기지 않고, 현재 edge 경로(`127.0.0.1:9081 -> irongate embedded thumb router`)로 직접 프록시하도록 SSOT를 고쳤다. 일부 `/thumbserver/{w}x{h}/{base64}.webp` 요청이 옛 Python 브리지에서 backend redirect를 따라가 원본 JPEG를 그대로 반환해 `320x240` 요청이 실제로는 원본 해상도로 보이던 문제가 있었기 때문이다.
- 2026-04-01: staging Apache passthrough host template과 canonical staging conf에 `/zero/payspot/delegate` direct alias/ProxyPass exception을 추가했다. 특파원 상세 SSR이 legacy `delegate_file` 이미지 URL(`/zero/payspot/delegate/<filename>`)을 렌더하는데, passthrough host는 이 경로를 Rust middleware로 보내 404가 났다. 이제 `wolchuck.cc`와 `w3.wolchuck.co.kr` 모두 같은 legacy delegate 이미지 경로를 Apache가 직접 서빙한다.
