# 운영 로그와 상관관계

VPSGuard의 운영 로그와 트래픽 분석 데이터는 목적과 보존 주기가 다르므로 분리합니다. 이 계약은 `OBS-012`, `OBS-013`, `NFR-005`, `SEC-005`를 구현합니다.

## 식별자

- Edge는 `guard-<process nonce 32 hex>-<sequence 16 hex>` 형식의 canonical `request_id`를 생성합니다.
- process nonce는 시작할 때 한 번 생성하므로 Edge가 재시작돼도 이전 request ID와 충돌하지 않습니다. 요청 hot path에서는 atomic sequence와 bounded 문자열 formatting만 수행합니다.
- Edge는 외부 client의 `X-Request-ID`를 신뢰하지 않고 자체 값으로 교체한 뒤 Nginx·Apache upstream과 client 응답에 같은 값을 전달합니다.
- loopback Control은 VPSGuard canonical 형식만 이어받고 나머지는 자체 ID로 교체합니다.
- 운영 명령은 `operation_id`, 사건은 `event_id`, API 오류는 `error-<uuid>`를 사용합니다.

관리자는 운영 콘솔의 `사건` 화면에서 request ID, operation ID 또는 event ID를 입력해 detail retention의 요청, incident와 audit action을 함께 조회할 수 있습니다.

## 저장 계층

| 계층 | 내용 | 보존 |
|---|---|---|
| systemd journal | JSON 운영 로그, 오류와 상태 변화 | host 정책을 존중하며 VPSGuard가 전역값을 변경하지 않음 |
| traffic detail | request ID, method, normalized route, status, latency, bytes, 판정 | `retention.detail_hours` |
| traffic rollup | 10초·1분 route 집계 | request ID 없이 `retention.aggregate_days` |
| incident | 상태 전이·provider 사건 | `retention.incident_days` |
| audit | operation ID와 운영 명령 결과 | `retention.audit_days` |

Edge는 SQLite에 접근하지 않습니다. telemetry는 bounded non-blocking datagram으로 전송하고 Control의 전용 writer thread가 batch transaction으로 저장합니다.

## JSON 공통 필드

- `log_schema_version`: 현재 `1`
- `component`: `guard-edge`, `guard-control` 또는 Control 안의 `guard-provider`
- `event_code` 또는 `error_code`: 검색 가능한 안정적 코드
- 해당 시 `request_id`, `operation_id`, `event_id`
- 오류 시 `problem`, `cause`, `impact`, `next_action`

정상 request 완료는 `debug`이고 systemd 기본 설정은 `info`이므로 모든 요청을 journal에 장기 적재하지 않습니다. 오류·용량 초과·정책 거부와 상태 변화는 `info` 이상으로 남깁니다.

## 개인정보와 비밀값

request body, 원본 query, cookie, Authorization, provider token과 private key는 journal·SQLite·UI에 저장하지 않습니다. 장기 rollup에는 request ID와 원본 IP를 포함하지 않습니다. secret fixture는 integration gate에서 로그와 증거 전체를 검사합니다.

## 운영 확인

```bash
journalctl -u vps-guard-edge.service -o json --since today
journalctl -u vps-guard-control.service -o json --since today
journalctl -u vps-guard-edge.service -o json | grep 'guard-0123'
```

systemd unit은 `SyslogIdentifier`, `StandardOutput=journal`과 unit별 rate limit을 명시합니다. journal 전체 보존량과 disk 상한은 다른 서비스에도 영향을 주므로 설치 과정에서 자동 변경하지 않습니다.
