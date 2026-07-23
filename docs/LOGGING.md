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
| traffic detail | request ID, method, normalized route, status, latency, bytes, 판정, bounded bot 분류 | `retention.detail_hours` |
| traffic rollup | 10초·1분 route 집계와 1분 bot 분류 집계 | request ID 없이 `retention.aggregate_days` |
| incident | 상태 전이·provider 사건 | `retention.incident_days` |
| audit | operation ID와 운영 명령 결과 | `retention.audit_days` |

Edge는 SQLite에 접근하지 않습니다. telemetry는 bounded non-blocking datagram으로 전송하고 Control의 전용 writer thread가 batch transaction으로 저장합니다. Edge 전송 성공·손실·재연결 누계와 처리 중 요청 수는 traffic summary에 노출합니다.

관리 화면의 traffic summary는 process lifetime 누계가 아닙니다. `retention.live_seconds` 시간창만 집계하며 RPS는 최근 10초 평균입니다. p95는 같은 시간창 안의 최근 최대 2,048개 sample을 사용합니다.

## JSON 공통 필드

- `log_schema_version`: 현재 `1`
- `component`: `guard-edge`, `guard-control` 또는 Control 안의 `guard-provider`
- `event_code` 또는 `error_code`: 검색 가능한 안정적 코드
- 해당 시 `request_id`, `operation_id`, `event_id`
- 오류 시 `problem`, `cause`, `impact`, `next_action`

정상 request 완료는 `debug`이고 systemd 기본 설정은 `info`이므로 모든 요청을 journal에 장기 적재하지 않습니다. Host 거부·속도 제한·선언형 bot 분류는 원본 요청별로 쓰지 않고 최초 1회와 이후 100회 단위의 bounded 집계 event만 남깁니다. systemd 기본 Edge filter는 제3자 Pingora journal을 끄고 VPSGuard schema만 수집합니다.

## 개인정보와 비밀값

request body, 원본 query, cookie, Authorization, provider token과 private key는 journal·SQLite·UI에 저장하지 않습니다. 기본 `info` journal에는 request별 원본 IP와 path도 남기지 않습니다. 차단 집계에는 normalized route와 IPv4 `/24`·IPv6 `/64` network만 사용합니다. User-Agent 원문 대신 `bot_class`, crawler provider·검증 여부·reason과 bounded `user_agent_family`만 저장합니다. 장기 rollup에는 request ID와 원본 IP를 포함하지 않습니다. 외부 명령 실패의 stderr는 원문 대신 byte 길이 marker로 교체합니다. secret fixture는 integration gate에서 로그와 증거 전체를 검사합니다.

Client IP detail 저장은 `retention.raw_ip_days`가 0보다 클 때만 활성화됩니다. Retention은 10초마다 테이블별 최대 10,000행을 처리하며 삭제 행, IP 비식별화 행과 backlog를 별도로 표시합니다. DB 파일의 reclaimable page는 자동 `VACUUM`하지 않습니다. 장시간 exclusive lock을 피하고 운영자가 유지보수 창에서 판단하도록 합니다.

## 운영 확인

```bash
journalctl -u vps-guard-edge.service -o json --since today
journalctl -u vps-guard-control.service -o json --since today
journalctl -u vps-guard-edge.service -o json | grep 'guard-0123'
```

세 systemd unit은 `SyslogIdentifier`, `StandardOutput=journal`과 unit별 rate limit을 명시합니다. release build는 Git commit을 binary startup event에 포함합니다. 로컬 개발 build는 `build_commit=unknown`으로 표시됩니다. journal 전체 보존량과 disk 상한은 다른 서비스에도 영향을 주므로 설치 과정에서 자동 변경하지 않습니다.

## 현재 한계

- ASN·국가 enrichment와 offline GeoIP missing 상태는 아직 `CODE_ONLY` 범위 밖이며 후속 구현 대상입니다.
- SQLite busy·disk-full, retention backlog 해소율과 이번 schema의 실제 2GB VPS 증거는 release gate에서 다시 수집해야 합니다.
- journal 보존 정책과 rotation은 host 소유이므로 VPSGuard가 완전한 중앙 로그 보존을 보장하지 않습니다.
