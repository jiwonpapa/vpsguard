# 보안 advisory 예외

## RUSTSEC-2024-0437

- 경로: `pingora-core 0.8.0 -> prometheus 0.13.4 -> protobuf 2.28.0`
- 상태: 임시 예외, 2026-08-14 재검토
- upstream: `cloudflare/pingora#875`
- 취약 동작: 신뢰할 수 없는 protobuf 입력의 unknown group을 decode할 때 무제한 재귀로 process가 종료될 수 있습니다.
- VPSGuard 노출성: VPSGuard는 protobuf request body를 decode하지 않습니다. 해당 의존성은 Pingora 내부 Prometheus metric encode 경로로만 유입되며 public protobuf parser endpoint가 없습니다.
- 통제: `protobuf` decode API 또는 Prometheus push/parser 기능을 추가하면 이 예외는 즉시 무효입니다.
- 제거 조건: Pingora가 `prometheus >=0.14` 또는 `protobuf >=3.7.2`를 사용한 release를 제공하면 pin을 갱신하고 예외를 삭제합니다.

이 예외는 취약 패키지가 없다는 뜻이 아닙니다. 현재 실행 경로에서 공격자 제어 입력이 취약 함수에 도달하지 않는다는 범위 제한 판정입니다.

## Pingora의 unmaintained 전이 의존성

| Advisory | Crate | 판정 |
|---|---|---|
| `RUSTSEC-2024-0388` | `derivative 2.2.0` | Pingora 내부 derive 의존성, 알려진 취약 동작 없음 |
| `RUSTSEC-2025-0069` | `daemonize 0.5.0` | Pingora CLI daemon 기능 의존성. systemd foreground 실행만 사용 |
| `RUSTSEC-2025-0134` | `rustls-pemfile 2.2.0` | archived parser wrapper. 알려진 취약 동작 없음, Pingora rustls가 전이 의존 |

- 상태: 임시 예외, 2026-08-14 재검토
- 통제: VPSGuard는 Pingora daemon mode를 사용하지 않으며 systemd가 lifecycle을 소유합니다.
- 제거 조건: Pingora에서 해당 의존성을 제거한 release가 나오면 pin 갱신 후 예외를 삭제합니다.
- 정책: `cargo audit`의 vulnerability는 별도 명시 예외 없이는 실패하고, unmaintained warning은 `cargo deny`에서 이 목록만 허용합니다.
