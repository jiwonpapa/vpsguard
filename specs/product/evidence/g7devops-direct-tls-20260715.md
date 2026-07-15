---
title: g7devops Direct TLS Cutover Evidence
status: verified
doc_type: operational-evidence
requirements:
  - EDGE-001
  - EDGE-002
  - EDGE-005
  - TLS-003
  - TLS-005
  - OPS-003
  - OPS-004
verified_at: 2026-07-15
target: g7devops
release_commit: 21ec223a2282d0063c49a0284422c58bdadda3f8
---

# g7devops 직접 TLS 전환 증거

## 판정

`g7devops` 테스트 VPS의 최종 공개 경로는 다음과 같습니다.

```text
Internet -> VPSGuard 0.0.0.0:80/443
         -> Nginx 127.0.0.1:18081
         -> PHP-FPM Unix socket
```

`EDGE-001`, `EDGE-002`, `EDGE-005`, `TLS-003`, `TLS-005`, `OPS-003`,
`OPS-004`를 **VPS_PASS**로 판정합니다. 탐지 모드는 `observe`, CSP는
`report_only`, Cloudflare provider는 비활성 상태를 유지합니다.

## 출처와 전환

- binary release commit: `21ec223a2282d0063c49a0284422c58bdadda3f8`
- CI: <https://github.com/jiwonpapa/vpsguard/actions/runs/29393408130>
- release: <https://github.com/jiwonpapa/vpsguard/actions/runs/29393536635>
- 최종 direct backup: `/var/lib/vps-guard/backups/direct-20260715T062942Z`
- 80 포트를 소유하던 `g7-default-deny.conf`를 첫 전환에서 발견했고 기존
  ingress로 자동 복구했습니다. 전환 후보가 이 listener까지 명시적으로
  비활성화하도록 수정한 뒤 direct TLS 전환을 통과했습니다.

## 실제 read-back

| 검증 | 결과 |
|---|---|
| public 80 owner | `vps-guard-edge` |
| public 443 owner | `vps-guard-edge` |
| Nginx listener | `127.0.0.1:18081` |
| PHP-FPM | `/run/php/php8.5-fpm-g7devops.sock` 직접 연결 |
| HTTP | `308` -> `https://www.g7devops.com/` |
| HTTPS / HTTP/2 | `/`, `/login`, `/robots.txt` 모두 `200` |
| Edge read-back | `x-vps-guard: guard-edge` |
| WebSocket | HTTP/1.1 `101 Switching Protocols` |
| SNI | `g7devops.com`, `www.g7devops.com`에서 등록 certificate 제공 |
| 잘못된 Host | `400` |
| SSH | `0.0.0.0:22`, `[::]:22` 유지 |
| non-web listener | 전환 전 목록과 동일 |
| nftables | 전환 전후 empty ruleset |

## 인증서와 자동 갱신

- 전환 전후 SHA-256 fingerprint:
  `94:4F:29:A0:4B:00:42:27:DD:40:12:A7:0F:1C:15:A3:B8:45:5C:54:C0:86:27:33:F6:5C:DF:DE:23:62:C1:7C`
- 만료: `2026-10-08 02:42:39 UTC`
- 기존 `certbot.timer`: enabled, active
- 기존 renewal: `authenticator = webroot`
- `certbot renew --cert-name g7devops.com --dry-run`: success
- deploy hook: cert/key·config 검증, edge 재시작, Host-safe health 재시도 PASS

기존 Certbot timer와 renewal 설정은 변경하지 않았습니다. Edge private key는
systemd `LoadCredential`로만 전달합니다. `TLS-002`의 완전한 무중단 reload와
`TLS-006`의 미설정 서버 자동 보조 apply는 이 증거의 승인 범위가 아닙니다.
