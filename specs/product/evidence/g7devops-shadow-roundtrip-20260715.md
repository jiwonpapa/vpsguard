---
title: g7devops Shadow Deployment and Restore Evidence
status: verified
doc_type: operational-evidence
requirements:
  - OPS-009
verified_at: 2026-07-15
target: g7devops
release_commit: 72af9e5ed811b7ebb4bd24414876e9ab9f0ca680
---

# g7devops shadow 배포·복구 왕복 증거

## 판정

`OPS-009` **VPS_PASS**. Ubuntu 24.04, x86_64, 2GB `g7devops` 서버에서 실패 자동 복구, 성공 배포, 수동 원상복귀와 동일 release 재설치를 완료했습니다. 공개 Nginx 80/443, Cloudflare mode, G7 site와 핵심 service는 변경하지 않았습니다.

이 증거는 shadow 배포·복구 범위만 승인합니다. public ingress 전환, Cloudflare DNS 변경, TLS 발급·갱신, 차단 정책 활성화와 성능 수용을 승인하지 않습니다.

## release 출처

- commit: `72af9e5ed811b7ebb4bd24414876e9ab9f0ca680`
- CI: <https://github.com/jiwonpapa/vpsguard/actions/runs/29390272859>
- release: <https://github.com/jiwonpapa/vpsguard/actions/runs/29390294476>
- release 결과: `completed/success`
- 로컬 artifact와 설치 binary의 SHA-256 일치:
  - `vps-guard`: `f76067bdad491edfbbf3eb81aa52ad534a3ca8c680dd7a6ce4fc547b38e032df`
  - `vps-guard-control`: `14ea6fe75fddf6bf45d6a8ea5eaa98414cb93cb712ff0eba2aa773f088da976a`
  - `vps-guard-edge`: `c9d62df3ec25f5ded1872587f19e22e0ad1ce16e976ad13ab428bcaef80ba790`

## 왕복 결과

1. 이전 release의 첫 apply가 listener 기동 경합으로 실패했습니다.
   - 외부 snapshot: `deploy-20260715T044620Z-1544354`
   - 내부 update snapshot: `deploy-20260715T044846Z-1670452`
   - 내부·외부 자동 restore: PASS
   - restore 뒤 VPSGuard unit·설치 경로 부재, Nginx·G7 핵심 service·공개 80/443 보존: PASS
2. bounded listener retry를 포함한 위 release로 shadow apply를 완료했습니다.
   - 외부 snapshot: `deploy-20260715T050224Z-2049207`
   - 내부 update snapshot: `deploy-20260715T050452Z-2175136`
3. 외부 snapshot `deploy-20260715T050224Z-2049207`을 `--verify`한 뒤 명시적 수동 restore했습니다.
   - protected SSH·Nginx·인증서·G7 hash read-back: PASS
   - VPSGuard unit·설치 경로 원상복귀: PASS
   - Nginx·G7 핵심 service·공개 HTTPS 응답 보존: PASS
4. 동일 release를 다시 설치해 최종 shadow 상태를 만들었습니다.
   - 외부 복구점: `deploy-20260715T052048Z-2805506`
   - 내부 update 복구점: `deploy-20260715T052314Z-2931438`
   - 배포 후 외부 snapshot read-back: PASS

## 최종 read-back

| 검증 | 결과 |
|---|---|
| `vps-guard-control`, `vps-guard-edge` | `active`, `enabled` |
| Control live, Edge live, Edge ready | `200`, `200`, `200` |
| VPSGuard listener | `127.0.0.1:7727`, `127.0.0.1:18080`만 사용 |
| 공개 listener | 기존 `0.0.0.0/[::]:80,443` 보존 |
| Nginx 설정 | `nginx -t` PASS, VPSGuard public site 설정 부재 |
| 핵심 service | Nginx, PHP 8.5 FPM, MySQL, Redis, G7 queue, G7 Reverb 모두 active |
| 공개 HTTPS | 기존 응답 `301` 보존 |
| Cloudflare mode | `enabled = false` |
| provider token | 값 미기록, `root:root:0600`만 확인 |
| 설정 파일 | `root:vps-guard:0640` |
| 최종 기동 이후 service error journal | 0건 |
| systemd MemoryCurrent | Control 4,516 KiB, Edge 4,376 KiB |

## 실행 명령 계약

- apply: `scripts/deploy-g7devops.sh --apply <verified-release-bundle> configs/vps-guard.g7devops.shadow.toml`
- restore verify/apply: `scripts/restore-g7devops.sh --verify|--apply <snapshot-id>`
- apply와 restore는 각각 commit-bound confirmation과 exact snapshot confirmation 없이는 실행되지 않습니다.
- 비밀값은 bundle, argv, log와 이 증거에 포함하지 않았습니다.
