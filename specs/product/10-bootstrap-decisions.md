---
title: VPS Guard Bootstrap Decisions
status: active
doc_type: decision-record
source_of_truth: true
spec_version: 1
last_reviewed: 2026-07-14
---

# 초기 구현 결정

## 확정

| 항목 | 결정 |
|---|---|
| 제품명 | `VPSGuard` |
| CLI | `vps-guard` |
| 실행 파일 | `vps-guard-edge`, `vps-guard-control` |
| systemd | `vps-guard-edge.service`, `vps-guard-control.service` |
| 저장소 | `jiwonpapa/vpsguard`, public |
| 초기 upstream | Nginx only |
| UI bind | `127.0.0.1:7727` |
| UI 접속 | edge 443의 별도 HTTPS 관리 Host, SSH는 단회 code 발급·복구 전용 |
| 원본 IP 기본 보존 | 7일 |
| 기준 Pingora 소스 | `jiwonpapa/rust-middleware` commit `29448031235634d3444103a22a2db7b2ccd0ab39` |
| 제거 commit | `87c0f0e61d5eb5a030fe4a70cdc40d3063cff135` |
| agent 구조 | 별도 `guard-agent` library crate, MVP에서는 `guard-control` 프로세스에 링크 |
| 첫 2GB 파일럿 | SSH alias `g7devops` |

## 라이선스 경계

현재 모든 workspace crate는 `publish = false`입니다. 공개 저장소 가시성만으로 사용·수정·재배포 권한을 부여하지 않는 all-rights-reserved 상태를 유지합니다. Community/Pro 라이선스와 외부 배포 권한은 파일럿 공개 전에 별도 결정합니다.

월척 Pingora 참조본은 형님이 개발한 소스의 출처와 기준 commit을 보존한 내부 이관 기준입니다. 참조 사본은 수정하지 않고 실행 workspace member와 release artifact에서 제외합니다.

## 보류

- 첫 Cloudflare test zone과 최소 권한 token
- Community/Pro 공개 라이선스
- 첫 VPS provider 방화벽 adapter
