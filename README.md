# VPSGuard

소규모 VPS의 정상 직접 연결 성능을 유지하면서, 서버 자원을 고갈시키는 봇과 이상 트래픽이 발생할 때만 로컬 방어와 Cloudflare 프록시를 단계적으로 가동하는 Rust 기반 적응형 보안 게이트웨이입니다.

## 현재 상태

현재는 **pre-MVP 개발용 수직 슬라이스**입니다. Pingora edge, 정책 hot reload, telemetry, SQLite/SSE control plane, Bun/React 운영 SPA와 provider adapter의 기본 코드가 있으나, 실제 Cloudflare 전환·복구, public 80/443, fault·2GB VPS·rollback 증거는 아직 없습니다. 현재 검증 단계는 [`verification-status.tsv`](specs/product/verification-status.tsv)가 정본입니다.

## 제품 핵심

```text
평상시: DNS only -> VPSGuard -> Nginx -> Application
비상시: Cloudflare proxied -> VPSGuard -> Nginx -> Application
관리면: guard.example.com:443 -> VPSGuard -> loopback Control
```

- 평상시에는 해외 프록시를 상시 통과하지 않습니다.
- 요청량만 보지 않고 PHP-FPM, MySQL, Redis와 고비용 경로의 실제 부담을 판단합니다.
- 검색봇, AI 학습봇, AI 검색봇과 스크래퍼를 포함한 자원 고갈형 자동화 트래픽을 다룹니다.
- 모든 자동 조치는 이유, 실제 적용 상태와 복구 방법을 남깁니다.
- 독립 웹 UI에서 실시간 트래픽, 외부 IP, 서버 자원과 사건을 확인합니다.

## 구현 정본

1. [MASTER SDD](specs/product/MASTER_SDD.md)
2. [요구사항과 계약](specs/product/06-requirements-contracts.md)
3. [검증 추적표](specs/product/07-verification-traceability.md)
4. [구현 백로그](specs/product/08-implementation-backlog.md)
5. [모니터링 웹 UI](specs/product/09-monitoring-web-ui.md)
6. [개발 헌법](DEVELOPMENT_CONSTITUTION.md)
7. [초기 구현 결정](specs/product/10-bootstrap-decisions.md)
8. [보안 advisory 예외](docs/security/advisory-exceptions.md)
9. [개발 MVP 구현 현황](specs/product/11-mvp-implementation-status.md)

전체 배경과 사업 가설은 [제품 문서 색인](specs/product/README.md)에서 확인합니다.

## 기존 자산

과거 월척웹에서 구현했던 Pingora `edge_proxy`를 기준 자산으로 사용합니다. 새 프록시를 처음부터 만들지 않고 Host, forwarded header, IP/CIDR, rate limit, body, timeout, TLS와 운영 테스트를 복구·일반화합니다.

## 프로젝트 경계

VPSGuard는 G7 Installer와 독립된 유지보수·방어 제품입니다. 설치기는 VPSGuard의 런타임 정책, 사건 상태와 업데이트를 소유하지 않습니다.

## 로컬 검증

```bash
bash scripts/check.sh
bash scripts/integration-gate.sh
bash scripts/ops-harness.sh
bash scripts/load-regression-gate.sh
cargo xtask coverage
cargo xtask web
```

운영 CLI는 설정 검증, 무변경 shadow plan과 local peer credential 기반 단회 로그인 code 발급을 제공합니다.

```bash
cargo run -p guard-cli -- check-config --config configs/vps-guard.example.toml
cargo run -p guard-cli -- plan --config configs/vps-guard.example.toml
sudo vps-guard issue-login-code
```

`g7devops` 배포 하네스는 기본이 plan-only입니다. `--apply`는 checksum이 맞는 Linux x86_64 bundle과 별도 shadow config를 요구하며, 기존 원격 config는 byte 단위로 같지 않으면 거부합니다. Nginx public 80/443, SSH, 인증서와 사이트 데이터는 변경하지 않습니다.

## 아직 release 인증이 필요한 기능

- 단일 listener의 인증서별 multi-SNI 선택
- Certbot HTTP-01 발급·갱신과 실제 served certificate 비교
- Cloudflare test zone의 실제 proxied 전환·복구와 `cf-ray` 증거
- `g7devops` public ingress cutover·bypass 왕복
- 2GB VPS 성능·장애·복구 파일럿과 multi-architecture artifact 실행 smoke

## 라이선스

현재 저장소는 `publish = false`와 all-rights-reserved 정책을 사용합니다. 공개 저장소라는 사실만으로 코드 사용·재배포 권한을 부여하지 않으며, Community/Pro 라이선스는 파일럿 공개 전에 별도로 확정합니다.
