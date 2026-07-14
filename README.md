# VPSGuard

소규모 VPS의 정상 직접 연결 성능을 유지하면서, 서버 자원을 고갈시키는 봇과 이상 트래픽이 발생할 때만 로컬 방어와 Cloudflare 프록시를 단계적으로 가동하는 Rust 기반 적응형 보안 게이트웨이입니다.

## 현재 상태

현재는 **개발 MVP 단계**입니다. Pingora loopback proxy, 요청 안전 정책, non-blocking telemetry, 상태·탐지 계약, loopback 운영 UI와 shadow 배포 하네스가 실행됩니다. public 80/443 전환, 실제 Cloudflare 변경과 운영 배포는 파일럿 gate 전까지 금지합니다.

## 제품 핵심

```text
평상시: DNS only -> VPSGuard -> Nginx -> Application
비상시: Cloudflare proxied -> VPSGuard -> Nginx -> Application
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
```

운영 CLI는 설정 검증과 무변경 shadow plan을 제공합니다.

```bash
cargo run -p guard-cli -- check-config --config configs/vps-guard.example.toml
cargo run -p guard-cli -- plan --config configs/vps-guard.example.toml
```

`g7devops` 배포 하네스는 기본이 plan-only입니다. `--apply`도 shadow port와 기존 원격 config를 요구하며 Nginx public 80/443, SSH, 인증서와 사이트 데이터를 변경하지 않습니다.

## 아직 release gate가 닫힌 기능

- 다중 인증서 SNI와 인증서 갱신 검증
- policy snapshot의 edge hot reload와 challenge·TTL 차단
- SQLite 장기 집계, 사건 timeline과 SSE
- 실제 Cloudflare API·원본 방화벽 adapter와 복구 검증
- public ingress cutover, bypass, 2GB VPS 성능·장애 파일럿

## 라이선스

현재 저장소는 `publish = false`와 all-rights-reserved 정책을 사용합니다. 공개 저장소라는 사실만으로 코드 사용·재배포 권한을 부여하지 않으며, Community/Pro 라이선스는 파일럿 공개 전에 별도로 확정합니다.
