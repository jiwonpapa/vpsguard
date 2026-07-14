# VPSGuard 운영 하네스

## 안전 경계

- 기본 설치와 `g7devops` 배포는 shadow port만 사용합니다.
- public 80/443, Nginx, Cloudflare와 원본 firewall 변경은 별도 `--apply`와 정확한 확인 변수가 필요합니다.
- SSH, `/etc/letsencrypt`, 사이트 data, `/etc/vps-guard`, `/var/lib/vps-guard`는 update·uninstall 대상이 아닙니다.
- 모든 외부 전환은 plan, snapshot, apply, read-back probe, rollback 순서로 실행합니다.

## g7devops shadow 배포

```bash
CARGO_BUILD_TOOL=cross cargo xtask release x86_64-unknown-linux-gnu
bash scripts/deploy-g7devops.sh --plan
VPS_GUARD_DEPLOY_CONFIRM=g7devops-shadow \
  bash scripts/deploy-g7devops.sh --apply \
  target/release-bundle/x86_64-unknown-linux-gnu/vpsguard-<version> \
  /path/to/g7devops-shadow.toml
```

이 단계는 public Nginx와 80/443을 변경하지 않습니다. release checksum·target, 원격 architecture와 config를 먼저 검증합니다. 기존 `/etc/vps-guard/config.toml`은 후보와 byte 단위로 같을 때만 유지하며 자동 덮어쓰지 않습니다. 원격 smoke는 loopback edge/control health, origin ready와 systemd 상태를 확인합니다.

## Public ingress와 bypass

`/etc/vps-guard/nginx/edge-origin.conf`는 Nginx를 loopback origin으로 옮기는 검증된 후보이고, `public-bypass.conf`는 기존 public Nginx listener 복구 후보입니다.

```bash
bash scripts/ingress-transaction.sh --to-edge --plan
sudo VPS_GUARD_INGRESS_CONFIRM=to-edge \
  VPS_GUARD_INGRESS_PROBE_URL=https://example.com/health/live \
  bash scripts/ingress-transaction.sh --to-edge --apply

sudo VPS_GUARD_INGRESS_CONFIRM=to-nginx \
  VPS_GUARD_INGRESS_PROBE_URL=https://example.com/health \
  bash scripts/ingress-transaction.sh --to-nginx --apply
```

후보 설치, `nginx -t`, service 전환과 외부 probe 중 하나라도 실패하면 이전 active include를 복구합니다.

## Update와 uninstall

```bash
bash scripts/update-release.sh --plan /path/to/bundle
sudo VPS_GUARD_UPDATE_CONFIRM=update-with-rollback \
  VPS_GUARD_EDGE_HOST=example.com \
  bash scripts/update-release.sh --apply /path/to/bundle

bash scripts/uninstall.sh --plan
sudo VPS_GUARD_UNINSTALL_CONFIRM=remove-owned-artifacts-only \
  VPS_GUARD_BYPASS_VERIFIED=nginx-public \
  VPS_GUARD_UNINSTALL_PROBE_URL=https://example.com/health \
  bash scripts/uninstall.sh --apply
```

Update는 binary/unit/tmpfiles snapshot을 만든 뒤 control과 Host-safe edge health 중 하나라도 실패하면 복구합니다. Uninstall은 Nginx 설정·활성 상태와 public probe를 확인하고 edge를 중지한 뒤 probe를 다시 통과해야만 `packaging/ownership-manifest.txt`의 정확한 allowlist를 제거합니다. 중간 probe가 실패하면 edge를 재기동하고 제거를 중단합니다.

## TLS 갱신

`packaging/certbot/vps-guard-deploy-hook`를 Certbot deploy hook으로 설치합니다. hook은 certificate/key public key 일치, 24시간 이상 유효기간, VPSGuard config를 검사한 뒤 edge를 재시작하고 health를 read-back합니다.

## Cloudflare 비상 보호

Cloudflare token 파일은 `0600`이어야 합니다. MVP는 `allowed_hosts`·`canonical_host`와 일치하는 정확히 한 개의 DNS record 및 IPv4·IPv6 Cloudflare CIDR을 모두 요구합니다. Backend는 record allowlist를 확인하고 다음 순서를 강제합니다.
Control service는 VPSGuard-owned `inet vps_guard` table만 다루기 위해 `CAP_NET_ADMIN`과 `AF_NETLINK`만 추가 허용하며, 공통 command allowlist 밖의 program은 실행하지 않습니다.

1. DNS와 원본 firewall snapshot
2. proxied 요청과 API read-back
3. 외부 HTTPS 응답의 `cf-ray` 확인
4. 단일 nft transaction으로 `inet vps_guard` table을 교체해 Cloudflare CIDR 외 80/443만 차단
5. kernel read-back 후 완료
6. 안정화 후 snapshot 역순 복구

실제 test zone·public 전환 증거 없이는 release 인증으로 판정하지 않습니다.
