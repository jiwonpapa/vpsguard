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
bash scripts/deploy-g7devops.sh --preflight \
  target/release-bundle/x86_64-unknown-linux-gnu/vpsguard-<version> \
  configs/vps-guard.g7devops.shadow.toml

VPS_GUARD_DEPLOY_CONFIRM=g7devops-shadow:<BUILD-INFO의-git-commit> \
  bash scripts/deploy-g7devops.sh --apply \
  target/release-bundle/x86_64-unknown-linux-gnu/vpsguard-<version> \
  configs/vps-guard.g7devops.shadow.toml
```

`--preflight`는 Ubuntu 24.04·x86_64·2GB, Nginx·PHP 8.5·MySQL·Redis·G7 service, `/home/g7devops/public_html/public`, loopback origin 8080과 public listener를 읽기 전용으로 검증합니다. `--apply`는 `BUILD-INFO.txt`의 정확한 commit 확인값을 요구합니다.

apply 직전에 root-only deployment snapshot을 만들고 binary·unit·drop-in·config·Cloudflare token·service enable/active와 first-install directory의 기존/부재 상태를 기록합니다. 실패하면 자동 복구하고, 성공 뒤에도 snapshot ID를 출력합니다. SSH·Nginx·인증서·G7 site source와 non-VPSGuard listener는 복구 대상으로 덮어쓰지 않고 전후 hash·상태가 같아야만 성공합니다.

Cloudflare token은 로컬 `secrets/cloudflare-token`에서 SSH stdin으로만 전달해 `/etc/vps-guard/secrets/cloudflare-token`의 `root:root 0600` 파일로 설치합니다. bundle, remote user staging file, argv, log와 evidence에는 넣지 않습니다. 기존 원격 token이나 `/etc/vps-guard/config.toml`이 후보와 byte 단위로 다르면 덮어쓰지 않고 배포 전체를 복구합니다.

이 단계는 public Nginx와 80/443, Cloudflare DNS mode를 변경하지 않습니다. 원격 smoke는 loopback edge/control health, origin ready, Nginx config와 보호 경계를 확인합니다.

## g7devops 직접 TLS 트래픽 편입

현재 `g7devops` 테스트 VPS는 VPSGuard가 public 80/443과 TLS를 직접 소유합니다.

```text
Internet -> VPSGuard public 80/443
         -> Nginx origin 127.0.0.1:18081 -> PHP-FPM Unix socket
```

기존 Certbot lineage와 timer는 그대로 두고 certificate와 private key만 systemd
credential로 edge에 전달합니다. Nginx의 기존 public 설정은 bypass 후보로 보존하며
활성 Nginx는 loopback origin만 엽니다.

```bash
bash scripts/cutover-g7devops-direct.sh --plan

VPS_GUARD_DIRECT_CONFIRM=g7devops:direct-tls:<BUILD-INFO의-git-commit> \
  bash scripts/cutover-g7devops-direct.sh --apply \
  target/release-bundle/x86_64-unknown-linux-gnu/vpsguard-<version>
```

전환 후보는 release checksum에 포함됩니다. apply는 active Nginx·VPSGuard config와
TLS drop-in을 백업하고 Nginx 문법·VPSGuard config를 사전 검사합니다. 전환 뒤
80/443의 process owner, loopback Nginx, certificate fingerprint, public 로그인과
`x-vps-guard: guard-edge`를 read-back하며 실패하면 이전 topology로 복구합니다.

기존 Nginx TLS를 유지한 중간 편입과 즉시 bypass는 다음 하네스를 사용합니다.

```bash
bash scripts/cutover-g7devops.sh --plan --to-edge
```

즉시 bypass는 같은 release에서 실행합니다.

```bash
VPS_GUARD_CUTOVER_CONFIRM=g7devops:to-nginx:<BUILD-INFO의-git-commit> \
  bash scripts/cutover-g7devops.sh --apply --to-nginx \
  target/release-bundle/x86_64-unknown-linux-gnu/vpsguard-<version>
```

probe·Nginx 문법·service·header read-back 중 하나라도 실패하면 active Nginx와 VPSGuard config 및 edge 기동 상태를 transaction 직전 값으로 복구합니다. 이 파일럿은 `mode = "observe"`, Cloudflare 비활성, HSTS 비활성과 기존 88MiB body 한도를 유지합니다.

## g7devops 배포 원상복귀

```bash
bash scripts/restore-g7devops.sh --list
bash scripts/restore-g7devops.sh --verify deploy-<timestamp>-<pid>

VPS_GUARD_RESTORE_CONFIRM=g7devops:deploy-<timestamp>-<pid> \
  bash scripts/restore-g7devops.sh --apply deploy-<timestamp>-<pid>
```

복구는 snapshot checksum과 server machine ID를 먼저 확인합니다. VPSGuard가 원래 없던 first install이면 새 binary·unit·drop-in·config·token·state directory와 전용 system account를 제거하고 service 상태를 원래대로 돌립니다. 기존 설치 update라면 snapshot에 있던 파일과 enable/active 상태를 복구하되 runtime data는 보존합니다. 마지막에 Nginx 문법·80/443과 보호 hash를 다시 확인합니다. snapshot 자체는 root-only 운영 증거로 남깁니다.

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

`tls.management`은 `auto`, `external_managed`, `vpsguard_assisted`, `manual` 중 하나입니다. 기본 `auto`는 `/etc/letsencrypt/live` lineage, renewal 설정, `certbot.timer`·Snap timer 또는 기존 Certbot cron을 읽기 전용으로 확인합니다. 정상 자동 갱신이 있으면 `external_managed`로 표시하고 VPSGuard가 timer나 renewal 설정을 다시 만들지 않습니다. edge service startup은 cert/key·SAN·현재 유효기간만 검사하며 package 설치·발급·timer 변경을 하지 않습니다.

Control은 6시간마다 공개 certificate의 SAN·만료와 갱신 상태를 갱신하고 인증된 status API·관리 화면에 소유자, manager, 만료와 다음 조치를 표시합니다. Edge는 startup마다 공개 certificate와 private key 일치를 추가 검사합니다. 실제 제공 중인 certificate fingerprint 비교는 아직 release gate입니다.

Certbot private key 원본을 `vps-guard` 계정에 직접 공개하지 않습니다. 설정에는 `cert_file = "tls-cert.pem"`, `key_file = "tls-key.pem"`처럼 service credential 이름을 사용하고, 설치 도구는 다음 template의 placeholder를 검증된 절대 경로로 치환합니다.

- Control: [`vps-guard-control-tls-certificate.conf.example`](../packaging/systemd/vps-guard-control-tls-certificate.conf.example) — 공개 certificate만 전달
- Edge: [`vps-guard-edge-tls-credentials.conf.example`](../packaging/systemd/vps-guard-edge-tls-credentials.conf.example) — certificate와 private key 전달

생성된 drop-in은 각각 `vps-guard-control.service.d/30-tls-certificate.conf`, `vps-guard-edge.service.d/30-tls-credentials.conf`에 설치합니다. 상대 TLS 경로는 `$CREDENTIALS_DIRECTORY` 밖으로 해석하지 않습니다. 기존 Certbot을 `auto`로 관측할 때는 certificate 설정에 비밀값이 아닌 `certbot_lineage = "example.com"`도 넣습니다. 로컬 개발에서만 직접 읽을 수 있는 절대 경로를 사용할 수 있습니다.

자동 갱신 수단이 없을 때 관리자는 `external_managed`, `vpsguard_assisted`, `manual`을 명시합니다. `vpsguard_assisted`에서만 관리 화면이 ACME email을 받아 DNS, 전용 webroot, origin challenge 연결, public 80, 발급, timer, deploy hook, served certificate 검증 순서의 typed plan을 만듭니다. 이 API는 plan만 반환하며 서버를 변경하지 않습니다. 실제 적용은 같은 plan hash를 다시 표시하고 별도 승인하는 후속 batch 전까지 실행하지 않습니다.

wildcard 인증서처럼 DNS-01이 필요하면 provider plugin의 root-only 자격증명을 별도로 만듭니다. 이 token은 아래 Cloudflare 비상 전환 token과 파일·수명·권한을 공유하지 않습니다.

`g7devops`에서는 기존 webroot renewal을 VPSGuard public 80을 통해 staging
`renew --dry-run`으로 검증했고 deploy hook 재시작과 served certificate fingerprint
read-back을 완료했습니다. 미설정 서버의 신규 발급 보조 apply와 완전한 무중단
certificate reload는 계속 release gate입니다.

근거: [Certbot webroot와 renewal hook 문서](https://eff-certbot.readthedocs.io/en/stable/using.html), [systemd credentials](https://systemd.io/CREDENTIALS/)

## Cloudflare 비상 보호

Cloudflare token 원본은 `root:root 0600`이어야 합니다. MVP는 `allowed_hosts`·`canonical_host`와 일치하는 정확히 한 hostname의 명시적 record ID·type allowlist 및 IPv4·IPv6 Cloudflare CIDR을 모두 요구합니다. Backend는 최대 16개의 A·AAAA 또는 단일 CNAME을 확인하고 다음 순서를 강제합니다.
Control service는 VPSGuard-owned `inet vps_guard` table만 다루기 위해 `CAP_NET_ADMIN`과 `AF_NETLINK`만 추가 허용하며, 공통 command allowlist 밖의 program은 실행하지 않습니다.

### API token 설정

VPSGuard의 기본 생성 경로는 Cloudflare User API Token입니다. Cloudflare dashboard의 `My Profile > API Tokens`에서 `Edit zone DNS` template 또는 custom token을 사용합니다.

User API Token을 만들 때 다음만 부여합니다.

- Permission: `Zone` / `DNS` / `Edit`
- Zone Resources: `Include` / `Specific zone` / 보호할 zone 한 개
- Client IP Address Filtering: VPS 공인 egress IP가 고정일 때만 선택적으로 해당 IP로 제한

현재 설정은 `zone_id`를 직접 받으므로 `Zone` / `Zone` / `Read`는 최소 권한에 필요하지 않습니다. 향후 UI가 zone 이름으로 ID를 찾는 기능을 제공할 때만 별도 검토합니다. Cache Purge, WAF, Rulesets, Account와 Zone Edit 권한은 부여하지 않습니다.

Account API Token 화면의 `Account DNS Settings`, `DNS Firewall`, `DNS View`는 `/zones/{zone_id}/dns_records`의 record 조회·변경 권한이 아닙니다. 필요한 zone-scoped `DNS Write`가 dashboard에 노출되지 않는 계정에서는 이를 대체 권한으로 선택하지 않습니다. Account API Token onboarding은 실제 `com.cloudflare.api.account.zone` 범위의 `DNS Write` 생성과 대상 계정 검증 증거가 준비될 때까지 지원 범위에서 제외합니다. `Account API Tokens Read/Write`도 다른 token 관리 권한이므로 runtime token에 부여하지 않습니다.

token 본문은 `/etc/vps-guard/secrets/cloudflare-token`에 한 줄로 저장하고 소유자 `root:root`, mode `0600`을 적용합니다. Control은 `vps-guard` 사용자로 실행하므로 이 파일을 직접 읽지 않습니다. Cloudflare를 활성화할 때만 [`vps-guard-control-cloudflare-credential.conf`](../packaging/systemd/vps-guard-control-cloudflare-credential.conf)를 `vps-guard-control.service.d/20-cloudflare-credential.conf`로 설치해 systemd `LoadCredential=`로 전달합니다. 설정의 `token_file = "cloudflare-token"`은 `$CREDENTIALS_DIRECTORY/cloudflare-token`으로만 해석됩니다. 로컬 개발에서는 Git에서 제외된 `0600` 절대 경로를 사용할 수 있습니다.

token을 대화, issue, shell argument 또는 로그에 붙였다면 유출로 간주하고 Cloudflare에서 roll한 뒤 원본 파일을 원자 교체하고 control service를 재시작합니다. token 본문은 TOML, UI, browser bundle, shell argv와 로그에 넣지 않습니다. 설정에는 `zone_id`와 비밀값이 아닌 record ID·name·type allowlist만 둡니다.

목표 API 범위는 다음으로 제한합니다.

- User token: `GET /user/tokens/verify`
- `GET /zones/{zone_id}/dns_records/{record_id}`: 허용 ID의 name·type·proxy 가능 여부와 snapshot
- `PATCH /zones/{zone_id}/dns_records/{record_id}`: `proxied` 변경
- 동일 record 재조회: API read-back

현재 adapter는 User API Token 활성 상태를 먼저 확인하고 설정된 모든 record ID를 개별 조회해 name·type·`proxiable`을 대조합니다. 같은 hostname의 A·AAAA를 모두 snapshot·변경·read-back하며 중간 PATCH 실패 시 이미 변경한 record를 즉시 되돌립니다. durable transaction snapshot은 중간 단계에서도 수동·자동 복구할 수 있습니다. CNAME은 Cloudflare 제약에 따라 같은 이름의 A·AAAA 또는 다른 CNAME과 함께 설정하지 않습니다.

코드와 fake API 검증은 완료됐지만 실제 test zone의 record ID·token scope·DNS 전환·복구 증거는 아직 release gate로 남습니다.

원본 보호 CIDR은 Cloudflare 공식 IPv4·IPv6 목록을 모두 가져와 hash·수집 시각과 함께 검증·cache해야 하며 UI에서 임의 수동 입력한 목록을 신뢰하지 않습니다.

근거: [Cloudflare API token 생성](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/), [Cloudflare API token 권한](https://developers.cloudflare.com/fundamentals/api/reference/permissions/), [DNS record 조회](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/), [DNS record PATCH](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/edit/), [Cloudflare IP 대역](https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/)

1. DNS와 원본 firewall snapshot
2. proxied 요청과 API read-back
3. 외부 HTTPS 응답의 `cf-ray` 확인
4. 단일 nft transaction으로 `inet vps_guard` table을 교체해 Cloudflare CIDR 외 80/443만 차단
5. kernel read-back 후 완료
6. 안정화 후 snapshot 역순 복구

실제 test zone·public 전환 증거 없이는 release 인증으로 판정하지 않습니다.

## 분석 모드 전환

- 기본 `detection.inspection = "profiled"`는 app profile과 동적 행동 정책을 사용합니다.
- `protocol_only`는 HTTP/TLS 종료, Host 검증, 전달 header 재작성, body·timeout 상한과 bounded 계측을 유지하되 app profile과 자동 동적 차단을 생략합니다. raw TCP/TLS pass-through가 아닙니다.
- mode를 바꾸기 전에 Cloudflare emergency transaction이 없고 상태가 `NORMAL`이며 origin lock이 복구됐는지 확인합니다. edge와 control을 같은 config로 재시작한 뒤 인증된 status API·관리 화면의 `inspection` 값을 확인합니다.
- VPSGuard가 소유하지 않는 SSH·DB·mail·사용자 port는 이 설정과 무관합니다. 소유한 HTTP listener로 들어온 비HTTP 입력은 거부합니다.

## 애플리케이션 보안 정책

- 기본 CSP는 `report_only`이며 정상 G7 SPA·관리자·업로드·WebSocket·외부 asset을 확인한 뒤에만 `enforce`로 바꿉니다.
- HSTS는 public HTTPS와 bypass origin이 모두 정상일 때만 `hsts_max_age_seconds`를 0보다 크게 설정합니다.
- `auth_rate_limit_rpm`은 profile이 인증으로 분류한 경로의 client별 한도입니다. shared IP를 고려해 조정하며 계정·session별 잠금은 origin에서 구현합니다.
- SQL injection·XSS와 G7의 입력 검증·escaping·CSRF 책임은 [애플리케이션 보안 경계](APP_SECURITY.md)를 따릅니다.

## 로그와 분석 데이터

- `vps-guard-edge`와 `vps-guard-control`의 structured log는 stdout/stderr로 출력하고 systemd journal에서 수집합니다. 별도 `/var/log/vps-guard` 파일을 중복 생성하지 않습니다.
- journal은 문제·원인·영향·조치 중심의 운영 로그이며 request 전체를 장기 분석하는 저장소로 사용하지 않습니다.
- 트래픽 분석은 edge의 bounded Unix datagram, control의 bounded memory/queue와 SQLite WAL 경로로 분리합니다.
- request body·query·cookie·authorization은 저장하지 않고 normalized route, status, latency, byte count, 판정과 제한된 기간의 client IP만 저장합니다.
- DB writer는 batch transaction, rollup과 bounded retention을 사용하고 queue drop·DB/WAL 크기·disk 여유·마지막 retention 성공을 UI에 표시해야 합니다.
- host 전역 journald 보존량은 VPSGuard가 자동 변경하지 않습니다. 설치 진단에서 현재 설정과 disk 사용량만 표시하고 변경은 관리자 선택으로 남깁니다.
