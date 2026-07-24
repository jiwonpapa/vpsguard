# VPSGuard 운영 하네스

거버넌스·fixture·evidence와 로컬·CI 오케스트레이션은 Python 표준 라이브러리를 사용하고, 운영 VPS의 privileged transaction은 Rust가 소유합니다. Shell은 호환 adapter와 bootstrap에만 유지합니다. 세부 경계는 [하네스 언어 아키텍처](HARNESS_ARCHITECTURE.md)를 따르며 운영 VPS에는 Python package나 pip dependency를 설치하지 않습니다.

## 안전 경계

- 기본 설치와 `g7devops` 배포는 shadow port만 사용합니다.
- public 80/443, Nginx, Cloudflare와 원본 firewall 변경은 별도 `--apply`와 정확한 확인 변수가 필요합니다.
- SSH, `/etc/letsencrypt`, 사이트 data, `/etc/vps-guard`, `/var/lib/vps-guard`는 update·uninstall 대상이 아닙니다.
- 모든 외부 전환은 plan, snapshot, apply, read-back probe, rollback 순서로 실행합니다.

## 단독 설치 관리자·UFW·WAF

`gnuboard5` 파일럿의 직접 관리자 주소는 `https://192.168.0.143:7443`입니다. SSH tunnel이 아니라 Apache TLS virtual host가 loopback Control로 전달합니다. 최초 접속은 `sudo vps-guard issue-login-code --ttl-seconds 600`으로 단회 code를 발급하고, `vpsguard-admin` group의 Linux 계정·서버 비밀번호를 확인한 뒤 화면 QR을 실제 운영자 인증 앱에 등록합니다. 이후 서버 계정·비밀번호와 등록한 TOTP 또는 일회용 복구 코드를 사용합니다. root·system·잠김·만료 계정은 거부하고 비밀번호 원문이나 verifier를 VPSGuard DB에 저장하지 않습니다.

단독 설치는 다음 순서를 지킵니다.

1. 현재 SSH port와 관리자 HTTPS port를 UFW에 운영자 규칙으로 먼저 허용합니다.
2. `vpsguard-admin` system group을 만들고 관리할 기존 Linux 계정만 명시적으로 추가한 뒤 새 login session에서 membership을 확인합니다. 배포 script는 rollback 불가능한 account membership을 자동 변경하지 않습니다.
3. 새 SSH 연결과 관리 URL을 별도 terminal/browser에서 확인합니다.
4. 운영자가 UFW를 활성화합니다. VPSGuard는 비활성 UFW를 자동 활성화하지 않습니다.
5. `firewall.mode = "standalone_ufw"`와 실제 SSH port를 설정합니다.
6. 관리 화면의 `방화벽`에서 IP/CIDR·port·protocol typed rule을 계획하고 diff를 확인한 뒤 적용합니다.
7. 적용 뒤 kernel read-back과 새 SSH 연결을 확인합니다.

VPSGuard는 comment가 `vpsguard:<rule-id>`인 소유 규칙만 추가·제거합니다. SSH port deny, 무제한 catch-all deny, raw command와 외부 운영자 규칙 변경을 거부합니다. UFW 상태 read-back, dry-run, 적용, 실패 복구는 root helper가 수행하며 Control은 systemd의 `0660 root:vps-guard` Unix socket으로만 호출합니다. 제거 시에는 예상치 못한 접속 변경을 피하려고 UFW와 기존 규칙을 보존하므로, VPSGuard 소유 규칙은 제거 전에 방화벽 화면에서 명시적으로 정리합니다.

JW-agent와 함께 설치할 때는 `firewall.mode = "jw_agent_delegated"`를 사용합니다. 이 mode에서 VPSGuard API·UI는 소유자를 표시하지만 UFW·nftables mutation을 fail-closed로 거부합니다. Nginx·Certbot·service·file·terminal 관리는 JW-agent 소유이며 VPSGuard에 중복 구현하지 않습니다.

외부 WAF는 `off` → `detection_only` → `tuned_enforce` 순서로 올립니다. detection audit에서 정상 로그인·회원가입·검색·관리·글쓰기·업로드 경로의 false positive를 확인하고 app별 최소 exclusion을 작성한 뒤에만 enforce합니다. 실제 mode는 `/api/v1/status`와 개요 화면에서 read-back합니다. `gnuboard5` 파일럿은 SQLi·XSS fixture 403과 anonymous GET baseline 오탐 0을 확인했지만 authenticated upload replay는 남아 있습니다.

VM 통합 프로브는 release bundle의 `scripts/standalone-security-probe.sh`를 사용합니다. 비밀번호는 prompt로만 받고 저장하지 않으며, TEST-NET source deny 규칙을 추가·read-back·제거하고 종료 trap에서 복구합니다. 실환경 CA에서는 `curl --insecure`를 제거한 별도 운영 probe를 사용해야 합니다.

## 로컬 빌드 저장공간

Cargo dev/test는 incremental을 끄고 dependency debug 정보를 제거해 반복 빌드의 디스크 누적을 제한합니다. 정리 하네스는 기본 plan-only이며 `--clean`에서만 repository `target` 아래의 재생성 가능한 cache를 전부 삭제합니다. 주요 개발 gate의 `--auto`는 재사용 가치 없는 임시 산출물만 회수하고 debug·release·coverage·rustdoc cache는 보존하며, 기본 4GiB 경고 기준을 넘어도 자동 초기화하지 않습니다. 릴리스 번들과 검증 evidence, 알 수 없는 운영자 파일은 보존합니다.

```bash
bash scripts/build-storage.sh
bash scripts/build-storage.sh --auto
bash scripts/build-storage.sh --clean
```

2026-07-20 기준 전체 `scripts/check.sh` clean rebuild에서 `target`은 35.1GiB에서 1.4GiB로 감소했습니다. 검증 후 다시 `--clean`하면 보존된 release bundle 약 20MiB만 남습니다.

## 단일 운영 transaction과 시간 예산

`OPS-010`은 apply·restore를 동시에 하나만 실행합니다. Rust transaction engine은
OS advisory lock, plan SHA-256, 완료 단계 ledger와 구조화 실패를 원자 저장하고,
process가 중단되면 같은 plan의 마지막 완료 단계 다음부터 재개합니다. shell remote
adapter도 같은 operation ID lock을 사용해 중복 실행을 즉시 거부합니다.

```bash
vps-guard ops plan \
  --operation-id apply-<release> \
  --kind apply \
  --release-id <release-commit> \
  --source nginx-public \
  --target vps-guard-public \
  --ingress-file /etc/nginx/sites-available/example.conf \
  --certificate /etc/letsencrypt/live/example.com/fullchain.pem \
  --output /var/backups/vps-guard/transactions/apply-<release>/plan.json

vps-guard ops status \
  --state /var/backups/vps-guard/transactions/active/state.json
```

hard limit은 preflight 60초, public ingress 누적 순단 5초, apply/update 전체
60초, restore 30초, 자동 rollback 10초입니다. snapshot은 VPSGuard 소유 파일,
승인된 단일 ingress 파일·symlink, service 상태, 공개 인증서 fingerprint와 listener
inventory만 포함합니다. `/home/*/public_html` 같은 사이트 tree는 plan 단계에서 거부합니다.

first-install 배포 상태는 Rust `guard-system` driver가 직접 snapshot·검증·복원합니다.
기존 Shell 진입점은 아래 CLI로만 전달하며 legacy schema v1 snapshot과 호환됩니다.

```bash
vps-guard ops deployment-state plan
sudo vps-guard ops deployment-state snapshot
sudo vps-guard ops deployment-state verify \
  /var/backups/vps-guard/deployments/deploy-<timestamp>-<id>
sudo env VPS_GUARD_RESTORE_CONFIRM=restore-deployment-snapshot \
  vps-guard ops deployment-state restore \
  /var/backups/vps-guard/deployments/deploy-<timestamp>-<id>
```

restore는 대상 검증 뒤 현재 상태를 pre-attempt snapshot으로 다시 보존하고,
VPSGuard-owned 파일·symlink·service·account만 변경합니다. 중간 실패는 같은 Rust
transaction directory의 원자 rollback checkpoint로 process 재시작 뒤에도 복구를
재개합니다. SSH·Nginx·인증서·G7 site 내용은 읽거나 복구하지 않습니다. 재개할 때는
최초 오류에 표시된 동일 `--operation-id`를 사용합니다.

## g7devops shadow 배포

```bash
cargo xtask release "$(rustc -vV | sed -n 's/^host: //p')"
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

apply 직전에 root-only deployment snapshot을 만들고 binary·unit·drop-in·config·Cloudflare token·service enable/active와 first-install directory의 기존/부재 상태를 기록합니다. 실패하면 자동 복구하고, 성공 뒤에도 snapshot ID를 출력합니다. SSH·Nginx·인증서·G7 site source는 복구하거나 전체 hash하지 않으며 상위 directory identity만 확인합니다. non-VPSGuard listener와 핵심 service read-back은 유지합니다. 따라서 배포 사이에 사용자가 변경한 site·Nginx 파일 때문에 VPSGuard 제거가 막히지 않습니다.

Cloudflare token은 로컬 `secrets/cloudflare-token`에서 SSH stdin으로만 전달해 `/etc/vps-guard/secrets/cloudflare-token`의 `root:root 0600` 파일로 설치합니다. bundle, remote user staging file, argv, log와 evidence에는 넣지 않습니다. 기존 원격 token이나 `/etc/vps-guard/config.toml`이 후보와 byte 단위로 다르면 덮어쓰지 않고 배포 전체를 복구합니다.

이 단계는 public Nginx와 80/443, Cloudflare DNS mode를 변경하지 않습니다. 원격 smoke는 loopback edge/control health, origin ready, Nginx config와 보호 경계를 확인합니다.

## g7devops 직접 TLS 트래픽 편입

직접 TLS 검증 이력의 topology는 VPSGuard가 public 80/443과 TLS를 소유했습니다.
현재 `g7devops` 서버는 운영 하네스 개선을 위해 Nginx public 80/443 원본 topology로
복구되어 있으며, 이 변경은 서버에 다시 배포하지 않습니다.

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

복구는 snapshot checksum과 server machine ID를 먼저 확인합니다. VPSGuard가 원래 없던 first install이면 새 binary·unit·drop-in·config·token·state directory와 전용 system account를 제거하고 service 상태를 원래대로 돌립니다. 기존 설치 update라면 snapshot에 있던 파일과 enable/active 상태를 복구하되 runtime data는 보존합니다. 마지막에 Nginx 문법·80/443, 보호 directory identity와 listener/service 상태를 확인합니다. 사이트 전체 file hash는 계산하지 않습니다. snapshot 자체는 root-only 운영 증거로 남깁니다.

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

Rust `IngressSwitchDriver`가 active Nginx, active VPSGuard config와 edge/bypass 후보 2개를 exact-file snapshot으로 보존합니다. staged 후보 설치, `nginx -t`, edge 준비, 짧은 active 교체, service 전환과 공개 `X-VPS-Guard` header read-back 중 하나라도 실패하면 네 파일과 edge 상태를 transaction 직전 값으로 자동 복구합니다. Shell은 기존 CLI 호환과 원격 read-only preflight만 담당합니다.

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

Update는 binary/unit/tmpfiles snapshot을 만든 뒤 control과 Host-safe edge health 중
하나라도 실패하면 복구합니다. 각 health 대기는 재시도 전체를 15초 hard limit 안에
끝내며, 개별 요청 timeout과 재시도 횟수를 곱해 update 60초 예산을 넘기지 않습니다.
이전 Control이 policy version만 갱신한 상태는 저장된 보호 설정과 실제 route 규칙이
정확히 일치할 때만 metadata version을 전진 복구하고, 규칙이 다르면 시작을 거부합니다.
Uninstall은 Nginx 설정·활성 상태와 public probe를 확인하고 edge를 중지한 뒤 probe를
다시 통과해야만 `packaging/ownership-manifest.txt`의 정확한 allowlist를 제거합니다.
중간 probe가 실패하면 edge를 재기동하고 제거를 중단합니다.

Update는 VPSGuard가 현재 public 443을 소유하면 즉시 거부합니다. 먼저 Nginx bypass를
적용하고 HTTPS read-back으로 Nginx가 public port를 소유함을 확인한 뒤 update를 실행해야
하므로 binary copy와 service health 대기 시간이 public 순단에 포함되지 않습니다.

전체 gate의 `release-lifecycle` 하네스는 격리 root에서 같은 update·uninstall script와
Rust deployment snapshot/restore CLI를 실행합니다. 정상 후보 활성화, edge health 실패
자동 원복, failed release 제거와 config·state·SSH·Nginx·인증서·site 보존을 대조합니다.
`VPS_GUARD_TEST_ROOT`는 `VPS_GUARD_FIXTURE_CONFIRM=isolated-root`와 `/`가 아닌 절대
경로가 함께 없으면 거부되며 운영 설치 절차로 사용하지 않습니다.

## Release artifact

태그 또는 수동 `Release artifacts` workflow는 x86_64·aarch64 Linux bundle을 각각
빌드하고 checksum, target ELF, CycloneDX SBOM을 검증합니다. 이어서 target architecture의
Ubuntu 24.04 container에서 `vps-guard`, Control, privileged helper와 Edge의
`--version`을 실제 실행하고, bundle의 example config를 packaged CLI로 검사합니다.
이 실행 단계가 성공한 bundle만 provenance attestation과 artifact upload로 넘어갑니다.
x86_64와 aarch64는 각 CPU의 GitHub-hosted Ubuntu 24.04 native runner에서 빌드합니다.
따라서 `pam-sys`와 bindgen은 해당 architecture의 PAM·Clang 개발 package에 직접
연결되며 오래된 cross image의 libc·LLVM 조합에 의존하지 않습니다.

## 격리 2GB 보호 설정 pilot

`UI-018`의 실제 정책 반영은 운영 서버가 아니라 repository에 등록한 private libvirt
VM manifest로 먼저 검증합니다. 기본 pilot은 `gnuboard5` VM만 대상으로 하며 verified
x86_64 bundle의 모든 checksum을 검사한 뒤 다음 순서를 한 transaction으로 실행합니다.

1. 현재 release·memory·service 상태를 기록하고 bundle과 body-free probe만 guest
   사용자 home의 commit별 stage에 복사
2. QEMU guest agent root 경계에서 기존 `update-release.sh`의 snapshot rollback 적용.
   모든 guest 명령은 GNU `timeout`의 TERM·15초 KILL grace로 감싸 하네스 연결이
   끊겨도 원격 update process를 남기지 않음
3. libvirt live memory를 정확히 2GiB로 축소하고 guest `MemTotal` read-back
4. root 전용 admin socket의 단회 code로 break-glass session을 만들되 code·cookie·CSRF는
   출력하거나 evidence에 저장하지 않음
5. 보호 설정 plan·apply 뒤 정상·strict·upload 요청으로 Edge telemetry version을 확인하고
   원래 설정을 다시 plan·apply해 Edge read-back
6. update 전 deployment snapshot과 원래 VM memory를 복구하고 release·service 상태를
   시작값과 대조한 뒤 stage 제거

```bash
python3 -m tools.vpsguard_harness vm-protection-pilot \
  --manifest tests/vm/gnuboard5-protection-pilot.json \
  --bundle /absolute/path/to/vpsguard-x86_64-unknown-linux-gnu \
  --evidence target-evidence/vm-lab/ui018-pilot.json

python3 -m tools.vpsguard_harness vm-protection-pilot \
  --manifest tests/vm/gnuboard5-protection-pilot.json \
  --bundle /absolute/path/to/vpsguard-x86_64-unknown-linux-gnu \
  --evidence target-evidence/vm-lab/ui018-pilot.json \
  --run --confirm isolated-vm:gnuboard5
```

첫 명령은 plan만 생성합니다. 실행 중 실패하면 적용한 설정은 probe가 먼저 원복하고,
상위 하네스가 deployment snapshot과 원래 memory를 다시 복구합니다. 자동 복구가
완료되지 않으면 stage를 지우지 않아 같은 bundle과 snapshot으로 수동 복구할 수
있습니다. g7devops public 서버에는 이 pilot을 사용하지 않습니다.

## 격리 2GB host pressure pilot

`DET-014`의 실제 host pressure는 `gnuboard5` private VM에서만 실행합니다.
verified x86_64 bundle로 후보 release를 적용하고 VM을 2GiB로 축소한 뒤 고정된
CPU worker, `/proc` 직접값, Control resource API와 상태 전이를 같은 timeline에
기록합니다. public HTTPS probe는 enforce profile의 `120 rpm`보다 낮은
`1,000 ms` 간격으로 고정하며 body와 credential을 저장하지 않습니다.

```bash
python3 -m tools.vpsguard_harness vm-host-pressure \
  --manifest tests/vm/gnuboard5-host-pressure.json \
  --bundle /absolute/path/to/vpsguard-x86_64-unknown-linux-gnu \
  --evidence target-evidence/vm-lab/det014-host-pressure.json

python3 -m tools.vpsguard_harness vm-host-pressure \
  --manifest tests/vm/gnuboard5-host-pressure.json \
  --bundle /absolute/path/to/vpsguard-x86_64-unknown-linux-gnu \
  --evidence target-evidence/vm-lab/det014-host-pressure.json \
  --run --confirm isolated-vm:gnuboard5
```

실행은 `NORMAL`, `WATCH`, `LOCAL_GUARD`, `RECOVERING`, `NORMAL` 순서와
`/proc`·API 정합성, public 순단 예산을 강제합니다. 종료 시 원래 deployment
snapshot, memory, balloon module, service와 SSH를 대조합니다. provider가 없는
VM에서 `EMERGENCY_PROXY`를 성공으로 간주하지 않으며 Cloudflare test zone
폐쇄루프 증거를 별도로 요구합니다.

## TLS 갱신

`packaging/certbot/vps-guard-deploy-hook`를 Certbot deploy hook으로 설치합니다. hook은 certificate/key public key 일치, 24시간 이상 유효기간, VPSGuard config를 검사한 뒤 edge를 재시작하고 health를 read-back합니다. 이어서 `VPS_GUARD_TLS_SERVER_NAME`을 SNI로, `VPS_GUARD_TLS_ADDRESS`의 명시적 IP·port로 TLS handshake를 수행해 갱신 파일과 실제 listener leaf의 SHA-256이 정확히 같을 때만 성공합니다. DNS·CDN 경로와 origin listener 검증을 혼합하지 않습니다.

`tls.management`은 `auto`, `external_managed`, `vpsguard_assisted`, `manual` 중 하나입니다. 기본 `auto`는 `/etc/letsencrypt/live` lineage, renewal 설정, `certbot.timer`·Snap timer 또는 기존 Certbot cron을 읽기 전용으로 확인합니다. 정상 자동 갱신이 있으면 `external_managed`로 표시하고 VPSGuard가 timer나 renewal 설정을 다시 만들지 않습니다. edge service startup은 cert/key·SAN·현재 유효기간만 검사하며 package 설치·발급·timer 변경을 하지 않습니다.

Control은 6시간마다 공개 certificate의 SAN·만료와 갱신 상태를 갱신하고 인증된 status API·관리 화면에 소유자, manager, 만료와 다음 조치를 표시합니다. Edge는 startup마다 공개 certificate와 private key 일치를 추가 검사합니다. 운영자는 같은 검증을 직접 실행할 수 있습니다.

```bash
sudo vps-guard verify-served-certificate \
  --certificate /etc/letsencrypt/live/example.com/fullchain.pem \
  --key /etc/letsencrypt/live/example.com/privkey.pem \
  --server-name example.com \
  --address 127.0.0.1:443
```

일치하면 bounded JSON report를 출력하고, 다른 leaf·잘못된 SAN·key 불일치·handshake 실패는 non-zero로 종료합니다. 현재 hook은 bounded restart와 read-back을 사용하며 완전한 connection-draining reload는 별도 release gate입니다.

Certbot private key 원본을 `vps-guard` 계정에 직접 공개하지 않습니다. 설정에는 `cert_file = "tls-cert.pem"`, `key_file = "tls-key.pem"`처럼 service credential 이름을 사용하고, 설치 도구는 다음 template의 placeholder를 검증된 절대 경로로 치환합니다.

- Control: [`vps-guard-control-tls-certificate.conf.example`](../packaging/systemd/vps-guard-control-tls-certificate.conf.example) — 공개 certificate만 전달
- Edge: [`vps-guard-edge-tls-credentials.conf.example`](../packaging/systemd/vps-guard-edge-tls-credentials.conf.example) — certificate와 private key 전달

생성된 drop-in은 각각 `vps-guard-control.service.d/30-tls-certificate.conf`, `vps-guard-edge.service.d/30-tls-credentials.conf`에 설치합니다. 상대 TLS 경로는 `$CREDENTIALS_DIRECTORY` 밖으로 해석하지 않습니다. 기존 Certbot을 `auto`로 관측할 때는 certificate 설정에 비밀값이 아닌 `certbot_lineage = "example.com"`도 넣습니다. 로컬 개발에서만 직접 읽을 수 있는 절대 경로를 사용할 수 있습니다.

자동 갱신 수단이 없을 때 관리자는 `external_managed`, `vpsguard_assisted`, `manual`을 명시합니다. `vpsguard_assisted`에서만 관리 화면이 ACME email을 받아 DNS, 전용 webroot, origin challenge 연결, public 80, 발급, timer, deploy hook, served certificate 검증 순서의 typed plan을 만듭니다. 이 API는 plan만 반환하며 서버를 변경하지 않습니다. 실제 적용은 같은 plan hash를 다시 표시하고 별도 승인하는 후속 batch 전까지 실행하지 않습니다.

wildcard 인증서처럼 DNS-01이 필요하면 provider plugin의 root-only 자격증명을 별도로 만듭니다. 이 token은 아래 Cloudflare 비상 전환 token과 파일·수명·권한을 공유하지 않습니다.

`g7devops`에서는 기존 webroot renewal을 VPSGuard public 80을 통해 staging
`renew --dry-run`으로 검증했고 deploy hook 재시작과 served certificate fingerprint
read-back을 완료했습니다. 현재 Rust exact 비교가 포함된 hook의 실제 renewal 재실행,
미설정 서버의 신규 발급 보조 apply와 완전한 무중단 certificate reload는 계속 release
gate입니다.

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

현재 adapter는 User API Token 활성 상태를 먼저 확인하고 설정된 모든 record ID를 개별 조회해 name·type·`proxiable`·TTL을 대조합니다. 같은 hostname의 A·AAAA를 모두 snapshot·변경·read-back하며 중간 PATCH 실패 시 이미 변경한 record와 TTL을 즉시 되돌립니다. `max_dns_ttl_seconds` 기본값은 300초이고 허용 범위는 60..=3600초입니다. Cloudflare API TTL `1`은 Auto 300초로 정규화하며 실제 DNS-only TTL이 설정 상한보다 크면 어떤 DNS 변경도 하지 않습니다. durable transaction에는 drain deadline이 저장돼 Control 재시작 뒤 이어서 진행하거나 수동 복구할 수 있습니다. CNAME은 Cloudflare 제약에 따라 같은 이름의 A·AAAA 또는 다른 CNAME과 함께 설정하지 않습니다.

코드와 fake API 검증은 완료됐지만 실제 test zone의 record ID·token scope·DNS 전환·복구 증거는 아직 release gate로 남습니다.

원본 보호 CIDR은 Cloudflare 공식 IPv4·IPv6 목록을 모두 가져와 hash·수집 시각과 함께 검증·cache해야 하며 UI에서 임의 수동 입력한 목록을 신뢰하지 않습니다.

## 관리자 HTTPS webhook 알림

`[notifications]`를 활성화하면 `LOCAL_GUARD`, `EMERGENCY_PROXY`,
`RECOVERY_READY` 전이와 Cloudflare 시작·완료·실패·수동 복구 완료를 별도 bounded
worker가 전달합니다. webhook URL은 query·fragment·내장 인증 정보가 없는 HTTPS만
허용합니다. 요청에는 event ID와 동일한 `Idempotency-Key`가 포함되며 payload는
요약·종류·심각도·mode·reason code로 제한됩니다. 내부 evidence, request body,
원본 IP와 credential은 전송하지 않습니다.

선택적인 bearer token은 `/etc/vps-guard/secrets/notification-webhook-token`에
`root:root 0600`으로 저장합니다.
[`vps-guard-control-notification-credential.conf.example`](../packaging/systemd/vps-guard-control-notification-credential.conf.example)을
`/etc/systemd/system/vps-guard-control.service.d/20-notification-credential.conf`로
설치하고 설정에는 `token_file = "notification-webhook-token"`만 기록합니다.

queue와 재시도는 설정 상한 안에서만 동작합니다. 전송 실패나 receiver 지연은 Edge
요청과 provider transaction을 막지 않습니다. 미완료 event ID는 SQLite에 남아 Control
재시작 뒤 남은 attempt만 이어가며, 성공한 event ID는 다시 보내지 않습니다. 관리자
화면에서 queue·drop·pending·성공·실패와 마지막 안정 오류 코드를 확인합니다.

근거: [Cloudflare API token 생성](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/), [Cloudflare API token 권한](https://developers.cloudflare.com/fundamentals/api/reference/permissions/), [DNS record 조회](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/), [DNS record PATCH](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/edit/), [Cloudflare IP 대역](https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/)

1. DNS와 원본 firewall snapshot
2. proxied 요청과 API read-back
3. 외부 HTTPS 응답의 `cf-ray` 확인
4. snapshot의 기존 DNS-only TTL까지 cache drain
5. 단일 nft transaction으로 `inet vps_guard` table을 교체해 Cloudflare CIDR 외 80/443만 차단
6. kernel read-back 후 완료
7. 안정화 후 `RECOVERY_READY`에서 외부 보호 유지
8. 관리자가 DNS-only 전환 영향을 확인·승인한 경우에만 snapshot 역순 복구

실제 test zone·public 전환 증거 없이는 release 인증으로 판정하지 않습니다.

## 분석 모드 전환

- 기본 `detection.inspection = "profiled"`는 app profile과 동적 행동 정책을 사용합니다.
- `protocol_only`는 HTTP/TLS 종료, Host 검증, 전달 header 재작성, 공통 다계층 rate limit·명시적 정책, body·timeout 상한과 bounded 계측을 유지하되 app profile과 app 전용 행동 판정을 생략합니다. raw TCP/TLS pass-through가 아닙니다.
- mode를 바꾸기 전에 Cloudflare emergency transaction이 없고 상태가 `NORMAL`이며 origin lock이 복구됐는지 확인합니다. edge와 control을 같은 config로 재시작한 뒤 인증된 status API·관리 화면의 `inspection` 값을 확인합니다.
- VPSGuard가 소유하지 않는 SSH·DB·mail·사용자 port는 이 설정과 무관합니다. 소유한 HTTP listener로 들어온 비HTTP 입력은 거부합니다.
- `max_in_flight_requests`, `downstream_io_timeout_ms`, `downstream_min_send_rate_bps`, `keepalive_request_limit`은 2GB VPS의 origin·slow-client 자원 경계입니다. 정상 대용량 응답의 총 크기는 임의로 자르지 않습니다.

## 애플리케이션 보안 정책

- 기본 CSP는 `report_only`이며 정상 G7 SPA·관리자·업로드·WebSocket·외부 asset을 확인한 뒤에만 `enforce`로 바꿉니다.
- HSTS는 public HTTPS와 bypass origin이 모두 정상일 때만 `hsts_max_age_seconds`를 0보다 크게 설정합니다.
- `auth_rate_limit_rpm`은 profile이 인증으로 분류한 경로의 client별 한도입니다. shared IP를 고려해 조정하며 계정·session별 잠금은 origin에서 구현합니다.
- 선택형 ModSecurity·OWASP CRS는 알려진 SQLi·XSS 입력을 origin 전에 보조 차단하지만 origin의 prepared query·escaping·CSRF 책임을 대체하지 않습니다. 세부 경계는 [애플리케이션 보안 경계](APP_SECURITY.md)를 따릅니다.

## 로그와 분석 데이터

- 식별자 형식, JSON 공통 필드와 상관 조회 절차는 [운영 로그와 상관관계](LOGGING.md)를 따릅니다.
- `vps-guard-edge`와 `vps-guard-control`의 structured log는 stdout/stderr로 출력하고 systemd journal에서 수집합니다. 별도 `/var/log/vps-guard` 파일을 중복 생성하지 않습니다.
- journal은 문제·원인·영향·조치 중심의 운영 로그이며 request 전체를 장기 분석하는 저장소로 사용하지 않습니다.
- 트래픽 분석은 edge의 bounded Unix datagram, control의 bounded memory/queue와 SQLite WAL 경로로 분리합니다.
- request body·query·cookie·authorization은 저장하지 않고 normalized route, status, latency, byte count, 판정과 제한된 기간의 client IP만 저장합니다.
- DB writer는 batch transaction, rollup과 bounded retention을 사용하고 queue drop·DB/WAL 크기·disk 여유·마지막 retention 성공을 UI에 표시해야 합니다.
- host 전역 journald 보존량은 VPSGuard가 자동 변경하지 않습니다. 설치 진단에서 현재 설정과 disk 사용량만 표시하고 변경은 관리자 선택으로 남깁니다.
- 각 VPSGuard systemd unit은 `SyslogIdentifier`와 30초당 2,000건의 rate limit을 소유하며 정상 request 완료는 기본 `info`가 아니라 `debug`에만 기록합니다.
