# VPSGuard

소규모 VPS의 정상 직접 연결 성능을 유지하면서, 서버 자원을 고갈시키는 봇과 이상 트래픽이 발생할 때만 로컬 방어와 Cloudflare 프록시를 단계적으로 가동하는 Rust 기반 적응형 보안 게이트웨이입니다.

## 현재 상태

현재는 **v0.1.0-alpha 파일럿**입니다. Pingora edge, 정책 hot reload, telemetry, SQLite/SSE control plane, Bun/React·Tailwind CSS·shadcn/ui 운영 SPA, Linux-PAM/TOTP, standalone UFW와 선택형 ModSecurity·OWASP CRS를 구현했습니다. `gnuboard5` VM의 public 80/443, 직접 웹 관리자, 공격 replay와 실제 2GB 검증, x86_64/aarch64 release artifact 실행은 통과했습니다. 다만 실제 운영자 PAM+TOTP 등록, Cloudflare test zone, 공식 crawler source와 authenticated upload WAF 오탐 검증은 남아 있습니다. 따라서 기본값은 Cloudflare 비활성·CSP report-only·기존 인증서 관리자 보존이며 production release로 간주하지 않습니다. 현재 검증 단계는 [`verification-status.tsv`](specs/product/verification-status.tsv)가 정본입니다.

## 제품 핵심

```text
평상시: DNS only -> VPSGuard -> Nginx -> Application
비상시: Cloudflare proxied -> VPSGuard -> Nginx -> Application
관리면: admin.example.com:443 또는 전용 7443 -> trusted TLS terminator -> loopback Control
```

- 평상시에는 해외 프록시를 상시 통과하지 않습니다.
- 요청량만 보지 않고 PHP-FPM, MySQL, Redis와 고비용 경로의 실제 부담을 판단합니다.
- 검색봇, AI 학습봇, AI 검색봇과 스크래퍼를 포함한 자원 고갈형 자동화 트래픽을 다룹니다.
- 모든 자동 조치는 이유, 실제 적용 상태와 복구 방법을 남깁니다.
- 독립 웹 UI에서 실시간 트래픽, 외부 IP, 서버 자원과 사건을 확인합니다.
- 단독 설치는 Linux-PAM+TOTP로 로그인하고 VPSGuard 소유 UFW 규칙만 typed transaction으로 관리합니다.
- JW-agent 연동 설치는 방화벽 소유권을 JW-agent에 위임하고 VPSGuard의 중복 서버 유지보수 기능을 비활성화합니다.

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
10. [핵심 서비스 관측 설정](docs/SERVICE_OBSERVABILITY.md)
11. [애플리케이션 보안 경계](docs/APP_SECURITY.md)
12. [인프라 거버넌스·하네스 언어 경계](docs/HARNESS_ARCHITECTURE.md)

전체 배경과 사업 가설은 [제품 문서 색인](specs/product/README.md)에서 확인합니다.

## 기존 자산

과거 월척웹에서 구현했던 Pingora `edge_proxy`를 기준 자산으로 사용합니다. 새 프록시를 처음부터 만들지 않고 Host, forwarded header, IP/CIDR, rate limit, body, timeout, TLS와 운영 테스트를 복구·일반화합니다.

## 프로젝트 경계

VPSGuard는 G7 Installer와 독립된 유지보수·방어 제품입니다. 설치기는 VPSGuard의 런타임 정책, 사건 상태와 업데이트를 소유하지 않습니다.

## 서버 설치

> 요구사항: `OPS-001`, `OPS-002`, `OPS-005`~`OPS-011`, `SEC-001`, `SEC-015`

현재 공개 설치 기준은 **Ubuntu 24.04 + systemd + Nginx**입니다. 기존 운영 사이트에는 먼저 `observe` shadow로 설치하고, 공개 요청 편입은 origin·edge·관리자 HTTPS를 모두 검증한 뒤 수행합니다. 운영 서버에는 Rust·Bun·Python package를 설치하지 않고 외부 Linux builder 또는 CI가 만든 checksum 포함 release bundle만 배포합니다.

현재는 v0.1.0-alpha이므로 범용 `curl | sh` 설치기를 제공하지 않습니다. 저장소의 자동 배포 하네스는 `g7devops`와 `gnuboard5` 파일럿 환경에 묶여 있습니다. 다른 서버에서는 아래 수동 절차로 후보를 준비하고 staging에서 전환·복구를 먼저 검증해야 합니다.

### 1. 설치 전 확인

- 기존 Nginx 설정, 인증서, SSH port와 UFW 상태를 백업·기록합니다.
- 애플리케이션 Host, 관리자 전용 Host, origin port와 실제 PHP-FPM·upstream 경로를 확정합니다.
- `7727`, `18080`, `18081`은 loopback 전용이며 UFW에 공개하지 않습니다.
- 첫 설치는 `detection.mode = "observe"`, `cloudflare.enabled = false`, CSP report-only로 시작합니다.
- VPSGuard는 기존 Nginx·인증서·사이트 파일을 first-install snapshot으로 복원하지 않습니다. 웹서버 설정은 별도 백업과 bypass 후보를 준비합니다.

서버 사전 점검 예시입니다.

```bash
uname -m
grep -E '^(ID|VERSION_ID)=' /etc/os-release
sudo -n true
sudo ss -ltnp
sudo nginx -t
sudo systemctl is-active nginx.service
```

필수 운영 package를 설치합니다. Nginx가 없는 새 서버라면 `nginx`를 함께 설치합니다.

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl ufw
```

### 2. 검증된 release bundle 생성·전송

대상 CPU와 같은 신뢰한 Ubuntu Linux builder에서 Rust `1.96.0`, Bun `1.3.10`과
PAM·Clang 개발 package를 준비한 뒤 빌드합니다.

```bash
git clone https://github.com/jiwonpapa/vpsguard.git
cd vpsguard

TARGET=x86_64-unknown-linux-gnu # ARM64는 aarch64-unknown-linux-gnu
cargo xtask release "$TARGET"

VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)"
BUNDLE="target/release-bundle/$TARGET/vpsguard-$VERSION"
(cd "$BUNDLE" && sha256sum --check SHA256SUMS)
rsync -a "$BUNDLE/" operator@example.com:/tmp/vpsguard-bundle/
```

태그 빌드는 GitHub Actions의 `Release artifacts` workflow에서도 x86_64·aarch64
네이티브 Ubuntu runner로 bundle, checksum, SBOM과 provenance를 생성합니다. 현재
GitHub Release 자동 첨부는 release gate이므로 Actions artifact 또는 직접 검증한
bundle을 사용합니다.

### 3. 서버 계정·설정·systemd 설치

이하 명령은 대상 서버에서 실행합니다. 먼저 bundle checksum과 target을 확인하고, 설치 전 VPSGuard 소유 경로를 snapshot합니다. 출력된 `snapshot=/var/backups/vps-guard/deployments/...` 경로를 반드시 보관합니다.

```bash
BUNDLE=/tmp/vpsguard-bundle
cd "$BUNDLE"
sha256sum --check SHA256SUMS
cat BUILD-INFO.txt
sudo "$BUNDLE/bin/vps-guard" ops deployment-state snapshot
```

전용 서비스 계정과 관리자 group을 한 번만 생성합니다. `<관리자계정>`에는 실제로 로그인할 기존 non-root Linux 계정을 넣고, group 반영을 위해 새 SSH session으로 다시 접속합니다.

```bash
getent passwd vps-guard >/dev/null || \
  sudo useradd --system --home-dir /var/lib/vps-guard --shell /usr/sbin/nologin vps-guard
getent group vpsguard-admin >/dev/null || sudo groupadd --system vpsguard-admin
sudo usermod -aG vpsguard-admin <관리자계정>
```

기본 파일을 설치합니다.

```bash
sudo install -d -m 0750 -o root -g vps-guard /etc/vps-guard
sudo install -d -m 0700 -o root -g root /etc/vps-guard/secrets /var/lib/vps-guard/pam
sudo install -d -m 0750 -o vps-guard -g vps-guard /var/lib/vps-guard /var/lib/vps-guard/events

sudo install -m 0755 "$BUNDLE"/bin/vps-guard{,-control,-privileged,-edge} /usr/local/bin/
sudo install -m 0644 "$BUNDLE"/systemd/*.service "$BUNDLE"/systemd/*.socket /etc/systemd/system/
sudo install -m 0644 "$BUNDLE/tmpfiles/vps-guard.conf" /usr/lib/tmpfiles.d/vps-guard.conf
sudo install -m 0644 "$BUNDLE/pam/vps-guard" /etc/pam.d/vps-guard
sudo install -m 0640 -o root -g vps-guard "$BUNDLE/vps-guard.example.toml" /etc/vps-guard/config.toml
sudo install -m 0644 "$BUNDLE/ownership-manifest.txt" /var/lib/vps-guard/ownership-manifest.txt
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/vps-guard.conf
```

`sudoedit /etc/vps-guard/config.toml`로 최소 다음 값을 실제 서버에 맞춥니다.

| 설정 | Nginx TLS 유지형 첫 설치 값 |
|---|---|
| `edge.http_bind` | `127.0.0.1:18080` |
| `edge.allowed_hosts` | 실제 애플리케이션 Host만 등록 |
| `edge.canonical_host` | 대표 애플리케이션 Host |
| `edge.trusted_proxy_cidrs` | `["127.0.0.1/32", "::1/128"]` |
| `origin.address` | `127.0.0.1:18081` |
| `ui.public_host` | 인증서가 있는 별도 관리자 Host |
| `ui.public_port` | `443` |
| `ui.tls_termination` | `trusted_external` |
| `ui.auth_provider` | Ubuntu 기본값 `pam` |
| `firewall.mode` | 첫 검증은 `disabled`, UFW 준비 후 `standalone_ufw` |
| `detection.profile` | `php`, `gnuboard5`, `gnuboard7`, `wordpress` 중 선택 |
| `detection.mode` | 첫 설치는 `observe` |
| `cloudflare.enabled` | 실제 test zone 검증 전 `false` |

관리 UI와 UFW를 사용할 설정 예시는 다음과 같습니다.

```toml
[ui]
bind = "127.0.0.1:7727"
public_host = "guard.example.com"
public_port = 443
tls_termination = "trusted_external"
auth_provider = "pam"
pam_service = "vps-guard"
pam_allowed_group = "vpsguard-admin"
admin_socket = "/run/vps-guard/admin.sock"
privileged_socket = "/run/vps-guard-privileged/control.sock"
login_rate_limit_rpm = 10
language = "ko"

[firewall]
mode = "disabled" # SSH·HTTPS 확인 뒤 standalone_ufw로 변경
ssh_port = 22
```

설정은 service 시작 전에 검증합니다.

```bash
sudo /usr/local/bin/vps-guard check-config --config /etc/vps-guard/config.toml
sudo systemctl daemon-reload
```

### 4. Nginx 웹서버 설정

안전한 첫 편입 topology는 다음과 같습니다. Nginx가 기존 TLS·Certbot을 유지하므로 즉시 bypass하기 쉽고, 애플리케이션 부하는 VPSGuard가 origin 전에 차단합니다.

```text
Internet -> Nginx public TLS :443 -> VPSGuard 127.0.0.1:18080
                                   -> Nginx origin 127.0.0.1:18081 -> Application
Admin    -> guard.example.com:443 -> Control 127.0.0.1:7727
```

먼저 기존 public virtual host는 그대로 둔 채, 기존 애플리케이션 처리 block을 복사해 loopback origin을 추가합니다. PHP 서비스명·root·location은 현재 사이트 값을 유지해야 합니다.

```bash
sudo cp --preserve=all /etc/nginx/sites-available/example.conf \
  /etc/nginx/sites-available/example.conf.pre-vpsguard
```

이 사본과 기존 direct application block이 즉시 사용할 bypass 후보입니다. 실제 site 파일명으로 바꾸고, 후보도 `nginx -t`를 통과하는지 확인합니다.

```nginx
# /etc/nginx/conf.d/vpsguard-map.conf - http {} context
map $http_upgrade $vpsguard_connection_upgrade {
    default upgrade;
    ''      close;
}

map $http_x_forwarded_proto $vpsguard_fastcgi_https {
    default off;
    https   on;
}

server {
    listen 127.0.0.1:18081;
    server_name example.com www.example.com;
    root /var/www/example/public;

    set_real_ip_from 127.0.0.1;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;

    # 기존 static, FastCGI, WebSocket, upload location을 이곳에 유지합니다.
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_param HTTPS $vpsguard_fastcgi_https;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }
}
```

origin을 먼저 검사·reload하고 직접 응답을 확인합니다.

```bash
sudo nginx -t
sudo systemctl reload nginx.service
curl --fail --header 'Host: example.com' http://127.0.0.1:18081/
```

이제 VPSGuard를 loopback shadow로 시작합니다.

```bash
sudo systemctl enable --now vps-guard-privileged.socket vps-guard-privileged.service
sudo systemctl enable --now vps-guard-control.service vps-guard-edge.service

curl --fail http://127.0.0.1:7727/health/live
curl --fail --header 'Host: example.com' http://127.0.0.1:18080/health/live
curl --fail --header 'Host: example.com' http://127.0.0.1:18080/
```

세 probe가 통과하면 기존 public HTTPS virtual host의 애플리케이션 `location /`을 다음 proxy로 교체합니다. 외부 요청의 `X-Forwarded-*`를 이어 붙이지 않고 실제 Nginx peer 값으로 덮어써야 합니다.

```nginx
location / {
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header Forwarded "";
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $vpsguard_connection_upgrade;
    proxy_request_buffering off;
    proxy_read_timeout 65s;
    proxy_pass http://127.0.0.1:18080;
}
```

관리자 Host는 같은 공개 Nginx에서 loopback Control로만 전달합니다. 먼저 `guard.example.com`의 A·AAAA DNS가 서버를 가리키는지 확인하고 기존 Certbot webroot로 인증서를 발급합니다. VPSGuard는 이 인증서의 발급·renewal 설정을 소유하지 않습니다.

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name guard.example.com;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/certbot;
        try_files $uri =404;
    }

    location / {
        return 301 https://guard.example.com$request_uri;
    }
}
```

```bash
sudo install -d -m 0755 /var/www/certbot
sudo nginx -t
sudo systemctl reload nginx.service
sudo certbot certonly --webroot --webroot-path /var/www/certbot \
  --domain guard.example.com
sudo certbot renew --dry-run
```

Certbot이 이미 관리하는 SAN 인증서에 관리자 Host가 포함돼 있다면 별도 발급 대신 해당 lineage를 사용합니다. 인증서가 준비되면 HTTPS virtual host를 추가합니다.

```nginx
server {
    listen 443 ssl http2;
    server_name guard.example.com;

    ssl_certificate /etc/letsencrypt/live/guard.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/guard.example.com/privkey.pem;

    location / {
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header Forwarded "";
        proxy_buffering off;
        proxy_read_timeout 65s;
        proxy_pass http://127.0.0.1:7727;
    }
}
```

최종 전환은 configtest 뒤 reload하고 공개 응답 header를 확인합니다.

```bash
sudo nginx -t
sudo systemctl reload nginx.service
curl --fail --silent --show-error --output /dev/null https://example.com/
curl --fail --silent --show-error --output /dev/null https://guard.example.com/
curl --fail --silent --show-error --dump-header - --output /dev/null \
  https://example.com/ | grep -i '^x-vps-guard: guard-edge'
```

공개 응답에는 `X-VPS-Guard: guard-edge`가 있어야 하며 `ss -ltnp`에서 `7727`, `18080`, `18081`은 loopback으로만 보여야 합니다. VPSGuard가 직접 public 80/443과 TLS를 소유하는 최종 topology는 인증서 systemd credential, Certbot deploy hook과 5초 ingress transaction 검증이 필요합니다. 현재 범용 서버에서는 위 Nginx TLS 유지형을 먼저 사용하고, 직접 TLS는 [`g7devops` 검증 절차](docs/OPERATIONS.md#g7devops-직접-tls-트래픽-편입)를 기준으로 별도 인증합니다.

### 5. 관리자 로그인과 UFW

PAM 관리자는 installer나 테스트가 TOTP를 미리 만들지 않습니다. 먼저 실제 Linux 관리자 계정을 allowlist group에 넣고 Control·privileged helper를 시작합니다.

```bash
sudo usermod -aG vpsguard-admin <관리자계정>
sudo systemctl restart vps-guard-privileged.service vps-guard-control.service
sudo vps-guard issue-login-code --ttl-seconds 600
```

`https://guard.example.com`을 열고 단회 코드, Linux 계정명과 서버 비밀번호를 입력합니다. 화면의 QR을 실제 인증 앱으로 스캔하고 현재 6자리 코드를 확인해야 등록이 완료됩니다. 서버 비밀번호는 저장하지 않으며 TOTP seed는 `/var/lib/vps-guard/pam`의 root-only key로 AEAD 봉인됩니다. 복구 코드는 최초 등록 직후 한 번만 표시되고 keyed hash만 저장됩니다.

등록 후에는 Linux 계정명, 서버 비밀번호와 직접 등록한 TOTP 또는 일회용 복구 코드로 로그인합니다. root·system·잠김·만료 계정과 `vpsguard-admin` group 밖의 계정은 거부됩니다. 사용자 home의 `.google_authenticator`나 테스트 seed를 VPSGuard credential로 복사하면 안 됩니다.

UFW는 VPSGuard가 자동 활성화하지 않습니다. 먼저 현재 SSH port, HTTP와 HTTPS를 운영자 규칙으로 허용하고 새 SSH session과 관리자 HTTPS를 확인한 뒤 활성화합니다.

```bash
SSH_PORT=22 # 실제 sshd port로 변경
sudo ufw allow "$SSH_PORT/tcp"
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw status verbose
sudo ufw enable
```

그 뒤 설정의 `firewall.mode`를 `standalone_ufw`로 바꾸고 실제 `ssh_port`를 기록한 다음 검증·재시작합니다. JW-agent가 UFW를 소유하면 `jw_agent_delegated`, host 방화벽 기능을 쓰지 않으면 `disabled`를 사용합니다.

```bash
sudo vps-guard check-config --config /etc/vps-guard/config.toml
sudo systemctl restart vps-guard-privileged.service vps-guard-control.service
```

### 6. Apache 설치 범위

Apache는 현재 **범용 공개 지원이 아니라 `gnuboard5` 격리 VM 파일럿**입니다. 검증 topology는 `Apache public TLS -> VPSGuard loopback -> Apache loopback origin`이며, 고정 Host·문서 root·인증서 경로가 포함된 [`configs/apache`](configs/apache) 파일을 다른 서버에 그대로 복사하면 안 됩니다.

Apache 서버는 `proxy`, `proxy_http`, `headers`, `remoteip`, `ssl` module과 별도 origin vhost가 필요합니다. ModSecurity·OWASP CRS도 자동 기본값이 아니며 `off -> detection -> app별 exclusion -> tuned_enforce` 순서로 정상 로그인·글쓰기·업로드 오탐을 검증합니다. 현재 파일럿의 exact 전환·bypass 명령은 [Apache 운영 절차](docs/OPERATIONS.md#단독-설치-관리자ufwwaf)와 [검증 증거](specs/product/evidence/gnuboard5-apache-vm-20260722.md)를 따릅니다.

### 7. 설치 확인·복구

```bash
sudo systemctl --no-pager --full status \
  vps-guard-privileged.socket vps-guard-privileged.service \
  vps-guard-control.service vps-guard-edge.service
sudo journalctl -u vps-guard-control -u vps-guard-edge --since '-10 minutes'
sudo ss -ltnp
```

문제가 생기면 먼저 준비한 Nginx direct bypass 설정으로 공개 요청을 원래 웹서버에 돌립니다. 그 뒤 설치 전 snapshot을 검증·복원합니다.

```bash
sudo vps-guard ops deployment-state verify \
  /var/backups/vps-guard/deployments/deploy-<timestamp>-<id>
sudo env VPS_GUARD_RESTORE_CONFIRM=restore-deployment-snapshot \
  vps-guard ops deployment-state restore \
  /var/backups/vps-guard/deployments/deploy-<timestamp>-<id>
```

업데이트·제거·Cloudflare·직접 TLS 전환은 [운영 하네스](docs/OPERATIONS.md)에서 plan, snapshot, apply, read-back, rollback 순서로 수행합니다.

## 로컬 검증

```bash
bash scripts/check.sh
bash scripts/dev-check.sh guard-edge
bash scripts/dev-check.sh python
bash scripts/dev-check.sh web
bash scripts/harness-language-gate.sh
bash scripts/build-storage.sh
bash scripts/coverage-gate.sh
bash scripts/integration-gate.sh
bash scripts/ops-harness.sh
bash scripts/load-regression-gate.sh
cargo xtask coverage
cargo xtask web
```

`build-storage.sh`는 기본적으로 정리 계획만 표시합니다. `--clean`은 명시적으로 요청할 때만 재생성 가능한 Cargo cache를 전부 제거합니다. 주요 개발 gate의 `--auto`는 `tmp`·임시 다운로드·timing 같은 재사용 가치 없는 항목만 회수하며 debug·release·coverage·rustdoc cache는 빌드 속도를 위해 삭제하지 않습니다. 활성 cache가 기본 4GiB 경고 기준을 넘어도 상태만 보고합니다. 두 정책 모두 `target/release-bundle`, `target/evidence`와 알 수 없는 파일을 보존합니다.

`dev-check.sh`는 명시한 Rust crate, Python 하네스 또는 Web만 빠르게 검사합니다. merge 판단은 계속 `check.sh` 전체 gate를 사용하며 범위 검증 결과로 대체하지 않습니다. CI는 PR의 모든 비-merge 커밋과 PR 본문에 요구사항 ID가 있는지도 검사합니다.

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
- 실제 여러 source의 high-cardinality 2GB soak와 authenticated upload WAF 오탐 replay
- multi-architecture artifact 실행 smoke

## 라이선스

현재 저장소는 `publish = false`와 all-rights-reserved 정책을 사용합니다. 공개 저장소라는 사실만으로 코드 사용·재배포 권한을 부여하지 않으며, Community/Pro 라이선스는 파일럿 공개 전에 별도로 확정합니다.
