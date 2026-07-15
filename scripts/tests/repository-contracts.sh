#!/usr/bin/env bash
set -euo pipefail

# OPS-007, NFR-005, NFR-007: 저장소 게이트는 CI 기본 이미지에서 재현되고 미수집 증거를
# 릴리스 완료로 오인하지 않아야 합니다.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

bash scripts/requirements-gate.sh
bash scripts/docs-gate.sh

release_output="$(mktemp)"
trap 'rm -f "${release_output}"' EXIT
if bash scripts/requirements-gate.sh --release >"${release_output}" 2>&1; then
  echo "release requirement gate unexpectedly passed without VPS evidence" >&2
  exit 1
fi
grep -Fq "release gate blocked" "${release_output}"

if grep -En '\brg([[:space:]]|$)' scripts/*.sh packaging/certbot/*; then
  echo "runtime harness must not depend on ripgrep being preinstalled" >&2
  exit 1
fi

grep -Fq 'pre-MVP' README.md
grep -Fq 'pre-MVP' specs/product/11-mvp-implementation-status.md
grep -Fq 'CODE_ONLY' specs/product/verification-status.tsv

if grep -Fq 'vpsguard-0.1.0' .github/workflows/release.yml; then
  echo "release workflow must derive the workspace version" >&2
  exit 1
fi
grep -Fq 'SHA256SUMS' scripts/deploy-g7devops.sh
grep -Fq 'VPS_GUARD_EDGE_HEALTH_URL' scripts/update-release.sh
grep -Fq 'VPS_GUARD_BYPASS_VERIFIED' scripts/uninstall.sh

# OPS-007, NFR-005: CI evidence must be generated at the exact paths uploaded by
# the workflow, and repository linters must remain available on a clean runner.
# shellcheck disable=SC2016 # GitHub workflow의 literal shell expression을 검사합니다.
grep -Fq 'echo "$(go env GOPATH)/bin" >> "${GITHUB_PATH}"' .github/workflows/ci.yml
grep -Fq 'apt-get install --yes shellcheck' .github/workflows/ci.yml
grep -Fq '[profile.ci.junit]' .config/nextest.toml
grep -Fq 'path = "junit.xml"' .config/nextest.toml
if grep -Fq 'path = "target/nextest/ci/junit.xml"' .config/nextest.toml; then
  echo "nextest JUnit path must be relative to the profile output directory" >&2
  exit 1
fi
grep -Fq 'outputFolder: "playwright-report"' web/playwright.config.ts

# NFR-007: workspace lint 상속, module rustdoc와 rustdoc warning 거부를
# 로컬 check와 CI 모두에서 제거할 수 없게 고정합니다.
grep -Eq '^[[:space:]]*missing_docs[[:space:]]*=[[:space:]]*"deny"[[:space:]]*$' Cargo.toml
grep -Fq 'bash scripts/docs-gate.sh' scripts/check.sh
grep -Fq 'RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps --document-private-items' scripts/check.sh
grep -Fq 'RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps --document-private-items' .github/workflows/ci.yml

# NFR-008, TLS-006, OBS-011, SEC-004: 외부 protocol client 우선 원칙과
# 최소 권한 provider·핵심 service 관측 경계를 문서에서 제거하지 못하게 합니다.
grep -Fq '표준 프로토콜·암호·wire format을 다루는 기능은 유지보수되는 검증된 crate 또는 외부 client를 우선' DEVELOPMENT_CONSTITUTION.md
grep -Fq 'HTTP status 수집' docs/adr/0002-edge-integrations-and-service-observability.md
grep -Fq 'VPSGuard의 기본 생성 경로는 Cloudflare User API Token입니다.' docs/OPERATIONS.md
grep -Fq 'Account DNS Settings`, `DNS Firewall`, `DNS View`는' docs/OPERATIONS.md
grep -Fq 'Account API Tokens Read/Write' docs/OPERATIONS.md
grep -Fq '전체 systemd unit·process 목록' specs/product/09-monitoring-web-ui.md
grep -Fq 'inspection = "profiled"' configs/vps-guard.example.toml
grep -Fq 'inspection = "protocol_only"' configs/vps-guard.protocol-only.integration.toml
grep -Fq 'protocol_only_tls=pass' scripts/integration-gate.sh
grep -Fq 'csp_mode = "report_only"' configs/vps-guard.example.toml
grep -Fq 'auth_rate_limit_rpm = 10' configs/vps-guard.example.toml
grep -Fq 'rejects_method(&context.method)' crates/guard-edge/src/proxy.rs
grep -Fq 'VPSGUARD_INTEGRATION_BODY_SECRET' scripts/integration-gate.sh
grep -Fq '계정·session·device별 한도' docs/APP_SECURITY.md

# SEC-001, SEC-004, ACT-006: Cloudflare 비밀값은 config/env가 아닌 root-only
# 원본과 systemd credential로 전달하고, 변경 대상은 명시적 record ID로 고정합니다.
grep -Fq 'LoadCredential=cloudflare-token:/etc/vps-guard/secrets/cloudflare-token' packaging/systemd/vps-guard-control-cloudflare-credential.conf
grep -Fq 'LoadCredential=mysql-monitor-url:/etc/vps-guard/secrets/mysql-monitor-url' packaging/systemd/vps-guard-control-service-credentials.conf.example
grep -Fq 'LoadCredential=redis-monitor-url:/etc/vps-guard/secrets/redis-monitor-url' packaging/systemd/vps-guard-control-service-credentials.conf.example
grep -Eq '^d /etc/vps-guard/secrets 0700 root root -$' packaging/tmpfiles/vps-guard.conf
grep -Fq 'token: SecretString' crates/guard-provider/src/cloudflare.rs
grep -Fq 'OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW' crates/guard-system/src/secret.rs
grep -Fq 'GET /zones/{zone_id}/dns_records/{record_id}' docs/OPERATIONS.md
if grep -Rq --exclude-dir=target --exclude='repository-contracts.sh' 'record_names' configs crates docs packaging specs; then
  echo "deprecated name-only Cloudflare allowlist must not return" >&2
  exit 1
fi

# TLS-001, TLS-006, SEC-001: startup은 검증만 하고 private key는 edge
# credential로만 전달하며 control에는 공개 certificate만 전달합니다.
grep -Fq 'management = "auto"' configs/vps-guard.example.toml
grep -Fq 'LoadCredential=tls-cert.pem:@CERT_FILE@' packaging/systemd/vps-guard-control-tls-certificate.conf.example
if grep -Fq 'tls-key.pem' packaging/systemd/vps-guard-control-tls-certificate.conf.example; then
  echo "control TLS credential must not receive the private key" >&2
  exit 1
fi
grep -Fq 'LoadCredential=tls-key.pem:@KEY_FILE@' packaging/systemd/vps-guard-edge-tls-credentials.conf.example
grep -Fq 'build_certbot_assisted_plan' crates/guard-control/src/api.rs

echo "repository contract tests: PASS"
