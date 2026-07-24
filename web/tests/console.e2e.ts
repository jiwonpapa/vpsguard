import { expect, test, type Page } from "@playwright/test";

// UI-002, UI-004: 브라우저 전용 시나리오는 Bun unit discovery와 분리합니다.

const status = {
  schema_version: 1,
  inspection: "profiled",
  security: {
    app_layer_active: true,
    baseline_response_headers: true,
    strip_origin_headers: true,
    csp_mode: "report_only",
    waf_mode: "tuned_enforce",
    waf_adapter: "mod_security_owasp_crs",
    hsts_max_age_seconds: 0,
    auth_rate_limit_rpm: null,
  },
  mode: "LOCAL_GUARD",
  manual_hold: false,
  policy_version: 7,
  last_transition_at: "2026-07-14T12:00:00Z",
  reasons: ["고비용 경로와 upstream 압력이 연속 관측됐습니다."],
  edge: "live",
  origin: "live",
  agent: "live",
  provider: "unavailable",
  provider_drain_deadline_unix_seconds: null,
  tls: "valid",
  tls_management: {
    health: "valid",
    ownership: "external_managed",
    renewal: "healthy",
    manager: "certbot.timer",
    certificate_count: 1,
    earliest_expiry: "2026-09-01T00:00:00Z",
    error_code: null,
    next_action: "현재 인증서 관리 설정을 유지하십시오.",
  },
  notification: {
    enabled: true,
    configured: true,
    queue_depth: 0,
    queue_capacity: 256,
    queue_dropped: 0,
    delivered: 12,
    failed: 0,
    pending: 0,
    last_success_at: "2026-07-14T12:00:00Z",
    last_failure_at: null,
    last_error_code: null,
    storage_available: true,
  },
};

async function mockApi(page: Page) {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/session" && route.request().method() === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          csrf_token: "csrf-fixture",
          expires_in_seconds: 3600,
          actor: "guard.admin",
          authentication_method: "password_totp",
        }),
      });
      return;
    }
    if (path === "/api/v1/auth/status") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          auth_provider: "local",
          setup_required: false,
          enrollment_enabled: true,
          password_login_enabled: true,
          totp_required: true,
          break_glass_available: true,
        }),
      });
      return;
    }
    if (path.startsWith("/api/v1/correlations/")) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          correlation_id: path.split("/").at(-1),
          request: {
            request_id: "guard-0123456789abcdef0123456789abcdef-0000000000000009",
            occurred_at_unix_ms: 1784000000000,
            method: "POST",
            route_class: "strict",
            normalized_route: "/api/login",
            route_cost: 5,
            status: 429,
            latency_micros: 1500,
            request_body_bytes: 64,
            response_body_bytes: 128,
            upstream_connection_reused: true,
            decision: "throttle",
            policy_version: 3,
          },
          events: [],
          audit_action: null,
        }),
      });
      return;
    }
    if (
      path === "/api/v1/settings/protection/plan"
      && route.request().method() === "POST"
    ) {
      const settings = route.request().postDataJSON().settings;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          settings,
          current_fingerprint: "protection-current",
          plan_hash: "protection-plan",
          current_policy_version: 7,
          next_policy_version: 8,
          changes: [{
            field: "local_strict_requests_per_minute",
            before: 30,
            after: settings.local_strict_requests_per_minute,
          }],
        }),
      });
      return;
    }
    if (
      path === "/api/v1/settings/protection/apply"
      && route.request().method() === "POST"
    ) {
      const idempotencyKey = route.request().headers()["idempotency-key"];
      await route.fulfill({
        status: idempotencyKey ? 200 : 400,
        contentType: "application/json",
        body: JSON.stringify(idempotencyKey ? {
          applied: true,
          operation_id: idempotencyKey,
          settings: route.request().postDataJSON().settings,
          policy_version: 8,
          fingerprint: "protection-applied",
          edge_observed_policy_version: 7,
          edge_readback: "pending",
        } : {
          error: { code: "IDEMPOTENCY_KEY_REQUIRED" },
        }),
      });
      return;
    }
    const data: Record<string, unknown> = {
      "/api/v1/status": status,
      "/api/v1/traffic/summary": {
        window_seconds: 900,
        window_started_at_unix_ms: 1783999100000,
        window_ended_at_unix_ms: 1784000000000,
        requests_per_second_milli: 1200,
        requests: 1200,
        status_2xx: 1100,
        status_3xx: 20,
        status_4xx: 70,
        status_5xx: 10,
        throttled: 30,
        denied: 4,
        challenged: 3,
        latency_p95_micros: 12500,
        unique_clients: 42,
        dropped_clients: 0,
        request_body_bytes: 64000,
        response_body_bytes: 819200,
        upstream_connections: 400,
        upstream_connections_reused: 320,
        in_flight_requests: 7,
        bot_requests: 18,
        bot_denied: 4,
        edge_telemetry_emitted: 1200,
        edge_telemetry_dropped: 0,
        edge_telemetry_reconnected: 1,
      },
      "/api/v1/resources": {
        state: "live",
        os: {
          cpu_usage_percent: 37,
          logical_cpu_count: 2,
          load_1m: 0.7,
          memory_total_bytes: 2147483648,
          memory_available_bytes: 1073741824,
          swap_total_bytes: 0,
          swap_free_bytes: 0,
          uptime_seconds: 7200,
        },
        services: [{
          name: "php_fpm",
          state: "delayed",
          last_success_at: "2026-07-14T12:00:00Z",
          error_code: "TIMEOUT",
          unit: "php8.3-fpm.service",
          collected_at_unix_ms: 1784000000000,
          resource_state: "live",
          semantic_state: "error",
          resource_error_code: null,
          semantic_error_code: "TIMEOUT",
          resources: {
            collected_at_unix_ms: 1784000000000,
            cpu_usage_usec: 500000,
            cpu_user_usec: 400000,
            cpu_system_usec: 100000,
            cpu_nr_throttled: 0,
            cpu_throttled_usec: 0,
            cpu_usage_milli_percent: 12500,
            memory_current_bytes: 134217728,
            memory_peak_bytes: 167772160,
            memory_high_events: 0,
            memory_max_events: 0,
            oom_events: 0,
            oom_kill_events: 0,
            io_read_bytes: 1048576,
            io_write_bytes: 2097152,
            process_count: 4,
            task_count: 7,
          },
          semantic: {
            kind: "php_fpm",
            accepted_connections: 100,
            listen_queue: 2,
            max_listen_queue: 4,
            listen_queue_length: 128,
            idle_processes: 3,
            active_processes: 2,
            total_processes: 5,
            max_active_processes: 4,
            max_children_reached: 1,
            slow_requests: 2,
          },
        }],
        storage: {
          condition: "healthy",
          queue_depth: 0,
          queue_capacity: 4096,
          queue_dropped_samples: 0,
          write_dropped_samples: 0,
          persisted_samples: 1200,
          persisted_batches: 12,
          write_failures: 0,
          database_bytes: 1048576,
          database_used_bytes: 786432,
          reclaimable_bytes: 262144,
          wal_bytes: 65536,
          disk_available_bytes: 10737418240,
          max_database_bytes: 536870912,
          min_disk_free_bytes: 268435456,
          database_budget_exceeded: false,
          disk_space_low: false,
          last_batch_at_unix_ms: 1784000000000,
          last_rollup_at_unix_ms: 1784000000000,
          last_retention_at_unix_ms: 1783999900000,
          last_write_error_at_unix_ms: null,
          retention_deleted_rows: 37,
          retention_anonymized_rows: 12,
          retention_backlog: false,
        },
      },
      "/api/v1/clients": { items: [{ client_ip: "203.0.113.8", requests: 77, throttled: 2, denied: 0, request_body_bytes: 2048, response_body_bytes: 16384, last_seen_unix_ms: 1784000000000 }] },
      "/api/v1/routes": { items: [] },
      "/api/v1/bots": { items: [{
        bot_class: "spoofed_crawler",
        bot_provider: "google",
        bot_verified: false,
        bot_reason: "official_network_mismatch",
        user_agent_family: "googlebot",
        requests: 8,
        denied: 8,
        throttled: 0,
        response_body_bytes: 1024,
      }] },
      "/api/v1/incidents": { items: [] },
      "/api/v1/firewall": {
        mode: "standalone_ufw",
        backend: "ufw",
        mutable: true,
        snapshot: {
          active: true,
          fingerprint: "fixture-fingerprint",
          owned_rules: [],
          foreign_rules: Array.from({ length: 8 }, (_, index) => `foreign-${index}`),
        },
      },
      "/api/v1/settings/protection": {
        schema_version: 1,
        settings: {
          watch_strict_requests_per_minute: 120,
          local_strict_requests_per_minute: 30,
          local_upload_requests_per_minute: 15,
          emergency_strict_requests_per_minute: 10,
          emergency_upload_requests_per_minute: 5,
        },
        policy_version: 7,
        fingerprint: "protection-current",
        edge_observed_policy_version: 7,
        edge_readback: "observed",
        enforcement_active: true,
      },
      "/api/v1/traffic/series": {
        items: [
          {
            bucket_unix_ms: 1784000000000,
            requests: 12,
            errors: 1,
            throttled: 2,
            latency_avg_micros: 900,
            request_body_bytes: 128,
            response_body_bytes: 4096,
          },
        ],
      },
    };
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(data[path] ?? {}),
    });
  });
}

async function mockAnonymousSession(page: Page) {
  await page.route("**/api/v1/session", async (route) => {
    if (route.request().method() === "GET") {
      await route.fulfill({
        status: 401,
        contentType: "application/json",
        body: JSON.stringify({ error: { code: "SESSION_AUTH_REQUIRED" } }),
      });
      return;
    }
    await route.fallback();
  });
}

test.beforeEach(async ({ page }) => {
  await mockApi(page);
});

test("renders protection posture and client drill-down", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "현재 방어 상태" })).toBeVisible();
  await expect(page.getByText("로컬 방어", { exact: true })).toBeVisible();
  await expect(page.getByText(/앱 보안 활성 · CSP report_only/)).toBeVisible();
  if ((page.viewportSize()?.width ?? 1280) < 768) {
    await page.getByRole("button", { name: "주요 메뉴 열기" }).click();
    await page.getByRole("dialog").getByRole("link", { name: "클라이언트" }).click();
  } else {
    await page.getByRole("link", { name: "클라이언트" }).click();
  }
  await expect(page.getByText("203.0.113.8")).toBeVisible();
  await page.getByLabel("Client 검색").fill("198.51");
  await expect(page.getByText("아직 수집된 항목이 없습니다.")).toBeVisible();
  await page.getByLabel("Client 검색").fill("203.0");
  await expect(page.getByText("18.0 KiB")).toBeVisible();
});

test("organizes the overview as a sectioned operations console", async ({ page }) => {
  await page.goto("/");

  if ((page.viewportSize()?.width ?? 1280) < 768) {
    await page.getByRole("button", { name: "주요 메뉴 열기" }).click();
    const mobileMenu = page.getByRole("dialog");
    await expect(mobileMenu.getByText("모니터링", { exact: true })).toBeVisible();
    await expect(mobileMenu.getByText("운영", { exact: true })).toBeVisible();
    await page.keyboard.press("Escape");
  } else {
    await expect(page.getByText("모니터링", { exact: true })).toBeVisible();
    await expect(page.getByText("운영", { exact: true })).toBeVisible();
  }
  await expect(page.getByRole("region", { name: "현재 보호 상태" })).toBeVisible();
  await expect(page.getByRole("region", { name: "실시간 트래픽" })).toBeVisible();
  await expect(page.getByRole("region", { name: "서버 압력" })).toBeVisible();
  await expect(page.getByRole("region", { name: "외부 알림" })).toBeVisible();
  await expect(page.getByText("delivered 12", { exact: true })).toBeVisible();
  await expect(page.getByText("CPU 사용", { exact: true })).toBeVisible();
  await expect(page.getByText("37%", { exact: true })).toBeVisible();
  await expect(page.getByText("운영 경계", { exact: true })).toHaveCount(0);
});

test("explains that Cloudflare recovery requires explicit approval", async ({ page }) => {
  await page.route("**/api/v1/status", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ ...status, mode: "RECOVERY_READY", provider: "complete" }),
    });
  });
  await page.goto("/");
  await expect(page.getByText("복구 승인 대기", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "보호 해제 승인" })).toBeVisible();
});

test("renders bounded storage health and retention state", async ({ page }) => {
  await page.goto("/resources");
  await expect(page.getByRole("heading", { name: "서버 자원과 서비스" })).toBeVisible();
  await expect(page.getByRole("region", { name: "저장 계층 상태" })).toContainText("healthy");
  await expect(page.getByText("1.1 MiB")).toBeVisible();
  await expect(page.getByText("10.0 GiB")).toBeVisible();
  await expect(page.getByRole("region", { name: "핵심 서비스 상태" })).toContainText("php8.3-fpm.service");
  await expect(page.getByRole("article", { name: "php_fpm 상태" })).toContainText("semantic error");
  await expect(page.getByRole("article", { name: "php_fpm 상태" })).toContainText("128.0 MiB");
  await expect(page.getByRole("article", { name: "php_fpm 상태" })).toContainText("Queue");
});

test("finds a request by correlation ID without a terminal", async ({ page }) => {
  await page.goto("/incidents");
  await page.getByLabel("상관관계 ID").fill(
    "guard-0123456789abcdef0123456789abcdef-0000000000000009",
  );
  await page.getByRole("button", { name: "추적" }).click();
  await expect(page.getByRole("region", { name: "상관관계 조회 결과" })).toContainText(
    "POST /api/login",
  );
  await expect(page.getByRole("region", { name: "상관관계 조회 결과" })).toContainText("429");
});

test("switches between live and persisted traffic resolutions", async ({ page }) => {
  await page.goto("/traffic");
  await expect(page.getByRole("img", { name: "1m 요청 추이" })).toBeVisible();
  await expect(page.getByText("spoofed crawler", { exact: true })).toBeVisible();
  await page.getByLabel("시계열 해상도").click();
  await page.getByRole("option", { name: "1초 live" }).click();
  await expect(page.getByRole("img", { name: "1s 요청 추이" })).toBeVisible();
});

test("renders typed standalone UFW controls without exposing raw commands", async ({ page }) => {
  await page.goto("/firewall");
  await expect(page.getByRole("heading", { name: "UFW 방화벽" })).toBeVisible();
  await expect(page.getByText("VPSGuard 소유", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Rule ID")).toHaveValue("public_https");
  await expect(page.getByLabel("Source IP/CIDR (선택)")).toBeVisible();
  await expect(page.getByText("foreign rules preserved 8")).toBeVisible();
  await expect(page.getByText(/ufw allow|sudo|shell/i)).toHaveCount(0);
});

test("plans and atomically applies typed protection limits", async ({ page }) => {
  await page.goto("/protection");
  await expect(page.getByRole("heading", { name: "보호 정책" })).toBeVisible();
  await expect(page.getByText("Edge 반영 확인", { exact: true })).toBeVisible();
  await page.getByLabel("LOCAL strict").fill("25");
  await page.getByRole("button", { name: "변경 계획 만들기" }).click();
  const plan = page.getByRole("region", { name: "보호 정책 변경 계획" });
  await expect(plan).toContainText("30 → 25 rpm");
  await plan.getByRole("button", { name: "확인 후 적용" }).click();
  await expect(page.getByText(/policy v8 원자 적용을 완료했습니다/)).toBeVisible();
});

test("renders JW-agent delegated firewall as read-only", async ({ page }) => {
  await page.route("**/api/v1/firewall", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        mode: "jw_agent_delegated",
        backend: "jw-agent",
        mutable: false,
        snapshot: null,
      }),
    });
  });
  await page.goto("/firewall");
  await expect(page.getByText("외부 위임", { exact: true })).toBeVisible();
  await expect(page.getByText(/JW-agent가 host firewall의 단일 소유자/)).toBeVisible();
  await expect(page.getByRole("button", { name: "계획 만들기" })).toHaveCount(0);
});

test("anonymous administrator is gated by two-factor login", async ({ page }) => {
  await mockAnonymousSession(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "관리자 로그인이 필요합니다" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "현재 방어 상태" })).toHaveCount(0);
  await page.getByRole("button", { name: "VPSGuard 관리자 로그인" }).first().click();
  await expect(page.getByRole("dialog", { name: "VPSGuard 관리자 로그인" })).toBeVisible();
  await expect(page.getByLabel("관리자 ID")).toBeVisible();
  await expect(page.getByLabel("인증기 6자리 코드")).toBeVisible();
});

test("PAM administrator enrolls a new authenticator before first login", async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const method = route.request().method();
    if (path === "/api/v1/auth/status") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          auth_provider: "pam",
          setup_required: true,
          enrollment_enabled: true,
          password_login_enabled: false,
          totp_required: false,
          break_glass_available: true,
        }),
      });
      return;
    }
    if (path === "/api/v1/session" && method === "GET") {
      await route.fulfill({ status: 401, contentType: "application/json", body: "{}" });
      return;
    }
    if (path === "/api/v1/auth/enrollment" && method === "POST") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          enrollment_id: "pam-enrollment",
          secret_base32: "JBSWY3DPEHPK3PXP",
          otpauth_uri: "otpauth://totp/VPSGuard:operator?secret=JBSWY3DPEHPK3PXP&issuer=VPSGuard",
          expires_in_seconds: 600,
        }),
      });
      return;
    }
    if (path === "/api/v1/auth/enrollment/confirm" && method === "POST") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        headers: { "set-cookie": "__Host-vps_guard_session=fixture; Secure; HttpOnly" },
        body: JSON.stringify({
          recovery_codes: ["AAAAAAAA-BBBBBBBB-CCCCCCCC-DDDDDDDD"],
          session: {
            csrf_token: "csrf-fixture",
            expires_in_seconds: 43200,
            actor: "operator",
            authentication_method: "pam_mfa",
          },
        }),
      });
      return;
    }
    await route.fallback();
  });

  await page.goto("/");
  const dialog = page.getByRole("dialog", { name: "최초 관리자 등록" });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText(/비밀번호는 저장하지 않습니다/)).toBeVisible();
  await dialog.getByLabel("최초 설정 단회 코드").fill("a".repeat(64));
  await dialog.getByLabel("Linux 서버 계정").fill("operator");
  await dialog.getByLabel("서버 계정 비밀번호", { exact: true }).fill("server-password");
  await dialog.getByLabel("서버 계정 비밀번호 확인").fill("server-password");
  await dialog.getByRole("button", { name: "2단계 인증 등록 계속" }).click();

  const totpDialog = page.getByRole("dialog", { name: "2단계 인증 연결" });
  await expect(totpDialog.getByRole("img", { name: "VPSGuard TOTP 등록 QR 코드" })).toBeVisible();
  await totpDialog.getByLabel("인증기 6자리 코드").fill("123456");
  await totpDialog.getByRole("button", { name: "등록 완료" }).click();
  await expect(page.getByRole("dialog", { name: "복구 코드 보관" })).toBeVisible();
  await expect(page.getByText("AAAAAAAA-BBBBBBBB-CCCCCCCC-DDDDDDDD")).toBeVisible();
});

test("uses the shadcn component contract for shared controls and dialogs", async ({ page }) => {
  await mockAnonymousSession(page);
  await page.goto("/");

  const headerLogin = page.getByRole("button", { name: "VPSGuard 관리자 로그인" }).first();
  await expect(headerLogin).toHaveAttribute("data-slot", "tooltip-trigger");
  const loginButton = page.getByRole("button", { name: "VPSGuard 관리자 로그인" }).last();
  await expect(loginButton).toHaveAttribute("data-slot", "button");
  await loginButton.click();

  const loginDialog = page.getByRole("dialog", { name: "VPSGuard 관리자 로그인" });
  await expect(loginDialog).toHaveAttribute("data-slot", "dialog-content");
  await expect(loginDialog.getByLabel("관리자 ID")).toHaveAttribute("data-slot", "input");
  await expect(
    loginDialog.getByRole("checkbox", { name: "인증기 대신 일회용 복구 코드 사용" }),
  ).toHaveAttribute("data-slot", "checkbox");
});

test("authenticated administrator can revoke every session with confirmation", async ({ page }) => {
  await page.route("**/api/v1/session", async (route) => {
    if (route.request().method() === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          csrf_token: "csrf-fixture",
          expires_in_seconds: 3600,
          actor: "guard.admin",
          authentication_method: "password_totp",
        }),
      });
      return;
    }
    await route.fallback();
  });
  await page.route("**/api/v1/sessions/revoke-all", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ logged_out: true, revoked_sessions: 2 }),
    });
  });
  await page.goto("/");
  await page.getByRole("button", { name: "모든 관리자 session 로그아웃" }).click();
  await expect(page.getByRole("alertdialog", { name: "모든 관리자 session 폐기" })).toBeVisible();
  await page.getByRole("button", { name: "모두 로그아웃" }).click();
  await expect(page.getByRole("heading", { name: "관리자 로그인이 필요합니다" })).toBeVisible();
});
