import { expect, test } from "@playwright/test";

// UI-011: 관리자 shell과 인증 dialog의 viewport·theme 회귀를 고정합니다.

const administratorAuthorization = {
  role: "administrator",
  capabilities: {
    view_raw_ip: true,
    export_sensitive: true,
    operate: true,
    administer: true,
  },
};

test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
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
    await route.fulfill({
      status: 401,
      contentType: "application/json",
      body: JSON.stringify({ error: { code: "SESSION_AUTH_REQUIRED" } }),
    });
  });
});

test("keeps the administrator shell consistent across themes", async ({ page }, testInfo) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "관리자 로그인이 필요합니다" })).toBeVisible();

  await expect(page).toHaveScreenshot(`${testInfo.project.name}-admin-gate-dark.png`, {
    animations: "disabled",
    fullPage: true,
  });

  await page.getByRole("button", { name: "테마 전환" }).click();
  await expect(page.locator("html")).not.toHaveClass(/dark/);
  await expect(page).toHaveScreenshot(`${testInfo.project.name}-admin-gate-light.png`, {
    animations: "disabled",
    fullPage: true,
  });

  await page.getByRole("button", { name: "VPSGuard 관리자 로그인" }).last().click();
  await expect(page.getByRole("dialog", { name: "VPSGuard 관리자 로그인" })).toBeVisible();
  await expect(page).toHaveScreenshot(`${testInfo.project.name}-admin-login-light.png`, {
    animations: "disabled",
    fullPage: true,
  });
});

test("keeps the authenticated operations overview consistent", async ({ page }, testInfo) => {
  await page.unroute("**/api/v1/**");
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const fixtures: Record<string, unknown> = {
      "/api/v1/session": {
        csrf_token: "csrf-fixture",
        expires_in_seconds: 3600,
        actor: "guard.admin",
        authentication_method: "password_totp",
        ...administratorAuthorization,
      },
      "/api/v1/auth/status": {
        auth_provider: "local",
        setup_required: false,
        enrollment_enabled: true,
        password_login_enabled: true,
        totp_required: true,
        break_glass_available: true,
      },
      "/api/v1/status": {
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
          auth_rate_limit_rpm: 12,
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
      },
      "/api/v1/traffic/summary": {
        window_seconds: 900,
        window_started_at_unix_ms: 1783999100000,
        window_ended_at_unix_ms: 1784000000000,
        requests_per_second_milli: 1284000,
        requests: 12840,
        status_2xx: 11890,
        status_3xx: 180,
        status_4xx: 690,
        status_5xx: 80,
        throttled: 318,
        denied: 44,
        challenged: 27,
        latency_p95_micros: 12500,
        unique_clients: 842,
        dropped_clients: 0,
        request_body_bytes: 640000,
        response_body_bytes: 8192000,
        upstream_connections: 4200,
        upstream_connections_reused: 3580,
        in_flight_requests: 14,
        bot_requests: 220,
        bot_denied: 44,
        edge_telemetry_emitted: 12840,
        edge_telemetry_dropped: 0,
        edge_telemetry_reconnected: 1,
      },
      "/api/v1/resources": {
        state: "live",
        os: {
          cpu_usage_percent: 37,
          logical_cpu_count: 2,
          load_1m: 0.72,
          memory_total_bytes: 2147483648,
          memory_available_bytes: 1073741824,
          swap_total_bytes: 0,
          swap_free_bytes: 0,
          uptime_seconds: 172800,
        },
        services: [],
        storage: {},
      },
    };
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(fixtures[path] ?? {}),
    });
  });

  await page.goto("/");
  await expect(page.getByRole("region", { name: "현재 보호 상태" })).toBeVisible();
  await expect(page).toHaveScreenshot(`${testInfo.project.name}-overview-dark.png`, {
    animations: "disabled",
    fullPage: true,
  });

  await page.getByRole("button", { name: "테마 전환" }).click();
  await expect(page).toHaveScreenshot(`${testInfo.project.name}-overview-light.png`, {
    animations: "disabled",
    fullPage: true,
  });
});
