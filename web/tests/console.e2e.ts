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
};

async function mockApi(page: Page) {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/session" && route.request().method() === "GET") {
      await route.fulfill({
        status: 401,
        contentType: "application/json",
        body: JSON.stringify({ error: { code: "SESSION_AUTH_REQUIRED" } }),
      });
      return;
    }
    if (path === "/api/v1/auth/status") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          setup_required: false,
          password_login_enabled: true,
          totp_required: true,
          break_glass_available: true,
        }),
      });
      return;
    }
    const data: Record<string, unknown> = {
      "/api/v1/status": status,
      "/api/v1/traffic/summary": {
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
      },
      "/api/v1/resources": {
        state: "live",
        os: {
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
        },
      },
      "/api/v1/clients": { items: [{ client_ip: "203.0.113.8", requests: 77, throttled: 2, denied: 0, request_body_bytes: 2048, response_body_bytes: 16384, last_seen_unix_ms: 1784000000000 }] },
      "/api/v1/routes": { items: [] },
      "/api/v1/incidents": { items: [] },
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

test.beforeEach(async ({ page }) => {
  await mockApi(page);
});

test("renders protection posture and client drill-down", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "현재 방어 상태" })).toBeVisible();
  await expect(page.getByText("로컬 방어", { exact: true })).toBeVisible();
  await expect(page.getByText(/앱 보안 활성 · CSP report_only/)).toBeVisible();
  await page.getByRole("link", { name: "클라이언트" }).click();
  await expect(page.getByText("203.0.113.8")).toBeVisible();
  await page.getByLabel("Client 검색").fill("198.51");
  await expect(page.getByText("아직 수집된 항목이 없습니다.")).toBeVisible();
  await page.getByLabel("Client 검색").fill("203.0");
  await expect(page.getByText("18.0 KiB")).toBeVisible();
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

test("switches between live and persisted traffic resolutions", async ({ page }) => {
  await page.goto("/traffic");
  await expect(page.getByRole("img", { name: "1m 요청 추이" })).toBeVisible();
  await page.getByLabel("시계열 해상도").selectOption("1s");
  await expect(page.getByRole("img", { name: "1s 요청 추이" })).toBeVisible();
});

test("mutation opens administrator two-factor login dialog", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "자동 대응 중지" }).click();
  await expect(page.getByRole("dialog", { name: "운영 명령 확인" })).toBeVisible();
  await page.getByRole("button", { name: "확인 후 실행" }).click();
  await expect(page.getByRole("dialog", { name: "VPSGuard 관리자 로그인" })).toBeVisible();
  await expect(page.getByLabel("관리자 ID")).toBeVisible();
  await expect(page.getByLabel("인증기 6자리 코드")).toBeVisible();
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
  await expect(page.getByRole("dialog", { name: "모든 관리자 session 폐기" })).toBeVisible();
  await page.getByRole("button", { name: "모두 로그아웃" }).click();
  await expect(page.getByRole("button", { name: "VPSGuard 관리자 로그인" })).toBeVisible();
});
