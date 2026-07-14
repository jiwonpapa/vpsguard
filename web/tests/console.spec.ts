import { expect, test, type Page } from "@playwright/test";

const status = {
  schema_version: 1,
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
};

async function mockApi(page: Page) {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
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
        services: [],
      },
      "/api/v1/clients": { items: [{ client_ip: "203.0.113.8", requests: 77, throttled: 2, denied: 0, last_seen_unix_ms: 1784000000000 }] },
      "/api/v1/routes": { items: [] },
      "/api/v1/incidents": { items: [] },
      "/api/v1/traffic/series": { items: [] },
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
  await page.getByRole("link", { name: "클라이언트" }).click();
  await expect(page.getByText("203.0.113.8")).toBeVisible();
});

test("mutation opens bootstrap session dialog", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "자동 대응 중지" }).click();
  await expect(page.getByRole("dialog", { name: "운영 session 시작" })).toBeVisible();
});
