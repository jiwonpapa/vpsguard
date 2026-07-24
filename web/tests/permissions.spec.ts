import { expect, test, type Page } from "@playwright/test";

// UI-012: 서버가 계산한 역할별 권한을 UI가 fail-closed로 반영하는지 검증합니다.

type Role = "viewer" | "analyst" | "operator" | "administrator";

const roleMatrix = {
  viewer: {
    view_raw_ip: false,
    export_sensitive: false,
    operate: false,
    administer: false,
  },
  analyst: {
    view_raw_ip: true,
    export_sensitive: true,
    operate: false,
    administer: false,
  },
  operator: {
    view_raw_ip: true,
    export_sensitive: false,
    operate: true,
    administer: false,
  },
  administrator: {
    view_raw_ip: true,
    export_sensitive: true,
    operate: true,
    administer: true,
  },
} as const;

const rawClientIp = "203.0.113.42";
const maskedClientNetwork = "203.0.113.0/24";

async function mockRoleApi(page: Page, role: Role) {
  const capabilities = roleMatrix[role];
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/session") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          csrf_token: "csrf-fixture",
          expires_in_seconds: 3600,
          actor: `${role}.account`,
          authentication_method: "password_totp",
          role,
          capabilities,
        }),
      });
      return;
    }
    if (path === "/api/v1/auth/status") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          auth_provider: "pam",
          setup_required: false,
          enrollment_enabled: true,
          password_login_enabled: true,
          totp_required: true,
          break_glass_available: true,
        }),
      });
      return;
    }
    if (path === "/api/v1/clients") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          items: [{
            client_ip: capabilities.view_raw_ip ? rawClientIp : maskedClientNetwork,
            requests: 12,
            throttled: 2,
            denied: 1,
            request_body_bytes: 1200,
            response_body_bytes: 3400,
            last_seen_unix_ms: 1784000000000,
          }],
        }),
      });
      return;
    }
    if (path === "/api/v1/settings/protection") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          settings: {
            watch_strict_requests_per_minute: 120,
            local_strict_requests_per_minute: 60,
            local_upload_requests_per_minute: 30,
            emergency_strict_requests_per_minute: 20,
            emergency_upload_requests_per_minute: 10,
          },
          fingerprint: "policy-fixture",
          policy_version: 7,
          edge_observed_policy_version: 7,
          edge_readback: "observed",
          enforcement_active: true,
        }),
      });
      return;
    }
    await route.fulfill({
      status: 404,
      contentType: "application/json",
      body: JSON.stringify({ error: { code: "FIXTURE_NOT_FOUND" } }),
    });
  });
}

for (const role of Object.keys(roleMatrix) as Role[]) {
  test(`${role} 역할은 민감 조회, export, 운영, 관리자 권한을 분리한다`, async ({ page }) => {
    const capabilities = roleMatrix[role];
    await mockRoleApi(page, role);
    await page.goto("/clients");

    if (capabilities.view_raw_ip) {
      await expect(page.getByRole("button", { name: `${rawClientIp} 상세 보기` })).toBeVisible();
      await expect(page.getByText(maskedClientNetwork, { exact: true })).toHaveCount(0);
    } else {
      await expect(page.getByText(maskedClientNetwork, { exact: true })).toBeVisible();
      await expect(page.getByText(rawClientIp, { exact: true })).toHaveCount(0);
    }

    await expect(page.getByRole("button", { name: "원시 IP CSV" }))
      .toHaveCount(capabilities.export_sensitive ? 1 : 0);
    await expect(page.getByRole("button", { name: "모든 관리자 session 로그아웃" }))
      .toHaveCount(capabilities.administer ? 1 : 0);

    await page.goto("/protection");
    await expect(page.getByRole("heading", { name: "보호 정책" })).toBeVisible();
    await expect(page.getByRole("button", { name: "변경 계획 만들기" }))
      .toHaveCount(capabilities.operate ? 1 : 0);
  });
}
