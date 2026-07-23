import { describe, expect, test } from "bun:test";

import { isTotpCode, validateAdminSetup } from "./auth";

describe("VPSGuard 관리자 입력", () => {
  test("OS 계정과 무관한 bounded 관리자 ID와 12자 비밀번호를 받는다", () => {
    expect(validateAdminSetup("guard.admin", "correct horse battery", "correct horse battery")).toBeNull();
    expect(validateAdminSetup("root space", "correct horse battery", "correct horse battery")).toContain("ID");
    expect(validateAdminSetup("guard", "too-short", "too-short")).toContain("12자");
  });

  test("확인 비밀번호와 TOTP 형식을 엄격히 검사한다", () => {
    expect(validateAdminSetup("guard", "correct horse battery", "different password")).toContain("일치");
    expect(isTotpCode("012345")).toBe(true);
    expect(isTotpCode("１２３４５６")).toBe(false);
    expect(isTotpCode("12345 6")).toBe(false);
  });

  test("PAM 최초 등록은 서버 비밀번호 정책을 복제하지 않는다", () => {
    expect(validateAdminSetup("operator", "short-os-password", "short-os-password", "pam")).toBeNull();
    expect(validateAdminSetup("operator", "", "", "pam")).toContain("서버 계정");
    expect(validateAdminSetup("operator", "server-password", "different", "pam")).toContain("일치");
  });
});
