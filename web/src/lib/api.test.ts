import { describe, expect, test } from "bun:test";

import { ApiError, apiErrorMessage, correlationPath } from "./api";

describe("상관관계 조회 API", () => {
  test("식별자를 path segment로 안전하게 인코딩한다", () => {
    expect(correlationPath("guard-abc_123")).toBe(
      "/api/v1/correlations/guard-abc_123",
    );
    expect(correlationPath("event id/unsafe")).toBe(
      "/api/v1/correlations/event%20id%2Funsafe",
    );
  });

  test("빈 식별자는 요청하지 않는다", () => {
    expect(() => correlationPath("   ")).toThrow("상관관계 ID");
  });
});

describe("구조화 API 오류", () => {
  test("문제·원인·영향·조치와 추적 ID를 한 메시지로 제공한다", () => {
    const error = new ApiError(
      "저장소를 읽지 못했습니다.",
      503,
      "STORAGE_QUERY_FAILED",
      "SQLite read가 실패했습니다.",
      "화면 데이터가 지연됩니다.",
      "disk 상태를 확인하십시오.",
      "error-123",
      "guard-123",
    );

    expect(apiErrorMessage(error, "fallback")).toContain("원인: SQLite read가 실패했습니다.");
    expect(apiErrorMessage(error, "fallback")).toContain("영향: 화면 데이터가 지연됩니다.");
    expect(apiErrorMessage(error, "fallback")).toContain("다음 조치: disk 상태를 확인하십시오.");
    expect(apiErrorMessage(error, "fallback")).toContain("오류 ID: error-123");
    expect(apiErrorMessage(error, "fallback")).toContain("요청 ID: guard-123");
  });
});
