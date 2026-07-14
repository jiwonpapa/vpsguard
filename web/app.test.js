import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

describe("operations console public surface", () => {
  const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
  const script = readFileSync(new URL("./app.js", import.meta.url), "utf8");

  test("shows required state and freshness surfaces", () => {
    expect(html).toContain("현재 방어 상태");
    expect(html).toContain("서버 압력");
    expect(html).toContain('id="freshness"');
  });

  test("does not persist operation token in browser storage", () => {
    expect(script).not.toContain("localStorage");
    expect(script).not.toContain("sessionStorage");
  });
});
