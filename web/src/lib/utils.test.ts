import { describe, expect, test } from "bun:test";

import { formatBytes, formatLatency, percent } from "./utils";

describe("operations console formatters", () => {
  test("formats bounded byte and latency values", () => {
    expect(formatBytes(1024 ** 2)).toBe("1.0 MiB");
    expect(formatLatency(12_500)).toBe("12.5 ms");
  });

  test("percentage handles empty and impossible totals", () => {
    expect(percent(1, 0)).toBe(0);
    expect(percent(12, 10)).toBe(100);
  });
});
