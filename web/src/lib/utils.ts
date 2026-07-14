import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

export const MODE_LABELS: Record<string, string> = {
  NORMAL: "정상",
  WATCH: "주의 관찰",
  LOCAL_GUARD: "로컬 방어",
  EMERGENCY_PROXY: "비상 보호",
  RECOVERING: "복구 중",
  MANUAL_HOLD: "수동 고정",
};

export function formatBytes(value: number | null | undefined): string {
  if (value == null) return "—";
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KiB`;
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MiB`;
  return `${(value / 1024 ** 3).toFixed(1)} GiB`;
}

export function formatLatency(micros: number): string {
  if (micros < 1_000) return `${micros} µs`;
  return `${(micros / 1_000).toFixed(1)} ms`;
}

export function formatTime(value: number | string): string {
  const date = typeof value === "number" ? new Date(value) : new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("ko-KR", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(date);
}

export function percent(part: number, total: number): number {
  return total === 0 ? 0 : Math.min(100, Math.round((part / total) * 100));
}
