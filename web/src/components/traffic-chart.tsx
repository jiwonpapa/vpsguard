import type { SeriesPoint } from "../lib/types";
import { formatTime } from "../lib/utils";

export function TrafficChart({
  points,
  resolution,
}: {
  points: SeriesPoint[];
  resolution: "1s" | "10s" | "1m";
}) {
  if (points.length === 0) {
    return <div className="grid h-64 place-items-center text-xs text-muted-foreground">시계열 표본 대기 중</div>;
  }
  const width = 900;
  const height = 260;
  const max = Math.max(1, ...points.map((point) => point.requests));
  const line = points
    .map((point, index) => {
      const x = points.length === 1 ? width / 2 : (index / (points.length - 1)) * width;
      const y = height - (point.requests / max) * (height - 32) - 16;
      return `${x},${y}`;
    })
    .join(" ");
  return (
    <figure className="px-5 py-5 sm:px-6">
      <svg className="h-64 w-full" viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`${resolution} 요청 추이`}>
        {[0.25, 0.5, 0.75].map((ratio) => (
          <line key={ratio} x1="0" x2={width} y1={height * ratio} y2={height * ratio} stroke="currentColor" className="text-border" />
        ))}
        <polyline points={line} fill="none" stroke="currentColor" strokeWidth="3" className="text-orange-400" vectorEffect="non-scaling-stroke" />
        {points.map((point, index) => {
          const x = points.length === 1 ? width / 2 : (index / (points.length - 1)) * width;
          const y = height - (point.requests / max) * (height - 32) - 16;
          return <circle key={point.bucket_unix_ms} cx={x} cy={y} r="3" className="fill-card stroke-orange-400" />;
        })}
      </svg>
      <figcaption className="mt-2 flex justify-between gap-3 font-mono text-[10px] text-muted-foreground">
        <span>{formatTime(points[0].bucket_unix_ms)}</span>
        <span>최대 {max.toLocaleString()} req/{resolution}</span>
        <span>{formatTime(points.at(-1)?.bucket_unix_ms ?? 0)}</span>
      </figcaption>
    </figure>
  );
}
