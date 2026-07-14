import type { ReactNode } from "react";

export function SectionHeading({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow: string;
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <header className="mb-7 flex flex-wrap items-end justify-between gap-4">
      <div>
        <div className="font-mono text-[10px] font-bold uppercase tracking-[0.18em] text-orange-400">
          {eyebrow}
        </div>
        <h1 className="mt-2 text-2xl font-semibold tracking-tight text-zinc-50">{title}</h1>
        {description ? <p className="mt-2 max-w-2xl text-sm text-zinc-500">{description}</p> : null}
      </div>
      {action}
    </header>
  );
}
