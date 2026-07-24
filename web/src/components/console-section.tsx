import type { ReactNode } from "react";
import { CircleHelp } from "lucide-react";

import { cn } from "../lib/utils";
import { Tooltip, TooltipContent, TooltipTrigger } from "./ui/tooltip";

export function ConsoleSection({
  label,
  title,
  description,
  action,
  children,
  className,
  contentClassName,
}: {
  label: string;
  title?: string;
  description?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  contentClassName?: string;
}) {
  return (
    <section
      aria-label={label}
      className={cn(
        "overflow-hidden rounded-xl border border-border/80 bg-card/70 shadow-sm shadow-black/[0.025]",
        className,
      )}
    >
      {title || description || action ? (
        <header className="flex flex-col gap-3 border-b border-border/70 px-5 py-4 sm:flex-row sm:items-start sm:justify-between sm:px-6">
          <div className="min-w-0">
            {title ? <h2 className="text-sm font-semibold tracking-tight text-foreground">{title}</h2> : null}
            {description ? <p className="mt-1 max-w-3xl text-xs leading-5 text-muted-foreground">{description}</p> : null}
          </div>
          {action ? <div className="shrink-0">{action}</div> : null}
        </header>
      ) : null}
      <div className={cn("p-5 sm:p-6", contentClassName)}>{children}</div>
    </section>
  );
}

export function MetricGrid({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <dl className={cn("grid divide-y divide-border/70 sm:grid-cols-2 sm:divide-x sm:divide-y-0 xl:grid-cols-4", className)}>
      {children}
    </dl>
  );
}

export function MetricItem({
  label,
  value,
  note,
  help,
  emphasis = false,
}: {
  label: string;
  value: string;
  note?: string;
  help?: string;
  emphasis?: boolean;
}) {
  return (
    <div className="min-w-0 px-5 py-4 first:pl-0 last:pr-0 sm:first:pl-5 sm:last:pr-5">
      <dt className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
        {label}
        {help ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <button type="button" className="rounded-sm outline-none focus-visible:ring-2 focus-visible:ring-ring" aria-label={`${label} 도움말`}>
                <CircleHelp className="size-3.5" aria-hidden="true" />
              </button>
            </TooltipTrigger>
            <TooltipContent sideOffset={6} className="max-w-72 leading-5">{help}</TooltipContent>
          </Tooltip>
        ) : null}
      </dt>
      <dd className={cn("mt-2 truncate font-mono text-xl font-medium tracking-tight", emphasis && "text-primary")}>{value}</dd>
      {note ? <p className="mt-1 truncate font-mono text-[10px] text-muted-foreground/70">{note}</p> : null}
    </div>
  );
}
