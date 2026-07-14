import type { HTMLAttributes } from "react";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "../../lib/utils";

const badgeVariants = cva(
  "inline-flex items-center border px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider",
  {
    variants: {
      variant: {
        neutral: "border-zinc-700 text-zinc-400",
        live: "border-emerald-700 bg-emerald-950 text-emerald-300",
        warning: "border-amber-700 bg-amber-950 text-amber-300",
        danger: "border-red-700 bg-red-950 text-red-300",
      },
    },
    defaultVariants: { variant: "neutral" },
  },
);

interface BadgeProps
  extends HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}
