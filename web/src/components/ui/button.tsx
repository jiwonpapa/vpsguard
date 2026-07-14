import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "../../lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap border text-xs font-bold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-orange-500 disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        default: "border-orange-500 bg-orange-500 px-3 py-2 text-zinc-950 hover:bg-orange-400",
        outline:
          "border-zinc-700 bg-transparent px-3 py-2 text-zinc-100 hover:border-zinc-500 hover:bg-zinc-900",
        ghost: "border-transparent px-2 py-2 text-zinc-400 hover:bg-zinc-900 hover:text-zinc-50",
        danger: "border-red-500 bg-red-500 px-3 py-2 text-white hover:bg-red-400",
      },
      size: {
        default: "h-9",
        sm: "h-8",
        icon: "size-9 p-0",
      },
    },
    defaultVariants: { variant: "default", size: "default" },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => (
    <button
      ref={ref}
      className={cn(buttonVariants({ variant, size }), className)}
      {...props}
    />
  ),
);
Button.displayName = "Button";
