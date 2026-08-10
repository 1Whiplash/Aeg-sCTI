import { cn } from "@/lib/utils";

const VARIANTS = {
  critical: "bg-critical/15 text-critical border-critical/30",
  high: "bg-high/15 text-high border-high/30",
  medium: "bg-medium/15 text-medium border-medium/30",
  low: "bg-low/15 text-low border-low/30",
  info: "bg-info/15 text-info border-info/30",
  default: "bg-muted text-muted-foreground border-border",
};

export function Badge({ variant = "default", className, children }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium",
        VARIANTS[variant] ?? VARIANTS.default,
        className,
      )}
    >
      {children}
    </span>
  );
}
