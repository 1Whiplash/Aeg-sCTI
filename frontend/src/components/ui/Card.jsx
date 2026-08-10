import { cn } from "@/lib/utils";

export function Card({ className, children }) {
  return (
    <div className={cn("rounded-lg border border-border bg-card text-card-foreground shadow-sm", className)}>
      {children}
    </div>
  );
}

export function CardHeader({ className, children }) {
  return <div className={cn("flex flex-col gap-1 p-4 pb-2", className)}>{children}</div>;
}

export function CardTitle({ className, children }) {
  return <h3 className={cn("text-sm font-semibold tracking-tight text-foreground", className)}>{children}</h3>;
}

export function CardContent({ className, children }) {
  return <div className={cn("p-4 pt-2", className)}>{children}</div>;
}
