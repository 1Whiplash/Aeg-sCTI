import { useState } from "react";
import { cn } from "@/lib/utils";

/** tabs: { label: string, content: ReactNode }[] */
export function Tabs({ tabs }) {
  const [active, setActive] = useState(0);
  if (!tabs || tabs.length === 0) return null;

  return (
    <div>
      <div className="flex flex-wrap gap-1 border-b border-border">
        {tabs.map((tab, index) => (
          <button
            key={tab.label}
            type="button"
            onClick={() => setActive(index)}
            className={cn(
              "border-b-2 px-3 py-2 text-sm font-medium transition-colors",
              index === active
                ? "border-primary text-primary"
                : "border-transparent text-muted-foreground hover:text-foreground",
            )}
          >
            {tab.label}
          </button>
        ))}
      </div>
      <div className="pt-3">{tabs[active].content}</div>
    </div>
  );
}
