import { Search } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Badge } from "@/components/ui/Badge";
import { detectIocType } from "@/lib/detectIocType";

export function Header() {
  const [query, setQuery] = useState("");
  const inputRef = useRef(null);
  const navigate = useNavigate();
  const detectedType = detectIocType(query);

  useEffect(() => {
    function handleKeyDown(event) {
      const isShortcut = (event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k";
      if (isShortcut) {
        event.preventDefault();
        inputRef.current?.focus();
      }
      if (event.key === "Escape" && document.activeElement === inputRef.current) {
        inputRef.current?.blur();
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  function handleSubmit(event) {
    event.preventDefault();
    const trimmed = query.trim();
    if (!trimmed || !detectedType) return;
    navigate(`/investigate?value=${encodeURIComponent(trimmed)}&type=${detectedType}`);
  }

  return (
    <header className="flex items-center gap-3 border-b border-border bg-card/50 px-6 py-3">
      <form onSubmit={handleSubmit} className="flex flex-1 items-center gap-2">
        <div className="relative max-w-xl flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <input
            ref={inputRef}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="IP, domain, hash veya URL ara..."
            className="w-full rounded-md border border-border bg-background py-2 pl-9 pr-16 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          />
          <kbd className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
            Ctrl K
          </kbd>
        </div>
        {query && (
          <Badge variant={detectedType ? "info" : "default"}>
            {detectedType ? detectedType.toUpperCase() : "tanınmadı"}
          </Badge>
        )}
      </form>
    </header>
  );
}
