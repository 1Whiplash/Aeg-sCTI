import { Activity, Bookmark, LayoutDashboard, Search, Settings, ShieldAlert } from "lucide-react";
import { NavLink } from "react-router-dom";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { to: "/", label: "Genel Bakış", icon: LayoutDashboard },
  { to: "/investigate", label: "IOC İncele", icon: Search },
  { to: "/alerts", label: "Uyarılar", icon: ShieldAlert },
  { to: "/activity", label: "Aktivite", icon: Activity },
  { to: "/bookmarks", label: "İzleme Listesi", icon: Bookmark },
  { to: "/settings", label: "Ayarlar", icon: Settings },
];

export function Sidebar({ open, onClose }) {
  return (
    <>
      {open && (
        <div
          className="fixed inset-0 z-40 bg-black/50 md:hidden"
          onClick={onClose}
          aria-hidden="true"
        />
      )}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-50 flex h-screen w-60 flex-col border-r border-border bg-card transition-transform duration-200 md:static md:translate-x-0",
          open ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <div className="flex items-center gap-2 border-b border-border px-4 py-4">
          <ShieldAlert className="glow-shield h-6 w-6 text-primary" />
          <div>
            <p className="text-sm font-bold leading-none text-foreground">AegisCTI</p>
            <p className="text-[11px] text-muted-foreground">Read-Only SOC</p>
          </div>
        </div>
        <nav className="flex-1 space-y-1 p-3">
          {NAV_ITEMS.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              onClick={onClose}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground",
                  isActive && "bg-primary/10 text-primary",
                )
              }
            >
              <Icon className="h-4 w-4" />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-border p-3 text-[11px] text-muted-foreground">
          Faz 1 · Read-Only Mod
        </div>
      </aside>
    </>
  );
}
