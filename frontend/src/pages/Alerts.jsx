import { AlertTriangle, Search } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Badge } from "@/components/ui/Badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { api } from "@/lib/api";

const SEVERITY_LABEL = {
  critical: "Kritik",
  high: "Yüksek",
};

const TYPE_OPTIONS = [
  { value: "all", label: "Tüm tipler" },
  { value: "ip", label: "IP" },
  { value: "domain", label: "Domain" },
  { value: "url", label: "URL" },
  { value: "hash", label: "Hash" },
];

const SEVERITY_OPTIONS = [
  { value: "all", label: "Tüm önem dereceleri" },
  { value: "critical", label: "Kritik" },
  { value: "high", label: "Yüksek" },
];

// Risk skoru bu eşiğin üzerindeki göstergeler (severity: high/critical) uyarı sayılır.
const ALERT_THRESHOLD = 50;

export default function Alerts() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const navigate = useNavigate();

  useEffect(() => {
    api
      .listHistory(100, ALERT_THRESHOLD)
      .then(setItems)
      .catch(() => setError("Uyarılar yüklenemedi."))
      .finally(() => setLoading(false));
  }, []);

  const filteredItems = useMemo(() => {
    const query = search.trim().toLowerCase();
    return items.filter((item) => {
      if (query && !item.ioc_value.toLowerCase().includes(query)) return false;
      if (typeFilter !== "all" && item.ioc_type !== typeFilter) return false;
      if (severityFilter !== "all" && item.severity !== severityFilter) return false;
      return true;
    });
  }, [items, search, typeFilter, severityFilter]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-foreground">Uyarılar</h1>
        <p className="text-sm text-muted-foreground">
          Risk skoru {ALERT_THRESHOLD}/100 ve üzeri olan göstergeler (önem derecesi yüksek veya
          kritik) burada otomatik olarak listelenir.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-high" />
            Aktif Uyarılar ({items.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="mb-4 flex flex-wrap items-center gap-3">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Göstergeye göre ara..."
                className="w-full rounded-md border border-border bg-background py-2 pl-9 pr-3 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
            <select
              value={typeFilter}
              onChange={(event) => setTypeFilter(event.target.value)}
              className="rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            >
              {TYPE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
            <select
              value={severityFilter}
              onChange={(event) => setSeverityFilter(event.target.value)}
              className="rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            >
              {SEVERITY_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          {loading && <p className="text-sm text-muted-foreground">Yükleniyor...</p>}
          {error && <p className="text-sm text-critical">{error}</p>}
          {!loading && items.length === 0 && (
            <p className="text-sm text-muted-foreground">
              Şu anda hiçbir uyarı yok — tüm göstergeler düşük/orta risk seviyesinde.
            </p>
          )}
          {!loading && items.length > 0 && filteredItems.length === 0 && (
            <p className="text-sm text-muted-foreground">Filtrelere uyan kayıt yok.</p>
          )}
          {!loading && filteredItems.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-border text-muted-foreground">
                    <th className="py-2 pr-4 font-medium">Gösterge</th>
                    <th className="py-2 pr-4 font-medium">Tip</th>
                    <th className="py-2 pr-4 font-medium">Risk Skoru</th>
                    <th className="py-2 pr-4 font-medium">Önem</th>
                    <th className="py-2 pr-4 font-medium">Tarih</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredItems.map((item) => (
                    <tr
                      key={item.id}
                      onClick={() =>
                        navigate(
                          `/investigate?value=${encodeURIComponent(item.ioc_value)}&type=${item.ioc_type}`,
                        )
                      }
                      className="cursor-pointer border-b border-border/50 hover:bg-muted/50"
                    >
                      <td className="max-w-xs truncate py-2 pr-4 text-foreground">{item.ioc_value}</td>
                      <td className="py-2 pr-4 text-muted-foreground">{item.ioc_type.toUpperCase()}</td>
                      <td className="py-2 pr-4 text-foreground">{item.risk_score}/100</td>
                      <td className="py-2 pr-4">
                        <Badge variant={item.severity}>
                          {SEVERITY_LABEL[item.severity] ?? item.severity}
                        </Badge>
                      </td>
                      <td className="py-2 pr-4 text-muted-foreground">
                        {new Date(item.created_at).toLocaleString("tr-TR")}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
