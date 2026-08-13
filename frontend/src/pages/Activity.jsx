import { Search, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Badge } from "@/components/ui/Badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { api } from "@/lib/api";
import { isAuthenticated } from "@/lib/auth";

const SEVERITY_LABEL = {
  critical: "Kritik",
  high: "Yüksek",
  medium: "Orta",
  low: "Düşük",
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
  { value: "medium", label: "Orta" },
  { value: "low", label: "Düşük" },
];

export default function Activity() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [authed, setAuthed] = useState(isAuthenticated());
  const navigate = useNavigate();

  useEffect(() => {
    api
      .listHistory()
      .then(setItems)
      .catch(() => setError("Geçmiş yüklenemedi."))
      .finally(() => setLoading(false));
  }, []);

  async function handleDelete(event, item) {
    event.stopPropagation(); // satırın kendi tıklama (incele) davranışını tetiklemesin
    if (!window.confirm(`"${item.ioc_value}" geçmişten kalıcı olarak silinsin mi?`)) return;
    try {
      await api.deleteHistoryEntry(item.id);
      setItems((prev) => prev.filter((entry) => entry.id !== item.id));
    } catch (err) {
      setError(err.status === 401 ? "Oturum süresi doldu, tekrar giriş yapın." : "Kayıt silinemedi.");
      if (err.status === 401) setAuthed(false);
    }
  }

  const filteredItems = useMemo(() => {
    const query = search.trim().toLowerCase();
    return items.filter((item) => {
      if (query && !item.ioc_value.toLowerCase().includes(query)) return false;
      if (typeFilter !== "all" && item.ioc_type !== typeFilter) return false;
      if (severityFilter !== "all" && item.severity !== severityFilter) return false;
      return true;
    });
  }, [items, search, typeFilter, severityFilter]);

  function goToInvestigate(item) {
    navigate(`/investigate?value=${encodeURIComponent(item.ioc_value)}&type=${item.ioc_type}`);
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-foreground">Aktivite</h1>
        <p className="text-sm text-muted-foreground">
          Geçmişte analiz edilen tüm göstergeler — bir satıra tıklayarak tekrar incele.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Sorgu Geçmişi</CardTitle>
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
            <p className="text-sm text-muted-foreground">Henüz hiçbir gösterge analiz edilmedi.</p>
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
                    {authed && <th className="py-2 pr-4 font-medium" />}
                  </tr>
                </thead>
                <tbody>
                  {filteredItems.map((item) => (
                    <tr
                      key={item.id}
                      onClick={() => goToInvestigate(item)}
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
                      {authed && (
                        <td className="py-2 text-right">
                          <button
                            type="button"
                            onClick={(event) => handleDelete(event, item)}
                            className="text-muted-foreground hover:text-critical"
                            aria-label="Sil"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </td>
                      )}
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
