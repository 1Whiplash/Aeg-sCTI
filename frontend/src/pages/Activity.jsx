import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Badge } from "@/components/ui/Badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { api } from "@/lib/api";

const SEVERITY_LABEL = {
  critical: "Kritik",
  high: "Yüksek",
  medium: "Orta",
  low: "Düşük",
};

export default function Activity() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    api
      .listHistory()
      .then(setItems)
      .catch(() => setError("Geçmiş yüklenemedi."))
      .finally(() => setLoading(false));
  }, []);

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
          {loading && <p className="text-sm text-muted-foreground">Yükleniyor...</p>}
          {error && <p className="text-sm text-critical">{error}</p>}
          {!loading && items.length === 0 && (
            <p className="text-sm text-muted-foreground">Henüz hiçbir gösterge analiz edilmedi.</p>
          )}
          {!loading && items.length > 0 && (
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
                  {items.map((item) => (
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
