import { AlertTriangle } from "lucide-react";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Badge } from "@/components/ui/Badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { api } from "@/lib/api";

const SEVERITY_LABEL = {
  critical: "Kritik",
  high: "Yüksek",
};

// Risk skoru bu eşiğin üzerindeki göstergeler (severity: high/critical) uyarı sayılır.
const ALERT_THRESHOLD = 50;

export default function Alerts() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    api
      .listHistory(100, ALERT_THRESHOLD)
      .then(setItems)
      .catch(() => setError("Uyarılar yüklenemedi."))
      .finally(() => setLoading(false));
  }, []);

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
          {loading && <p className="text-sm text-muted-foreground">Yükleniyor...</p>}
          {error && <p className="text-sm text-critical">{error}</p>}
          {!loading && items.length === 0 && (
            <p className="text-sm text-muted-foreground">
              Şu anda hiçbir uyarı yok — tüm göstergeler düşük/orta risk seviyesinde.
            </p>
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
