import { CheckCircle2, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { ThreatMap } from "@/components/ui/ThreatMap";
import { api } from "@/lib/api";

const ALERT_THRESHOLD = 50;
const CRITICAL_THRESHOLD = 80;
const ONE_DAY_MS = 24 * 60 * 60 * 1000;

const SEVERITY_LABEL = {
  critical: "Kritik",
  high: "Yüksek",
  medium: "Orta",
  low: "Düşük",
};

export default function Dashboard() {
  const [health, setHealth] = useState(null);
  const [healthError, setHealthError] = useState(false);
  const [stats, setStats] = useState(null);
  const [mapPoints, setMapPoints] = useState([]);
  const [recentAlerts, setRecentAlerts] = useState([]);

  useEffect(() => {
    api
      .health()
      .then(setHealth)
      .catch(() => setHealthError(true));

    api
      .listHistory(200)
      .then((items) => {
        const now = Date.now();
        setStats({
          openAlerts: items.filter((item) => item.risk_score >= ALERT_THRESHOLD).length,
          criticalCount: items.filter((item) => item.risk_score >= CRITICAL_THRESHOLD).length,
          last24h: items.filter((item) => now - new Date(item.created_at).getTime() < ONE_DAY_MS)
            .length,
        });

        const withGeo = items.filter((item) => item.geo);
        setMapPoints(
          withGeo.slice(0, 30).map((item) => ({
            lat: item.geo.lat,
            lon: item.geo.lon,
            severity: item.severity,
          })),
        );
        setRecentAlerts(withGeo.filter((item) => item.risk_score >= ALERT_THRESHOLD).slice(0, 8));
      })
      .catch(() => {});
  }, []);

  const statCards = [
    { label: "Açık Uyarılar", value: stats?.openAlerts ?? "—", variant: "high" },
    { label: "Kritik IOC", value: stats?.criticalCount ?? "—", variant: "critical" },
    { label: "İncelenen Gösterge (24s)", value: stats?.last24h ?? "—", variant: "info" },
    { label: "Sistem Modu", value: "Read-Only", variant: "low" },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-foreground">SOC Genel Bakış</h1>
          <p className="text-sm text-muted-foreground">
            AegisCTI · Faz 1 Otonom Tehdit İstihbaratı Platformu
          </p>
        </div>
        <div className="flex items-center gap-2 rounded-md border border-border bg-card px-3 py-1.5 text-xs">
          {healthError && (
            <>
              <XCircle className="h-3.5 w-3.5 text-critical" />
              <span className="text-critical">Backend'e ulaşılamıyor</span>
            </>
          )}
          {!healthError && health && (
            <>
              <CheckCircle2 className="h-3.5 w-3.5 text-low" />
              <span className="text-muted-foreground">Bağlı · v{health.version}</span>
            </>
          )}
          {!healthError && !health && (
            <span className="text-muted-foreground">Kontrol ediliyor...</span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {statCards.map((stat) => (
          <Card key={stat.label}>
            <CardHeader>
              <CardTitle>{stat.label}</CardTitle>
            </CardHeader>
            <CardContent className="flex items-center justify-between">
              <span className="text-2xl font-bold text-foreground">{stat.value}</span>
              <Badge variant={stat.variant}>{stat.variant}</Badge>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Tehdit Haritası</CardTitle>
          </CardHeader>
          <CardContent>
            {mapPoints.length > 0 ? (
              <ThreatMap points={mapPoints} />
            ) : (
              <p className="text-sm text-muted-foreground">
                Henüz konum verisi olan bir analiz yok — bir IP analiz ettiğinde burada görünecek.
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Son Uyarılar</CardTitle>
          </CardHeader>
          <CardContent>
            {recentAlerts.length === 0 && (
              <p className="text-sm text-muted-foreground">Aktif uyarı yok.</p>
            )}
            <ul className="space-y-3">
              {recentAlerts.map((item) => (
                <li key={item.id} className="flex items-center justify-between gap-2 text-sm">
                  <div className="min-w-0">
                    <p className="truncate font-medium text-foreground">{item.ioc_value}</p>
                    <p className="truncate text-xs text-muted-foreground">
                      {[item.geo?.city, item.geo?.country].filter(Boolean).join(", ") || "—"}
                    </p>
                  </div>
                  <Badge variant={item.severity}>
                    {SEVERITY_LABEL[item.severity] ?? item.severity}
                  </Badge>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
