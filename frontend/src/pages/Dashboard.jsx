import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { api } from "@/lib/api";

const STAT_CARDS = [
  { label: "Açık Uyarılar", value: "—", variant: "high" },
  { label: "Kritik IOC", value: "—", variant: "critical" },
  { label: "İncelenen Gösterge (24s)", value: "—", variant: "info" },
  { label: "Sistem Modu", value: "Read-Only", variant: "low" },
];

export default function Dashboard() {
  const [health, setHealth] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api
      .health()
      .then(setHealth)
      .catch(() => setError("Backend'e ulaşılamadı."));
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-foreground">SOC Genel Bakış</h1>
        <p className="text-sm text-muted-foreground">
          AegisCTI · Faz 1 Otonom Tehdit İstihbaratı Platformu
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {STAT_CARDS.map((stat) => (
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

      <Card>
        <CardHeader>
          <CardTitle>Backend Durumu</CardTitle>
        </CardHeader>
        <CardContent>
          {error && <p className="text-sm text-critical">{error}</p>}
          {!error && !health && <p className="text-sm text-muted-foreground">Kontrol ediliyor...</p>}
          {health && (
            <pre className="rounded-md bg-muted p-3 text-xs text-muted-foreground">
              {JSON.stringify(health, null, 2)}
            </pre>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
