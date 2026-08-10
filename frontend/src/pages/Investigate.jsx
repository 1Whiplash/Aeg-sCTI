import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Badge } from "@/components/ui/Badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { RiskGauge } from "@/components/ui/RiskGauge";
import { Tabs } from "@/components/ui/Tabs";
import { api } from "@/lib/api";

const SEVERITY_LABEL = {
  critical: "Kritik",
  high: "Yüksek",
  medium: "Orta",
  low: "Düşük",
};

export default function Investigate() {
  const [searchParams] = useSearchParams();
  const value = searchParams.get("value");
  const iocType = searchParams.get("type");

  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!value || !iocType) return;
    setLoading(true);
    setError(null);
    setResult(null);
    api
      .analyzeIOC({ value, ioc_type: iocType })
      .then(setResult)
      .catch(() => setError("Analiz sırasında bir hata oluştu."))
      .finally(() => setLoading(false));
  }, [value, iocType]);

  if (!value || !iocType) {
    return (
      <div>
        <h1 className="text-xl font-bold text-foreground">IOC İncele</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Üstteki arama çubuğundan (Ctrl+K) bir IP, domain, hash veya URL ara.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="break-all text-xl font-bold text-foreground">{value}</h1>
        <p className="text-sm text-muted-foreground">Tip: {iocType.toUpperCase()}</p>
      </div>

      {loading && <p className="text-sm text-muted-foreground">Analiz ediliyor, bu biraz sürebilir...</p>}
      {error && <p className="text-sm text-critical">{error}</p>}

      {result && (
        <>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <Card className="flex flex-col items-center justify-center gap-3 p-6 lg:col-span-1">
              <RiskGauge score={result.risk_score} />
              <Badge variant={result.severity}>
                {SEVERITY_LABEL[result.severity] ?? result.severity}
              </Badge>
            </Card>

            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle>AI SOC Analisti Raporu</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm leading-relaxed text-foreground">{result.llm_analysis}</p>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>OSINT Kanıtları</CardTitle>
            </CardHeader>
            <CardContent>
              <Tabs
                tabs={
                  result.osint_evidence.length > 0
                    ? result.osint_evidence.map((item) => ({
                        label: item.source,
                        content: (
                          <pre className="max-h-96 overflow-auto rounded-md bg-muted p-3 text-xs text-muted-foreground">
                            {JSON.stringify(item.raw_data, null, 2)}
                          </pre>
                        ),
                      }))
                    : [
                        {
                          label: "Kanıt yok",
                          content: (
                            <p className="text-sm text-muted-foreground">
                              Bu gösterge için hiçbir OSINT kaynağından veri dönmedi (API key
                              tanımlı değilse veya kaynaklar sonuçsuzsa bu beklenen bir durumdur).
                            </p>
                          ),
                        },
                      ]
                }
              />
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
