import { Bot, CheckCircle2, FileDown, MapPin, Radar, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { AdminLoginGate } from "@/components/ui/AdminLoginGate";
import { Badge } from "@/components/ui/Badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { RiskGauge } from "@/components/ui/RiskGauge";
import { Tabs } from "@/components/ui/Tabs";
import { ThreatMap } from "@/components/ui/ThreatMap";
import { VendorVerdicts } from "@/components/ui/VendorVerdicts";
import { api } from "@/lib/api";
import { isAuthenticated } from "@/lib/auth";
import { cn } from "@/lib/utils";
import { exportAnalysisPdf } from "@/lib/pdfExport";

const SEVERITY_LABEL = {
  critical: "Kritik",
  high: "Yüksek",
  medium: "Orta",
  low: "Düşük",
};

const SEVERITY_BORDER = {
  critical: "border-l-critical",
  high: "border-l-high",
  medium: "border-l-medium",
  low: "border-l-low",
};

export default function Investigate() {
  const [searchParams] = useSearchParams();
  const value = searchParams.get("value");
  const iocType = searchParams.get("type");

  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [blockState, setBlockState] = useState(null); // null | "loading" | { blocked, message }
  const [authed, setAuthed] = useState(isAuthenticated());

  useEffect(() => {
    if (!value || !iocType) return;
    setLoading(true);
    setError(null);
    setResult(null);
    setBlockState(null);
    api
      .analyzeIOC({ value, ioc_type: iocType })
      .then(setResult)
      .catch(() => setError("Analiz sırasında bir hata oluştu."))
      .finally(() => setLoading(false));
  }, [value, iocType]);

  async function handleBlockIp() {
    if (
      !window.confirm(
        `"${value}" adresi FortiGate'te GERÇEKTEN engellenecek (blocklist grubuna eklenip iki yönlü deny policy uygulanacak). Emin misiniz?`,
      )
    ) {
      return;
    }
    setBlockState("loading");
    try {
      const response = await api.blockIp(value);
      setBlockState(response);
    } catch (err) {
      if (err.status === 401) {
        setAuthed(false);
        setBlockState(null);
        return;
      }
      setBlockState({ blocked: false, message: err.message ?? "İstek gönderilemedi." });
    }
  }

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
        <p className="text-sm text-muted-foreground">
          Tip: {iocType.toUpperCase()}
          {result && ` · Analiz zamanı: ${new Date(result.analyzed_at).toLocaleString("tr-TR")}`}
        </p>
      </div>

      {loading && <p className="text-sm text-muted-foreground">Analiz ediliyor, bu biraz sürebilir...</p>}
      {error && <p className="text-sm text-critical">{error}</p>}

      {result && (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => exportAnalysisPdf(result)}
              className="inline-flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2 text-sm font-medium text-foreground hover:bg-muted"
            >
              <FileDown className="h-4 w-4" />
              PDF İndir
            </button>

            {iocType === "ip" && authed && (
              <button
                type="button"
                onClick={handleBlockIp}
                disabled={blockState === "loading"}
                className="inline-flex items-center gap-2 rounded-md border border-critical/40 bg-critical/10 px-3 py-2 text-sm font-medium text-critical hover:bg-critical/20 disabled:opacity-50"
              >
                <img src="/fortigate-logo.png" alt="FortiGate" className="h-4 w-4" />
                {blockState === "loading" ? "Gönderiliyor..." : "FortiGate'e Kural Bas"}
              </button>
            )}
            {iocType === "ip" && !authed && <AdminLoginGate onSuccess={() => setAuthed(true)} />}
          </div>

          {blockState && blockState !== "loading" && (
            <p className={cn("text-sm", blockState.blocked ? "text-low" : "text-muted-foreground")}>
              {blockState.message}
            </p>
          )}

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <Card className="flex flex-col items-center justify-center gap-3 p-6 lg:col-span-1">
              <RiskGauge score={result.risk_score} />
              <Badge variant={result.severity}>
                {SEVERITY_LABEL[result.severity] ?? result.severity}
              </Badge>
            </Card>

            <Card
              className={cn(
                "border-l-4 lg:col-span-2",
                SEVERITY_BORDER[result.severity] ?? "border-l-border",
              )}
            >
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Bot className="h-4 w-4 text-primary" />
                  <CardTitle>AI SOC Analisti Raporu</CardTitle>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm leading-relaxed text-foreground">{result.llm_analysis}</p>

                {result.recommended_actions?.length > 0 && (
                  <div>
                    <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                      Önerilen Aksiyonlar
                    </p>
                    <ul className="space-y-2">
                      {result.recommended_actions.map((action, index) => (
                        <li key={index} className="flex items-start gap-2 text-sm text-foreground">
                          <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
                          <span>{action}</span>
                        </li>
                      ))}
                    </ul>
                    <p className="mt-2 text-xs italic text-muted-foreground">
                      Not: Bu öneriler LLM tarafından üretildi ve bazen hedefi doğrudan
                      yönetebileceğinizi varsayan ifadeler içerebilir. Gösterge sizin
                      kontrolünüzde değilse (çoğu durumda öyledir), sadece izleme/engelleme
                      adımlarını uygulayın.
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {result.exposed_services?.length > 0 && (
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Radar className="h-4 w-4 text-medium" />
                  <CardTitle>Açığa Çıkan Riskli Servisler</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {result.exposed_services.map((service) => (
                    <Badge key={service} variant="medium">
                      {service}
                    </Badge>
                  ))}
                </div>
                <p className="mt-2 text-xs text-muted-foreground">
                  Shodan'a göre bu hedefte açık — risk skorunu etkilemez, sadece saldırı yüzeyi
                  hakkında bilgi verir. Hedef sizin kontrolünüzde değilse doğrudan müdahale
                  edemeyebilirsiniz; izleme/engelleme önerilerine bakın.
                </p>
              </CardContent>
            </Card>
          )}

          {result.geo && (
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <MapPin className="h-4 w-4 text-primary" />
                  <CardTitle>Coğrafi Konum</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <ThreatMap
                  lat={result.geo.lat}
                  lon={result.geo.lon}
                  severity={result.severity}
                  label={[result.geo.city, result.geo.country].filter(Boolean).join(", ")}
                />
                <p className="mt-2 text-xs text-muted-foreground">
                  {[result.geo.city, result.geo.country].filter(Boolean).join(", ") || "Bilinmiyor"}
                  {" · "}
                  {result.geo.lat.toFixed(2)}, {result.geo.lon.toFixed(2)}
                </p>
              </CardContent>
            </Card>
          )}

          {result.osint_evidence.some((item) => ["virustotal", "abuseipdb"].includes(item.source)) && (
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4 text-primary" />
                  <CardTitle>Kaynak Bazlı Doğrulama</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <VendorVerdicts osintEvidence={result.osint_evidence} />
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader>
              <CardTitle>OSINT Kanıtları (ham veri)</CardTitle>
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
