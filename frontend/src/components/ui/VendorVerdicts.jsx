import { ChevronDown, ChevronUp } from "lucide-react";
import { useState } from "react";
import { Badge } from "@/components/ui/Badge";

/** VirusTotal `last_analysis_results` motor adı -> {category, result} sözlüğünü
 * category'ye göre gruplar, her grubu isim listesine çevirir. */
function groupVtEngines(lastAnalysisResults) {
  const groups = { malicious: [], suspicious: [], harmless: [], undetected: [] };
  for (const [engineName, verdict] of Object.entries(lastAnalysisResults ?? {})) {
    const bucket = groups[verdict?.category];
    if (bucket) bucket.push(engineName);
  }
  for (const key of Object.keys(groups)) groups[key].sort();
  return groups;
}

function EngineGroup({ label, engines, variant }) {
  if (engines.length === 0) return null;
  return (
    <div>
      <p className="mb-1 text-xs font-semibold text-muted-foreground">
        {label} ({engines.length})
      </p>
      <div className="flex flex-wrap gap-1.5">
        {engines.map((name) => (
          <Badge key={name} variant={variant}>
            {name}
          </Badge>
        ))}
      </div>
    </div>
  );
}

function VirusTotalVerdicts({ data }) {
  const results = data?.data?.attributes?.last_analysis_results;
  if (!results) return null;
  const groups = groupVtEngines(results);
  const [showClean, setShowClean] = useState(false);
  const cleanCount = groups.harmless.length + groups.undetected.length;

  return (
    <div className="space-y-3">
      <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        VirusTotal Motor Sonuçları
      </p>
      {groups.malicious.length === 0 && groups.suspicious.length === 0 && (
        <p className="text-sm text-muted-foreground">Hiçbir motor zararlı/şüpheli işaretlemedi.</p>
      )}
      <EngineGroup label="Zararlı" engines={groups.malicious} variant="critical" />
      <EngineGroup label="Şüpheli" engines={groups.suspicious} variant="medium" />

      {cleanCount > 0 && (
        <div>
          <button
            type="button"
            onClick={() => setShowClean((v) => !v)}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
          >
            {showClean ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
            Temiz / taranmadı motorları göster ({cleanCount})
          </button>
          {showClean && (
            <div className="mt-2 space-y-3">
              <EngineGroup label="Temiz" engines={groups.harmless} variant="low" />
              <EngineGroup label="Taranmadı" engines={groups.undetected} variant="default" />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

const ABUSE_CATEGORY_LABELS = {
  1: "DNS Uzlaşması", 2: "DDoS Saldırısı", 3: "Kötü Amaçlı Yazılım", 4: "Kimlik Avı",
  5: "Kaba Kuvvet (Fraud Orders)", 6: "Sahte Sipariş", 7: "DDoS Saldırısı", 8: "Kötüye Kullanım (FTP)",
  9: "Kimlik Bilgisi Hırsızlığı", 10: "Ping Taraması", 11: "Kaba Kuvvet Girişi (SSH)",
  12: "Kaba Kuvvet Girişi", 13: "Kaba Kuvvet Girişi (FTP)", 14: "Port Taraması", 15: "Hack Girişimi",
  16: "SQL Enjeksiyonu", 17: "Sahtecilik", 18: "Kaba Kuvvet Saldırısı", 19: "Kötüye Kullanım (VoIP)",
  20: "Zararlı İçerik Barındırma", 21: "DDoS Saldırısı", 22: "Kaba Kuvvet Girişi (SSH)",
  23: "IoT Hedefli Saldırı", 24: "Spam", 27: "Web Kırılganlığı Taraması",
};

function AbuseIPDBVerdicts({ data }) {
  const reports = data?.data?.reports;
  if (!Array.isArray(reports) || reports.length === 0) return null;

  const categoryCounts = new Map();
  for (const report of reports) {
    for (const catId of report.categories ?? []) {
      const label = ABUSE_CATEGORY_LABELS[catId] ?? `Kategori ${catId}`;
      categoryCounts.set(label, (categoryCounts.get(label) ?? 0) + 1);
    }
  }

  return (
    <div className="space-y-2">
      <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        AbuseIPDB Şikayet Kategorileri ({reports.length} rapor)
      </p>
      <div className="flex flex-wrap gap-1.5">
        {Array.from(categoryCounts.entries()).map(([label, count]) => (
          <Badge key={label} variant="high">
            {label} ({count})
          </Badge>
        ))}
      </div>
      <p className="text-xs italic text-muted-foreground">
        AbuseIPDB, rapor edeni anonimleştirir — "kim" yerine "hangi tür şikayet" bilgisi verilir.
      </p>
    </div>
  );
}

/** OSINT kanıtları içindeki VirusTotal/AbuseIPDB motor/kaynak bazlı doğrulamalarını
 * okunaklı bir özet olarak gösterir. Hiçbir tanınan kaynak yoksa null döner. */
export function VendorVerdicts({ osintEvidence }) {
  const vt = osintEvidence?.find((item) => item.source === "virustotal");
  const abuse = osintEvidence?.find((item) => item.source === "abuseipdb");

  const hasVt = Boolean(vt?.raw_data?.data?.attributes?.last_analysis_results);
  const hasAbuse = Array.isArray(abuse?.raw_data?.data?.reports) && abuse.raw_data.data.reports.length > 0;

  if (!hasVt && !hasAbuse) return null;

  return (
    <div className="space-y-4">
      {hasVt && <VirusTotalVerdicts data={vt.raw_data} />}
      {hasAbuse && <AbuseIPDBVerdicts data={abuse.raw_data} />}
    </div>
  );
}
