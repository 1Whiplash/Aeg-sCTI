import { ArrowRight, RefreshCw, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AdminLoginGate } from "@/components/ui/AdminLoginGate";
import { Badge } from "@/components/ui/Badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { api } from "@/lib/api";
import { isAuthenticated } from "@/lib/auth";

const IOC_TYPES = [
  { value: "ip", label: "IP" },
  { value: "domain", label: "Domain" },
  { value: "url", label: "URL" },
  { value: "hash", label: "Hash" },
];

const VALUE_PLACEHOLDER = {
  ip: "örn. 1.2.3.4",
  domain: "örn. example.com",
  url: "örn. https://example.com/yol",
  hash: "örn. 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0",
};

const SEVERITY_LABEL = { critical: "Kritik", high: "Yüksek", medium: "Orta", low: "Düşük" };

function DiffPanel({ diff, analysis }) {
  if (diff.is_first_check) {
    return (
      <div className="mt-2 rounded-md border border-border bg-muted/40 p-3 text-sm">
        <p className="text-muted-foreground">
          İlk kontrol — karşılaştırma için geçmiş kayıt yok. Şu anki durum:{" "}
          <span className="font-medium text-foreground">{analysis.risk_score}/100</span>{" "}
          <Badge variant={analysis.severity}>{SEVERITY_LABEL[analysis.severity] ?? analysis.severity}</Badge>
        </p>
      </div>
    );
  }

  const delta = diff.risk_score_delta;
  const deltaLabel = delta > 0 ? `+${delta}` : `${delta}`;
  const deltaColor = delta > 0 ? "text-critical" : delta < 0 ? "text-low" : "text-muted-foreground";

  return (
    <div className="mt-2 space-y-2 rounded-md border border-border bg-muted/40 p-3 text-sm">
      <p>
        Risk skoru: {diff.previous_risk_score} →{" "}
        <span className="font-medium text-foreground">{analysis.risk_score}</span>{" "}
        <span className={deltaColor}>({deltaLabel})</span>
      </p>
      {diff.severity_changed && (
        <p>
          Önem derecesi değişti:{" "}
          <Badge variant={diff.previous_severity}>
            {SEVERITY_LABEL[diff.previous_severity] ?? diff.previous_severity}
          </Badge>{" "}
          <ArrowRight className="inline h-3 w-3" />{" "}
          <Badge variant={analysis.severity}>{SEVERITY_LABEL[analysis.severity] ?? analysis.severity}</Badge>
        </p>
      )}
      {diff.virustotal_malicious_delta !== null && diff.virustotal_malicious_delta !== 0 && (
        <p className="text-muted-foreground">
          VirusTotal zararlı motor sayısı: {diff.virustotal_malicious_delta > 0 ? "+" : ""}
          {diff.virustotal_malicious_delta}
        </p>
      )}
      {diff.new_exposed_services.length > 0 && (
        <p className="text-muted-foreground">
          Yeni açık servis: <span className="text-foreground">{diff.new_exposed_services.join(", ")}</span>
        </p>
      )}
      {diff.removed_exposed_services.length > 0 && (
        <p className="text-muted-foreground">
          Artık açık olmayan servis:{" "}
          <span className="text-foreground">{diff.removed_exposed_services.join(", ")}</span>
        </p>
      )}
      {!diff.severity_changed &&
        delta === 0 &&
        diff.new_exposed_services.length === 0 &&
        diff.removed_exposed_services.length === 0 &&
        (diff.virustotal_malicious_delta === null || diff.virustotal_malicious_delta === 0) && (
          <p className="text-muted-foreground">Son kontrolden bu yana anlamlı bir değişiklik yok.</p>
        )}
      <p className="text-xs text-muted-foreground">
        Önceki kontrol: {new Date(diff.previous_checked_at).toLocaleString("tr-TR")}
      </p>
    </div>
  );
}

export default function Bookmarks() {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [form, setForm] = useState({ value: "", ioc_type: "ip", display_name: "", notes: "" });
  const [submitting, setSubmitting] = useState(false);
  const [authed, setAuthed] = useState(isAuthenticated());
  const [recheckingId, setRecheckingId] = useState(null);
  const [results, setResults] = useState({}); // { [bookmarkId]: { diff, analysis } }
  const navigate = useNavigate();

  function loadEntries() {
    setLoading(true);
    api
      .listBookmarks()
      .then(setEntries)
      .catch(() => setError("İzleme listesi yüklenemedi."))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    loadEntries();
  }, []);

  async function handleSubmit(event) {
    event.preventDefault();
    if (!form.value.trim() || !form.display_name.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      await api.addBookmark({
        value: form.value.trim(),
        ioc_type: form.ioc_type,
        display_name: form.display_name.trim(),
        notes: form.notes.trim() || null,
      });
      setForm({ value: "", ioc_type: "ip", display_name: "", notes: "" });
      loadEntries();
    } catch (err) {
      setError(err.message);
      if (err.status === 401) setAuthed(false);
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDelete(id, displayName) {
    if (!window.confirm(`"${displayName}" izleme listesinden silinsin mi?`)) return;
    try {
      await api.deleteBookmark(id);
      setEntries((prev) => prev.filter((entry) => entry.id !== id));
    } catch (err) {
      setError(err.status === 401 ? "Oturum süresi doldu, tekrar giriş yapın." : "Kayıt silinemedi.");
      if (err.status === 401) setAuthed(false);
    }
  }

  async function handleRecheck(id) {
    setRecheckingId(id);
    try {
      const response = await api.recheckBookmark(id);
      setResults((prev) => ({ ...prev, [id]: response }));
    } catch {
      setError("Yeniden kontrol başarısız oldu.");
    } finally {
      setRecheckingId(null);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-foreground">İzleme Listesi</h1>
        <p className="text-sm text-muted-foreground">
          Takip etmek istediğin göstergeleri isimlendirerek kaydet. "Kontrol Et" ile taze bir analiz
          çalıştırıp bir önceki kontrolden bu yana ne değiştiğini gör.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>İzlemeye Al</CardTitle>
        </CardHeader>
        <CardContent>
          {!authed && <AdminLoginGate onSuccess={() => setAuthed(true)} />}
          {authed && (
            <form onSubmit={handleSubmit} className="flex flex-wrap items-end gap-3">
              <div className="flex flex-col gap-1">
                <label className="text-xs text-muted-foreground">Değer</label>
                <input
                  value={form.value}
                  onChange={(e) => setForm({ ...form, value: e.target.value })}
                  placeholder={VALUE_PLACEHOLDER[form.ioc_type]}
                  className="w-56 rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono text-xs"
                />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs text-muted-foreground">Tip</label>
                <select
                  value={form.ioc_type}
                  onChange={(e) => setForm({ ...form, ioc_type: e.target.value })}
                  className="rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                >
                  {IOC_TYPES.map((t) => (
                    <option key={t.value} value={t.value}>
                      {t.label}
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs text-muted-foreground">İsim</label>
                <input
                  value={form.display_name}
                  onChange={(e) => setForm({ ...form, display_name: e.target.value })}
                  placeholder="örn. Şüpheli C2 adayı"
                  className="w-56 rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs text-muted-foreground">Not (opsiyonel)</label>
                <input
                  value={form.notes}
                  onChange={(e) => setForm({ ...form, notes: e.target.value })}
                  placeholder="örn. 12.08 loglarında görüldü"
                  className="w-56 rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
              <button
                type="submit"
                disabled={submitting}
                className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:opacity-90 disabled:opacity-50"
              >
                {submitting ? "Ekleniyor..." : "Ekle"}
              </button>
            </form>
          )}
          {error && <p className="mt-2 text-sm text-critical">{error}</p>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Takip Edilenler</CardTitle>
        </CardHeader>
        <CardContent>
          {loading && <p className="text-sm text-muted-foreground">Yükleniyor...</p>}
          {!loading && entries.length === 0 && (
            <p className="text-sm text-muted-foreground">Henüz izlemeye alınan gösterge yok.</p>
          )}
          {!loading && entries.length > 0 && (
            <div className="space-y-3">
              {entries.map((entry) => (
                <div key={entry.id} className="rounded-md border border-border p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <p className="font-medium text-foreground">{entry.display_name}</p>
                      <p className="break-all text-xs text-muted-foreground">
                        {entry.value} · {entry.ioc_type.toUpperCase()}
                        {entry.notes && ` · ${entry.notes}`}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() =>
                          navigate(`/investigate?value=${encodeURIComponent(entry.value)}&type=${entry.ioc_type}`)
                        }
                        className="text-xs text-muted-foreground hover:text-foreground"
                      >
                        Detaya git
                      </button>
                      <button
                        type="button"
                        onClick={() => handleRecheck(entry.id)}
                        disabled={recheckingId === entry.id}
                        className="inline-flex items-center gap-1.5 rounded-md border border-border bg-card px-3 py-1.5 text-xs font-medium text-foreground hover:bg-muted disabled:opacity-50"
                      >
                        <RefreshCw className={recheckingId === entry.id ? "h-3.5 w-3.5 animate-spin" : "h-3.5 w-3.5"} />
                        {recheckingId === entry.id ? "Kontrol ediliyor..." : "Kontrol Et"}
                      </button>
                      {authed && (
                        <button
                          type="button"
                          onClick={() => handleDelete(entry.id, entry.display_name)}
                          className="text-muted-foreground hover:text-critical"
                          aria-label="Sil"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      )}
                    </div>
                  </div>
                  {results[entry.id] && (
                    <DiffPanel diff={results[entry.id].diff} analysis={results[entry.id].analysis} />
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
