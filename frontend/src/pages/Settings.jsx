import { Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { api } from "@/lib/api";

const IOC_TYPES = [
  { value: "ip", label: "IP" },
  { value: "domain", label: "Domain" },
  { value: "url", label: "URL" },
  { value: "hash", label: "Hash" },
];

export default function Settings() {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [form, setForm] = useState({ value: "", ioc_type: "ip", reason: "" });
  const [submitting, setSubmitting] = useState(false);

  function loadEntries() {
    setLoading(true);
    api
      .listWhitelist()
      .then(setEntries)
      .catch(() => setError("Whitelist yüklenemedi."))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    loadEntries();
  }, []);

  async function handleSubmit(event) {
    event.preventDefault();
    if (!form.value.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      await api.addWhitelistEntry({
        value: form.value.trim(),
        ioc_type: form.ioc_type,
        reason: form.reason.trim() || null,
      });
      setForm({ value: "", ioc_type: "ip", reason: "" });
      loadEntries();
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDelete(id) {
    try {
      await api.deleteWhitelistEntry(id);
      setEntries((prev) => prev.filter((entry) => entry.id !== id));
    } catch {
      setError("Kayıt silinemedi.");
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-foreground">Ayarlar</h1>
        <p className="text-sm text-muted-foreground">
          Güvenli kabul edilen IP/domain'leri (whitelist) burada yönetebilirsin — bu listedeki
          göstergeler analiz edildiğinde risk skoru her zaman 0 döner.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Whitelist'e Ekle</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="flex flex-wrap items-end gap-3">
            <div className="flex flex-col gap-1">
              <label className="text-xs text-muted-foreground">Değer</label>
              <input
                value={form.value}
                onChange={(e) => setForm({ ...form, value: e.target.value })}
                placeholder="örn. 8.8.8.8"
                className="w-56 rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
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
              <label className="text-xs text-muted-foreground">Neden (opsiyonel)</label>
              <input
                value={form.reason}
                onChange={(e) => setForm({ ...form, reason: e.target.value })}
                placeholder="örn. Google DNS"
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
          {error && <p className="mt-2 text-sm text-critical">{error}</p>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Whitelist Kayıtları</CardTitle>
        </CardHeader>
        <CardContent>
          {loading && <p className="text-sm text-muted-foreground">Yükleniyor...</p>}
          {!loading && entries.length === 0 && (
            <p className="text-sm text-muted-foreground">Henüz whitelist kaydı yok.</p>
          )}
          {!loading && entries.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-border text-muted-foreground">
                    <th className="py-2 pr-4 font-medium">Değer</th>
                    <th className="py-2 pr-4 font-medium">Tip</th>
                    <th className="py-2 pr-4 font-medium">Neden</th>
                    <th className="py-2 pr-4 font-medium">Eklenme</th>
                    <th className="py-2 font-medium" />
                  </tr>
                </thead>
                <tbody>
                  {entries.map((entry) => (
                    <tr key={entry.id} className="border-b border-border/50">
                      <td className="py-2 pr-4 text-foreground">{entry.value}</td>
                      <td className="py-2 pr-4 text-muted-foreground">
                        {entry.ioc_type.toUpperCase()}
                      </td>
                      <td className="py-2 pr-4 text-muted-foreground">{entry.reason ?? "—"}</td>
                      <td className="py-2 pr-4 text-muted-foreground">
                        {new Date(entry.created_at).toLocaleDateString("tr-TR")}
                      </td>
                      <td className="py-2 text-right">
                        <button
                          type="button"
                          onClick={() => handleDelete(entry.id)}
                          className="text-muted-foreground hover:text-critical"
                          aria-label="Sil"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
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
