import { Lock } from "lucide-react";
import { useState } from "react";
import { api } from "@/lib/api";
import { setToken } from "@/lib/auth";

/** Whitelist yazma / FortiGate aksiyonu gibi korumalı işlemler için küçük bir
 * admin girişi istemi. Giriş başarılı olunca `onSuccess` çağrılır. */
export function AdminLoginGate({ onSuccess }) {
  const [showForm, setShowForm] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  if (!showForm) {
    return (
      <button
        type="button"
        onClick={() => setShowForm(true)}
        className="inline-flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2 text-sm font-medium text-muted-foreground hover:bg-muted"
      >
        <Lock className="h-4 w-4" />
        Bu işlem için yönetici girişi gerekiyor
      </button>
    );
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const res = await api.login(username, password);
      setToken(res.access_token);
      onSuccess();
    } catch {
      setError("Kullanıcı adı veya şifre hatalı.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-wrap items-center gap-2">
      <input
        value={username}
        onChange={(event) => setUsername(event.target.value)}
        placeholder="Kullanıcı adı"
        className="w-32 rounded-md border border-border bg-background px-2 py-1.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
      />
      <input
        type="password"
        value={password}
        onChange={(event) => setPassword(event.target.value)}
        placeholder="Şifre"
        className="w-32 rounded-md border border-border bg-background px-2 py-1.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
      />
      <button
        type="submit"
        disabled={submitting}
        className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:opacity-90 disabled:opacity-50"
      >
        {submitting ? "..." : "Giriş"}
      </button>
      {error && <span className="text-xs text-critical">{error}</span>}
    </form>
  );
}
