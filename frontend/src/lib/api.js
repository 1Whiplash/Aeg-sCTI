import { clearToken, getToken } from "./auth";

const API_BASE = "/api/v1";

async function request(path, options = {}) {
  const { headers, ...rest } = options;
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...headers },
    ...rest,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    const error = new Error(body?.detail ?? `API isteği başarısız: ${res.status}`);
    error.status = res.status;
    // Token geçersiz/süresi dolmuşsa temizle ki sayfa bir sonraki render'da
    // AdminLoginGate'i tekrar göstersin (bkz. sayfalardaki authed reset'i).
    if (res.status === 401) clearToken();
    throw error;
  }
  if (res.status === 204) return null;
  return res.json();
}

function authHeaders() {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export const api = {
  health: () => request("/health"),
  login: (username, password) =>
    request("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  analyzeIOC: (payload) =>
    request("/ioc/analyze", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  blockIp: (ipAddress) =>
    request("/actions/block-ip", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ ip_address: ipAddress }),
    }),
  listWhitelist: () => request("/whitelist"),
  addWhitelistEntry: (payload) =>
    request("/whitelist", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify(payload),
    }),
  deleteWhitelistEntry: (id) =>
    request(`/whitelist/${id}`, { method: "DELETE", headers: authHeaders() }),
  listHistory: (limit = 100, minRiskScore = null) => {
    const params = new URLSearchParams({ limit });
    if (minRiskScore !== null) params.set("min_risk_score", minRiskScore);
    return request(`/history?${params.toString()}`);
  },
  deleteHistoryEntry: (id) => request(`/history/${id}`, { method: "DELETE", headers: authHeaders() }),
  listBookmarks: () => request("/bookmarks"),
  addBookmark: (payload) =>
    request("/bookmarks", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify(payload),
    }),
  deleteBookmark: (id) => request(`/bookmarks/${id}`, { method: "DELETE", headers: authHeaders() }),
  recheckBookmark: (id) => request(`/bookmarks/${id}/recheck`, { method: "POST" }),
};
