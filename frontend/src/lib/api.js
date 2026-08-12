const API_BASE = "/api/v1";

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    throw new Error(body?.detail ?? `API isteği başarısız: ${res.status}`);
  }
  if (res.status === 204) return null;
  return res.json();
}

export const api = {
  health: () => request("/health"),
  analyzeIOC: (payload) =>
    request("/ioc/analyze", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  blockIp: (ipAddress) =>
    request("/actions/block-ip", {
      method: "POST",
      body: JSON.stringify({ ip_address: ipAddress }),
    }),
  listWhitelist: () => request("/whitelist"),
  addWhitelistEntry: (payload) =>
    request("/whitelist", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  deleteWhitelistEntry: (id) => request(`/whitelist/${id}`, { method: "DELETE" }),
  listHistory: (limit = 100) => request(`/history?limit=${limit}`),
};
