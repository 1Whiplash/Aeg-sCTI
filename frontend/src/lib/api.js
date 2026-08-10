const API_BASE = "/api/v1";

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    throw new Error(`API isteği başarısız: ${res.status}`);
  }
  return res.json();
}

export const api = {
  health: () => request("/health"),
  analyzeIOC: (payload) =>
    request("/ioc/analyze", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
};
