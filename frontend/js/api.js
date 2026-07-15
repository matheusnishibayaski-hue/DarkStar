import { API_TOKEN_KEY } from "./constants.js";

export function apiHeaders(extra = {}) {
  const headers = { ...extra };
  const token = localStorage.getItem(API_TOKEN_KEY);
  if (token) headers["X-Chat-Token"] = token;
  return headers;
}

export function apiFetch(url, options = {}) {
  const headers = apiHeaders(options.headers || {});
  if (options.body && !headers["Content-Type"] && !(options.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }
  return fetch(url, { ...options, headers, credentials: "include" });
}

export function logStreamUrl(executionId) {
  const token = localStorage.getItem(API_TOKEN_KEY);
  let url = `/api/logs/stream/${encodeURIComponent(executionId)}`;
  if (token) url += `?token=${encodeURIComponent(token)}`;
  return url;
}

export async function checkClientConfig(toast) {
  try {
    const res = await fetch("/api/client-config", { credentials: "include" });
    if (!res.ok) return;
    const cfg = await res.json();
    if (cfg.authRequired) {
      const { ensureAuth } = await import("./auth.js");
      await ensureAuth(toast);
    }
  } catch { /* ignore */ }
}

export async function consumeSseStream(response, handlers, { signal } = {}) {
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  try {
    while (true) {
      if (signal?.aborted) break;
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const parts = buffer.split("\n\n");
      buffer = parts.pop() || "";

      for (const part of parts) {
        if (!part.trim() || part.trim().startsWith(":")) continue;
        let event = "message";
        let dataStr = "";
        for (const line of part.split("\n")) {
          if (line.startsWith("event:")) event = line.slice(6).trim();
          else if (line.startsWith("data:")) dataStr = line.slice(5).trim();
        }
        if (!dataStr) continue;
        try {
          const data = JSON.parse(dataStr);
          handlers[event]?.(data);
        } catch { /* ignore malformed */ }
      }
    }
  } finally {
    try {
      reader.cancel();
    } catch { /* ignore */ }
  }
}
