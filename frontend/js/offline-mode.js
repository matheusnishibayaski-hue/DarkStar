/** Modo offline — LLM local via Ollama (air-gapped). */

import { OFFLINE_MODE_STORAGE_KEY } from "./constants.js";
import { apiFetch } from "./api.js";
import { toast } from "./ui.js";
import { loadModels, selectDefaultModelFromCatalog } from "./tools-panel.js";

/** @type {HTMLInputElement | null} */
let toggleEl = null;
/** @type {Set<(on: boolean) => void>} */
const listeners = new Set();

export function isOfflineModeEnabled() {
  if (toggleEl) return Boolean(toggleEl.checked);
  return loadOfflinePreference();
}

export function loadOfflinePreference() {
  try {
    return localStorage.getItem(OFFLINE_MODE_STORAGE_KEY) === "1";
  } catch {
    return false;
  }
}

function saveOfflinePreference(on) {
  try {
    localStorage.setItem(OFFLINE_MODE_STORAGE_KEY, on ? "1" : "0");
  } catch {
    /* ignore */
  }
}

export function applyOfflineTheme(on) {
  document.documentElement.classList.toggle("mode-offline", on);
}

export function onOfflineModeChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function notifyListeners(on) {
  for (const fn of listeners) {
    try {
      fn(on);
    } catch {
      /* ignore */
    }
  }
}

/**
 * @param {boolean} on
 * @param {{ silent?: boolean, persistServer?: boolean }} [opts]
 */
export async function setOfflineMode(on, { silent = false, persistServer = true } = {}) {
  const enabled = Boolean(on);
  if (toggleEl) toggleEl.checked = enabled;
  saveOfflinePreference(enabled);
  applyOfflineTheme(enabled);
  notifyListeners(enabled);

  if (persistServer) {
    try {
      const res = await apiFetch("/api/ai-provider", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: enabled ? "ollama" : "openrouter" }),
      });
      if (!res.ok) {
        const detail = await res.text();
        throw new Error(detail || `HTTP ${res.status}`);
      }
      const data = await res.json();
      const llmOk = data?.llm?.ok !== false;
      await loadModels();
      selectDefaultModelFromCatalog?.();
      if (!silent) {
        if (enabled) {
          toast(
            llmOk
              ? "Modo offline — Argus via Ollama local"
              : "Offline ativo, mas Ollama não respondeu — confira se o daemon está rodando",
            llmOk ? "success" : "warn",
          );
        } else {
          toast("Modo online — Argus via OpenRouter", "success");
        }
      } else if (enabled && !llmOk) {
        toast("Ollama offline — inicie o daemon ou desligue o modo offline", "warn");
      }
    } catch (err) {
      if (!silent) {
        toast(`Falha ao alternar provedor: ${err?.message || err}`, "error");
      }
    }
  }
}

/**
 * @param {HTMLInputElement | null} input
 */
export function initOfflineMode(input) {
  toggleEl = input;
  if (!input) {
    applyOfflineTheme(loadOfflinePreference());
    return;
  }

  // Preferência local → sincroniza no servidor; se não houver, lê o servidor
  void (async () => {
    const localPref = loadOfflinePreference();
    try {
      const res = await apiFetch("/api/ai-provider");
      if (res.ok) {
        const data = await res.json();
        const serverOffline = Boolean(data.offline || data.provider === "ollama");
        // localStorage vence na 1ª pintura da sessão do browser
        const wantOffline = localPref || serverOffline;
        await setOfflineMode(wantOffline, { silent: true, persistServer: true });
        return;
      }
    } catch {
      /* ignore */
    }
    await setOfflineMode(localPref, { silent: true, persistServer: true });
  })();

  input.addEventListener("change", () => {
    void setOfflineMode(input.checked);
  });
}
