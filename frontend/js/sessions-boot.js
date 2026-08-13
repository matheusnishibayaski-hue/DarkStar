/**
 * Boot das conversas a partir do banco.
 * Arquivo separado para evitar cache stale de sessions.js no browser.
 */

import { apiFetch } from "./api.js";
import { STORAGE_KEY } from "./constants.js";
import {
  store,
  createSession,
  applyLoadedSessions,
  currentClientId,
} from "./sessions.js";

const MIGRATED_KEY = "darkstar-sessions-migrated-db";

function loadLegacyLocalStore() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) return JSON.parse(raw);
  } catch {
    /* ignore */
  }
  try {
    const legacy = localStorage.getItem("chat-ia-kali-sessions");
    if (legacy) return JSON.parse(legacy);
  } catch {
    /* ignore */
  }
  return { sessions: [], activeId: null };
}

async function apiListAll() {
  const res = await apiFetch("/api/chat-sessions");
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "falha ao listar conversas");
  }
  const data = await res.json();
  return data.sessions || [];
}

async function apiListForClient(clientId) {
  const cid = clientId || "default";
  const res = await apiFetch(`/api/chat-sessions?client_id=${encodeURIComponent(cid)}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "falha ao listar conversas");
  }
  const data = await res.json();
  return data.sessions || [];
}

async function apiMigrate(sessions) {
  const res = await apiFetch("/api/chat-sessions/migrate", {
    method: "POST",
    body: JSON.stringify({ sessions }),
  });
  if (!res.ok) return null;
  return res.json();
}

let bootPromise = null;

/** Carrega conversas do banco; migra localStorage uma vez se o DB estiver vazio. */
export async function bootSessionsFromDb() {
  if (bootPromise) return bootPromise;
  bootPromise = (async () => {
    try {
      const cid = currentClientId();
      let all = await apiListAll();
      const migrated = localStorage.getItem(MIGRATED_KEY) === "1";
      if (!all.length && !migrated) {
        const legacy = loadLegacyLocalStore();
        if (legacy.sessions?.length) {
          await apiMigrate(legacy.sessions);
          localStorage.setItem(MIGRATED_KEY, "1");
        } else {
          localStorage.setItem(MIGRATED_KEY, "1");
        }
      } else if (!migrated) {
        localStorage.setItem(MIGRATED_KEY, "1");
      }

      const sessions = await apiListForClient(cid);
      applyLoadedSessions(sessions, cid);
    } catch (err) {
      console.warn("chat_boot_db_failed_fallback_local", err);
      const legacy = loadLegacyLocalStore();
      store.sessions = legacy.sessions || [];
      store.activeId = legacy.activeId || store.sessions[0]?.id || null;
      if (!store.activeId) createSession();
    }
  })();
  return bootPromise;
}
