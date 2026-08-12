/**
 * Boot das conversas a partir do banco.
 * Arquivo separado para evitar cache stale de sessions.js no browser.
 */

import { apiFetch } from "./api.js";
import { STORAGE_KEY } from "./constants.js";
import { store, createSession } from "./sessions.js";

const ACTIVE_KEY = "darkstar-active-session";
const MIGRATED_KEY = "darkstar-sessions-migrated-db";

function readActiveId() {
  try {
    return localStorage.getItem(ACTIVE_KEY) || null;
  } catch {
    return null;
  }
}

function writeActiveId(id) {
  try {
    if (id) localStorage.setItem(ACTIVE_KEY, id);
    else localStorage.removeItem(ACTIVE_KEY);
  } catch {
    /* ignore */
  }
}

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

async function apiList() {
  const res = await apiFetch("/api/chat-sessions");
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
      let sessions = await apiList();
      const migrated = localStorage.getItem(MIGRATED_KEY) === "1";
      if (!sessions.length && !migrated) {
        const legacy = loadLegacyLocalStore();
        if (legacy.sessions?.length) {
          await apiMigrate(legacy.sessions);
          localStorage.setItem(MIGRATED_KEY, "1");
          sessions = await apiList();
          if (legacy.activeId) writeActiveId(legacy.activeId);
        } else {
          localStorage.setItem(MIGRATED_KEY, "1");
        }
      } else if (!migrated) {
        localStorage.setItem(MIGRATED_KEY, "1");
      }

      store.sessions = sessions.map((s) => ({
        id: s.id,
        title: s.title || "novo chat",
        preferredTool: s.preferredTool || "auto",
        messages: Array.isArray(s.messages) ? s.messages : [],
        createdAt: s.createdAt || Date.now(),
        updatedAt: s.updatedAt || Date.now(),
        client_id: s.client_id || "",
      }));

      const savedActive = readActiveId();
      if (savedActive && store.sessions.some((s) => s.id === savedActive)) {
        store.activeId = savedActive;
      } else {
        store.activeId = store.sessions[0]?.id || null;
      }
      writeActiveId(store.activeId);

      if (!store.activeId) {
        createSession();
      }
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
