import { STORAGE_KEY, ARGUS_WELCOME_MESSAGE, API_TOKEN_KEY } from "./constants.js";
import { apiFetch } from "./api.js";
import { escapeHtml } from "./exec.js";
import { getActiveClientId } from "./client-workspace.js";
import { isSessionBusy } from "./session-runs.js";

/** @type {{ sessionsEl: HTMLElement, sessionTitleEl: HTMLElement, onChanged?: () => void }} */
let ctx = {};

export let store = { sessions: [], activeId: null };

const ACTIVE_KEY = "darkstar-active-session";
const MIGRATED_KEY = "darkstar-sessions-migrated-db";
let saveTimer = null;
let bootPromise = null;

export function currentClientId() {
  try {
    return getActiveClientId() || localStorage.getItem("darkstar.active_client_id") || "default";
  } catch {
    return "default";
  }
}

export function initSessions(context) {
  ctx = context;
  window.addEventListener("darkstar:client-changed", (e) => {
    const cid = e.detail?.clientId || currentClientId();
    reloadSessionsForClient(cid).catch((err) => console.warn("chat_reload_client_failed", err));
  });
}

function uid() {
  return crypto.randomUUID?.() || `s-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function readActiveId(clientId = currentClientId()) {
  try {
    const keyed = localStorage.getItem(`${ACTIVE_KEY}:${clientId || "default"}`);
    if (keyed) return keyed;
    if ((clientId || "default") === "default") {
      return localStorage.getItem(ACTIVE_KEY) || null;
    }
  } catch {
    /* ignore */
  }
  return null;
}

function writeActiveId(id, clientId = currentClientId()) {
  try {
    const key = `${ACTIVE_KEY}:${clientId || "default"}`;
    if (id) localStorage.setItem(key, id);
    else localStorage.removeItem(key);
    if ((clientId || "default") === "default") {
      if (id) localStorage.setItem(ACTIVE_KEY, id);
      else localStorage.removeItem(ACTIVE_KEY);
    }
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

function sessionPayload(session) {
  const messages = (session.messages || []).filter((m) => m?.kind !== "pending-attachments");
  const pending = Array.isArray(session.pendingAttachments) ? session.pendingAttachments : [];
  if (pending.length) {
    messages.push({
      role: "system",
      kind: "pending-attachments",
      content: "",
      attachments: pending.map((a) => ({
        name: String(a?.name || "").slice(0, 256),
        content: String(a?.content || "").slice(0, 200000),
      })),
      at: Date.now(),
    });
  }
  return {
    id: session.id,
    title: session.title || "novo chat",
    preferredTool: session.preferredTool || "auto",
    messages,
    createdAt: session.createdAt || Date.now(),
    updatedAt: session.updatedAt || Date.now(),
    client_id: session.client_id || currentClientId() || "default",
  };
}

async function apiUpsert(session) {
  const res = await apiFetch(`/api/chat-sessions/${encodeURIComponent(session.id)}`, {
    method: "PUT",
    body: JSON.stringify(sessionPayload(session)),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "falha ao salvar conversa");
  }
  return res.json();
}

async function apiDelete(sessionId) {
  const res = await apiFetch(`/api/chat-sessions/${encodeURIComponent(sessionId)}`, {
    method: "DELETE",
  });
  if (!res.ok && res.status !== 404) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "falha ao excluir conversa");
  }
}

async function apiList(clientId = currentClientId()) {
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

/** Persiste no banco (debounced). Mantém API sync para callers existentes. */
export function saveStore() {
  writeActiveId(store.activeId);
  const session = getActiveSession();
  if (!session) return;
  session.updatedAt = Date.now();
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    apiUpsert(session).catch((err) => {
      console.warn("chat_persist_failed", err);
    });
  }, 350);
}

/** Flush imediato (create/rename/delete / F5). */
export async function saveStoreNow(session = getActiveSession()) {
  writeActiveId(store.activeId);
  if (!session) return;
  session.updatedAt = Date.now();
  if (saveTimer) {
    clearTimeout(saveTimer);
    saveTimer = null;
  }
  await apiUpsert(session);
}

/** Flush síncrono no unload (keepalive) — evita perder última mensagem no F5. */
export function flushStoreOnUnload() {
  writeActiveId(store.activeId);
  const session = getActiveSession();
  if (!session) return;
  if (saveTimer) {
    clearTimeout(saveTimer);
    saveTimer = null;
  }
  session.updatedAt = Date.now();
  try {
    const body = JSON.stringify(sessionPayload(session));
    const headers = { "Content-Type": "application/json" };
    try {
      const token = localStorage.getItem(API_TOKEN_KEY);
      if (token) headers["X-Chat-Token"] = token;
    } catch { /* ignore */ }
    void fetch(`/api/chat-sessions/${encodeURIComponent(session.id)}`, {
      method: "PUT",
      headers,
      body,
      credentials: "include",
      keepalive: true,
    }).catch(() => {
      /* unload/tab-hide: browser often aborts; ignore Failed to fetch */
    });
  } catch (err) {
    console.warn("chat_unload_flush_failed", err);
  }
}

let unloadHooked = false;
export function hookSessionUnloadFlush() {
  if (unloadHooked || typeof window === "undefined") return;
  unloadHooked = true;
  const flush = () => flushStoreOnUnload();
  window.addEventListener("pagehide", flush);
  window.addEventListener("beforeunload", flush);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") flush();
  });
}

export function getActiveSession() {
  return store.sessions.find((s) => s.id === store.activeId) || null;
}

export function getSessionById(id) {
  return store.sessions.find((s) => s.id === id) || null;
}

export function createSession() {
  const session = {
    id: uid(),
    title: "novo chat",
    createdAt: Date.now(),
    updatedAt: Date.now(),
    preferredTool: "auto",
    client_id: currentClientId() || "default",
    pendingAttachments: [],
    messages: [
      {
        role: "assistant",
        content: ARGUS_WELCOME_MESSAGE,
        at: Date.now(),
        toolExecutions: [],
      },
    ],
  };
  store.sessions.unshift(session);
  store.activeId = session.id;
  writeActiveId(session.id);
  saveStoreNow(session).catch((err) => console.warn("chat_create_failed", err));
  return session;
}

export function ensureSession() {
  if (!getActiveSession()) createSession();
}

function mapSessionRow(s) {
  const raw = Array.isArray(s.messages) ? s.messages : [];
  const pendingMsg = raw.find((m) => m?.kind === "pending-attachments");
  const messages = raw.filter((m) => m?.kind !== "pending-attachments");
  const pending = Array.isArray(pendingMsg?.attachments) ? pendingMsg.attachments : [];
  return {
    id: s.id,
    title: s.title || "novo chat",
    preferredTool: s.preferredTool || "auto",
    messages,
    createdAt: s.createdAt || Date.now(),
    updatedAt: s.updatedAt || Date.now(),
    client_id: s.client_id || "default",
    pendingAttachments: pending,
  };
}

export function applyLoadedSessions(sessions, clientId = currentClientId()) {
  store.sessions = (sessions || []).map(mapSessionRow);
  const savedActive = readActiveId(clientId);
  if (savedActive && store.sessions.some((s) => s.id === savedActive)) {
    store.activeId = savedActive;
  } else {
    store.activeId = store.sessions[0]?.id || null;
  }
  writeActiveId(store.activeId, clientId);
  if (!store.activeId) createSession();
}

export async function reloadSessionsForClient(clientId = currentClientId()) {
  try {
    const sessions = await apiList(clientId);
    applyLoadedSessions(sessions, clientId);
    renderSessions();
    updateSessionTitle();
    ctx.afterSwitchSession?.(store.activeId);
  } catch (err) {
    console.warn("chat_reload_client_failed", err);
    ctx.onReloadError?.(err);
  }
}

/**
 * Carrega conversas do banco; migra localStorage uma vez se o DB estiver vazio.
 * Chamar no boot (main.js) antes de renderizar.
 */
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
        client_id: s.client_id || "default",
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

export function sessionTitle(session) {
  if (session?.title && session.title !== "novo chat") return session.title;
  const first = session?.messages?.find((m) => m.role === "user");
  if (first) {
    const line = first.content.split("\n")[0];
    return line.slice(0, 48) + (line.length > 48 ? "…" : "");
  }
  return "novo chat";
}

function sessionInitial(session) {
  const title = sessionTitle(session).trim();
  if (!title) return "?";
  return title[0].toUpperCase();
}

export function formatRelativeTime(ts) {
  const diff = Date.now() - ts;
  const min = Math.floor(diff / 60000);
  if (min < 1) return "agora";
  if (min < 60) return `${min}m`;
  const h = Math.floor(min / 60);
  if (h < 24) return `${h}h`;
  return `${Math.floor(h / 24)}d`;
}

export function collectSessionExecutions(session) {
  const all = [];
  for (const msg of session?.messages || []) {
    if (msg.role === "assistant" && msg.toolExecutions?.length) {
      all.push(...msg.toolExecutions);
    }
  }
  return all;
}

/** Execuções com carimbo de data da mensagem do assistente. */
export function collectSessionExecutionsDetailed(session) {
  const all = [];
  for (const msg of session?.messages || []) {
    if (msg.role === "assistant" && msg.toolExecutions?.length) {
      const at = msg.at || session.updatedAt;
      for (const ex of msg.toolExecutions) {
        all.push({ ...ex, executedAt: at });
      }
    }
  }
  return all;
}

export function collectSessionHistory(session) {
  return (session?.messages || [])
    .filter((m) => m && m.kind !== "folder-ingest" && m.kind !== "pending-attachments" && m.role !== "system")
    .map((m) => ({ role: m.role, content: m.content }));
}

export function updateSessionTitle() {
  const session = getActiveSession();
  const title = session ? sessionTitle(session) : "chat";
  if (ctx.sessionTitleEl) {
    ctx.sessionTitleEl.textContent = title;
  }
  document.title = `${title} — DarkStar`;
}

export function collectSessionLogIds(session) {
  const ids = new Set();
  for (const ex of collectSessionExecutions(session)) {
    if (ex.log_file_id) ids.add(ex.log_file_id);
  }
  return [...ids];
}

export function renameSession(id, newTitle) {
  const session = store.sessions.find((s) => s.id === id);
  if (!session) return false;
  const trimmed = (newTitle || "").trim().slice(0, 80);
  session.title = trimmed || "novo chat";
  session.updatedAt = Date.now();
  saveStoreNow(session).catch((err) => console.warn("chat_rename_failed", err));
  renderSessions();
  if (store.activeId === id) updateSessionTitle();
  ctx.onChanged?.();
  return true;
}

function beginRenameSession(sessionId, anchorEl) {
  const session = store.sessions.find((s) => s.id === sessionId);
  const item = anchorEl?.closest?.(".history-item");
  if (!session || !item) return;

  const titleEl = item.querySelector(".history-item-title");
  if (!titleEl || item.querySelector(".history-item-rename-input")) return;

  const input = document.createElement("input");
  input.type = "text";
  input.className = "history-item-rename-input";
  input.value = sessionTitle(session);
  input.maxLength = 80;
  input.setAttribute("aria-label", "Nome da conversa");
  titleEl.replaceWith(input);
  input.focus();
  input.select();

  let done = false;
  const finish = (save) => {
    if (done) return;
    done = true;
    if (save) renameSession(sessionId, input.value);
    else renderSessions();
  };

  input.addEventListener("click", (e) => e.stopPropagation());
  input.addEventListener("keydown", (e) => {
    e.stopPropagation();
    if (e.key === "Enter") {
      e.preventDefault();
      finish(true);
    } else if (e.key === "Escape") {
      e.preventDefault();
      finish(false);
    }
  });
  input.addEventListener("blur", () => finish(true));
}

export function deleteSession(id, e) {
  e?.preventDefault?.();
  e?.stopPropagation?.();
  if (!id) return;
  const session = store.sessions.find((s) => s.id === id);
  const label = session ? sessionTitle(session) : id.slice(0, 8);
  if (!window.confirm(`Excluir a conversa "${label}"?`)) return;
  const logIds = session ? collectSessionLogIds(session) : [];
  try {
    ctx.beforeDeleteSession?.(id, logIds);
  } catch (err) {
    console.warn("before_delete_session_failed", err);
  }
  store.sessions = store.sessions.filter((s) => s.id !== id);
  if (store.activeId === id) {
    store.activeId = store.sessions[0]?.id || null;
    writeActiveId(store.activeId);
    if (!store.activeId) createSession();
  } else {
    writeActiveId(store.activeId);
  }
  renderSessions();
  updateSessionTitle();
  ctx.afterDeleteSession?.();
  apiDelete(id).catch((err) => console.warn("chat_delete_failed", err));
}

export function switchSession(id) {
  ctx.beforeSwitchSession?.(store.activeId, id);
  store.activeId = id;
  writeActiveId(id);
  renderSessions();
  updateSessionTitle();
  ctx.afterSwitchSession?.(id);
}

export function renderSessions() {
  const { sessionsEl } = ctx;
  if (!sessionsEl) return;

  sessionsEl.innerHTML = "";
  if (store.sessions.length === 0) {
    sessionsEl.innerHTML = `
      <div class="history-empty">
        <span class="history-empty-title">Sem conversas</span>
        <span>Crie uma com Nova conversa.</span>
      </div>`;
    return;
  }

  const sorted = [...store.sessions].sort((a, b) => b.updatedAt - a.updatedAt);
  for (const s of sorted) {
    const title = sessionTitle(s);
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = `history-item${s.id === store.activeId ? " active" : ""}`;
    btn.title = title;
    const execCount = collectSessionExecutions(s).length;
    const running = isSessionBusy(s.id);
    const metaParts = [formatRelativeTime(s.updatedAt)];
    if (execCount) metaParts.push(`${execCount} exec`);
    btn.innerHTML = `
      <span class="history-item-icon" aria-hidden="true">${escapeHtml(sessionInitial(s))}</span>
      <span class="history-item-body">
        <span class="history-item-title">${escapeHtml(title)}</span>
        <span class="history-item-meta">
          <span class="history-item-meta-text">${escapeHtml(metaParts.join(" · "))}</span>
          ${running ? '<span class="history-item-chip">em execução</span>' : ""}
        </span>
      </span>
      <span class="history-item-actions">
        <span class="history-item-rename" title="Renomear" aria-label="Renomear conversa">✎</span>
        <span class="history-item-del" title="Excluir" aria-label="Excluir conversa">×</span>
      </span>
    `;
    btn.addEventListener("click", () => switchSession(s.id));
    btn.querySelector(".history-item-title")?.addEventListener("dblclick", (e) => {
      e.preventDefault();
      e.stopPropagation();
      beginRenameSession(s.id, e.target);
    });
    btn.querySelector(".history-item-rename")?.addEventListener("click", (e) => {
      e.stopPropagation();
      beginRenameSession(s.id, e.target);
    });
    btn.querySelector(".history-item-del").addEventListener("click", (e) => deleteSession(s.id, e));
    sessionsEl.appendChild(btn);
  }
}

export function rebuildInputHistory(inputHistoryRef) {
  const session = getActiveSession();
  inputHistoryRef.list = (session?.messages || [])
    .filter((m) => m.role === "user")
    .map((m) => m.content);
  inputHistoryRef.idx = inputHistoryRef.list.length;
}

/** @deprecated compat — loadStore antigo */
export function loadStore() {
  return store;
}
