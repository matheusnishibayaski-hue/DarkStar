import { STORAGE_KEY, ARGUS_WELCOME_MESSAGE } from "./constants.js";
import { deleteSessionLogs } from "./data-admin.js";
import { escapeHtml } from "./exec.js";

/** @type {{ sessionsEl: HTMLElement, sessionTitleEl: HTMLElement, onChanged?: () => void }} */
let ctx = {};

export let store = loadStore();

export function initSessions(context) {
  ctx = context;
}

export function loadStore() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) return JSON.parse(raw);
  } catch { /* ignore */ }
  // migração leve do storage antigo
  try {
    const legacy = localStorage.getItem("chat-ia-kali-sessions");
    if (legacy) {
      localStorage.setItem(STORAGE_KEY, legacy);
      return JSON.parse(legacy);
    }
  } catch { /* ignore */ }
  return { sessions: [], activeId: null };
}

export function saveStore() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
}

function uid() {
  return crypto.randomUUID?.() || `s-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

export function getActiveSession() {
  return store.sessions.find((s) => s.id === store.activeId) || null;
}

export function createSession() {
  const session = {
    id: uid(),
    title: "novo chat",
    createdAt: Date.now(),
    updatedAt: Date.now(),
    preferredTool: "auto",
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
  saveStore();
  return session;
}

export function ensureSession() {
  if (!getActiveSession()) createSession();
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
  return (session?.messages || []).map((m) => ({ role: m.role, content: m.content }));
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
  saveStore();
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
  e?.stopPropagation();
  const session = store.sessions.find((s) => s.id === id);
  const logIds = session ? collectSessionLogIds(session) : [];
  ctx.beforeDeleteSession?.(id, logIds);
  store.sessions = store.sessions.filter((s) => s.id !== id);
  if (store.activeId === id) {
    store.activeId = store.sessions[0]?.id || null;
    if (!store.activeId) createSession();
  }
  saveStore();
  renderSessions();
  updateSessionTitle();
  ctx.afterDeleteSession?.();
}

export function switchSession(id) {
  store.activeId = id;
  saveStore();
  renderSessions();
  updateSessionTitle();
  ctx.afterSwitchSession?.(id);
}

export function renderSessions() {
  const { sessionsEl } = ctx;
  if (!sessionsEl) return;

  sessionsEl.innerHTML = "";
  if (store.sessions.length === 0) {
    sessionsEl.innerHTML = '<p class="history-empty">// nenhuma conversa</p>';
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
    btn.innerHTML = `
      <span class="history-item-icon" aria-hidden="true">${escapeHtml(sessionInitial(s))}</span>
      <span class="history-item-body">
        <span class="history-item-title">${escapeHtml(title)}</span>
        <span class="history-item-meta">${formatRelativeTime(s.updatedAt)}${execCount ? ` · ${execCount} exec` : ""}</span>
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
