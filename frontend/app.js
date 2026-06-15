const STORAGE_KEY = "chat-ia-kali-sessions";

const BANNER = `[ Chat IA Kali — pentest terminal ]
150+ ferramentas | tool:auto | hist | +
Use apenas em alvos autorizados.
`;

const chatEl = document.getElementById("chat");
const form = document.getElementById("form");
const input = document.getElementById("input");
const btnTools = document.getElementById("btn-tools");
const btnHistory = document.getElementById("btn-history");
const btnNew = document.getElementById("btn-new");
const toolBadge = document.getElementById("tool-badge");
const toolList = document.getElementById("tool-list");
const toolSearch = document.getElementById("tool-search");
const historyEl = document.getElementById("chat-history");
const overlayTools = document.getElementById("overlay-tools");
const overlayHistory = document.getElementById("overlay-history");

let store = loadStore();
let loading = false;
let preferredTool = "auto";
let toolCategories = [];

function loadStore() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) return JSON.parse(raw);
  } catch { /* ignore */ }
  return { sessions: [], activeId: null };
}

function saveStore() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
}

function uid() {
  return crypto.randomUUID?.() || `s-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function getActiveSession() {
  return store.sessions.find((s) => s.id === store.activeId) || null;
}

function createSession() {
  const session = {
    id: uid(),
    title: "novo",
    createdAt: Date.now(),
    updatedAt: Date.now(),
    preferredTool: "auto",
    messages: [],
  };
  store.sessions.unshift(session);
  store.activeId = session.id;
  saveStore();
  return session;
}

function ensureSession() {
  if (!getActiveSession()) createSession();
}

function sessionTitle(session) {
  const first = session.messages.find((m) => m.role === "user");
  if (first) return first.content.slice(0, 48) + (first.content.length > 48 ? "…" : "");
  return "novo chat";
}

function setPreferredTool(tool) {
  preferredTool = tool;
  const session = getActiveSession();
  if (session) {
    session.preferredTool = tool;
    saveStore();
  }
  toolBadge.textContent = tool;
  toolBadge.classList.toggle("fixed", tool !== "auto");
  document.querySelectorAll(".tool-item").forEach((el) => {
    el.classList.toggle("active", el.dataset.tool === tool);
  });
}

function openOverlay(overlay) {
  overlay.hidden = false;
  if (overlay === overlayTools) toolSearch.focus();
}

function closeOverlay(overlay) {
  overlay.hidden = true;
  input.focus();
}

function closeAllOverlays() {
  closeOverlay(overlayTools);
  closeOverlay(overlayHistory);
}

function deleteSession(id, e) {
  e?.stopPropagation();
  store.sessions = store.sessions.filter((s) => s.id !== id);
  if (store.activeId === id) {
    store.activeId = store.sessions[0]?.id || null;
    if (!store.activeId) createSession();
  }
  saveStore();
  renderHistory();
  renderChat();
  syncToolFromSession();
}

function switchSession(id) {
  store.activeId = id;
  saveStore();
  renderHistory();
  renderChat();
  syncToolFromSession();
  closeOverlay(overlayHistory);
  input.focus();
}

function renderHistory() {
  historyEl.innerHTML = "";
  if (store.sessions.length === 0) {
    historyEl.innerHTML = '<p class="history-empty">// nenhuma conversa</p>';
    return;
  }

  const sorted = [...store.sessions].sort((a, b) => b.updatedAt - a.updatedAt);
  for (const s of sorted) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = `history-item${s.id === store.activeId ? " active" : ""}`;
    btn.innerHTML = `
      <span class="history-item-title">${escapeHtml(sessionTitle(s))}</span>
      <span class="history-item-del" title="excluir">×</span>
    `;
    btn.addEventListener("click", () => switchSession(s.id));
    btn.querySelector(".history-item-del").addEventListener("click", (e) => deleteSession(s.id, e));
    historyEl.appendChild(btn);
  }
}

function syncToolFromSession() {
  const session = getActiveSession();
  setPreferredTool(session?.preferredTool || "auto");
}

function renderToolList(filter = "") {
  const q = filter.toLowerCase().trim();
  toolList.innerHTML = "";

  const autoBtn = document.createElement("button");
  autoBtn.type = "button";
  autoBtn.className = `tool-item${preferredTool === "auto" ? " active" : ""}`;
  autoBtn.dataset.tool = "auto";
  autoBtn.innerHTML = `
    <span class="tool-item-name">auto</span>
    <span class="tool-item-desc">IA escolhe a melhor ferramenta</span>
  `;
  autoBtn.addEventListener("click", () => selectTool("auto"));
  toolList.appendChild(autoBtn);

  for (const cat of toolCategories) {
    const tools = cat.tools.filter((t) => !q || t.toLowerCase().includes(q) || cat.name.toLowerCase().includes(q));
    if (tools.length === 0) continue;

    const label = document.createElement("div");
    label.className = "tool-cat-label";
    label.textContent = cat.name;
    toolList.appendChild(label);

    for (const tool of tools) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = `tool-item${preferredTool === tool ? " active" : ""}`;
      btn.dataset.tool = tool;
      btn.innerHTML = `<span class="tool-item-name">${escapeHtml(tool)}</span>`;
      btn.addEventListener("click", () => selectTool(tool));
      toolList.appendChild(btn);
    }
  }
}

function selectTool(tool) {
  setPreferredTool(tool);
  closeOverlay(overlayTools);
}

async function loadTools() {
  try {
    const res = await fetch("/api/tools");
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data.categories) && data.categories.length > 0) {
        toolCategories = data.categories;
        return true;
      }
    }
  } catch { /* ignore */ }
  toolCategories = [];
  return false;
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

function line(className, html) {
  const el = document.createElement("div");
  el.className = `term-line ${className || ""}`.trim();
  el.innerHTML = html;
  return el;
}

function buildExecBlock(t) {
  const badgeClass = t.blocked ? "status-blocked" : t.success ? "status-ok" : "status-fail";
  const badgeText = t.blocked ? "blocked" : t.success ? "ok" : `exit ${t.exit_code}`;
  const output = [t.stdout, t.stderr].filter(Boolean).join("\n") || "(sem saída)";

  const block = document.createElement("div");
  block.className = "term-exec";
  block.innerHTML = `
    <div class="term-exec-header" onclick="this.parentElement.classList.toggle('open')">
      <span class="${badgeClass}">[${badgeText}]</span>
      <span>$ ${escapeHtml(t.command)}</span>
    </div>
    <div class="term-exec-body">${escapeHtml(output)}</div>
  `;
  return block;
}

function renderChat() {
  const session = getActiveSession();
  chatEl.innerHTML = "";

  chatEl.appendChild(line("banner", escapeHtml(BANNER)));

  if (!session || session.messages.length === 0) {
    chatEl.appendChild(line("dim", "// digite um comando ou pergunta abaixo"));
    chatEl.scrollTop = chatEl.scrollHeight;
    return;
  }

  for (const msg of session.messages) {
    if (msg.role === "user") {
      chatEl.appendChild(line("prompt-line", `<span class="cmd">${escapeHtml(msg.content)}</span>`));
    } else {
      chatEl.appendChild(line("assistant", escapeHtml(msg.content)));
      for (const t of msg.toolExecutions || []) {
        chatEl.appendChild(buildExecBlock(t));
      }
    }
  }
  chatEl.scrollTop = chatEl.scrollHeight;
}

function appendUserLine(text) {
  const dim = chatEl.querySelector(".term-line.dim");
  if (dim) dim.remove();
  chatEl.appendChild(line("prompt-line", `<span class="cmd">${escapeHtml(text)}</span>`));
  chatEl.scrollTop = chatEl.scrollHeight;
}

function appendAssistant(content, toolExecutions = []) {
  chatEl.appendChild(line("assistant", escapeHtml(content)));
  for (const t of toolExecutions) {
    chatEl.appendChild(buildExecBlock(t));
  }
  chatEl.scrollTop = chatEl.scrollHeight;
}

function showTyping() {
  const el = line("typing-line dim", "processando");
  el.id = "typing";
  chatEl.appendChild(el);
  chatEl.scrollTop = chatEl.scrollHeight;
}

function hideTyping() {
  document.getElementById("typing")?.remove();
}

function newChat() {
  createSession();
  syncToolFromSession();
  renderHistory();
  renderChat();
  closeAllOverlays();
  input.focus();
}

async function sendMessage(text) {
  if (!text.trim() || loading) return;

  ensureSession();
  const session = getActiveSession();
  session.preferredTool = preferredTool;
  saveStore();

  const history = session.messages.map((m) => ({ role: m.role, content: m.content }));

  loading = true;
  input.disabled = true;
  input.value = "";

  const isFirst = session.messages.length === 0;
  session.messages.push({ role: "user", content: text });
  session.updatedAt = Date.now();
  if (isFirst) session.title = sessionTitle(session);
  saveStore();
  renderHistory();
  appendUserLine(text);
  showTyping();

  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: text,
        history,
        preferred_tool: preferredTool,
      }),
    });

    hideTyping();

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      const errMsg = `erro: ${err.detail || res.statusText}`;
      session.messages.push({ role: "assistant", content: errMsg });
      saveStore();
      chatEl.appendChild(line("error", escapeHtml(errMsg)));
      return;
    }

    const data = await res.json();
    session.messages.push({
      role: "assistant",
      content: data.message,
      toolExecutions: data.tool_executions || [],
    });
    session.updatedAt = Date.now();
    saveStore();
    appendAssistant(data.message, data.tool_executions || []);
  } catch (e) {
    hideTyping();
    const errMsg = `erro de conexão: ${e.message}`;
    session.messages.push({ role: "assistant", content: errMsg });
    saveStore();
    chatEl.appendChild(line("error", escapeHtml(errMsg)));
  } finally {
    loading = false;
    input.disabled = false;
    input.focus();
  }
}

btnTools.addEventListener("click", async () => {
  await loadTools();
  toolSearch.value = "";
  renderToolList();
  openOverlay(overlayTools);
});

btnHistory.addEventListener("click", () => {
  renderHistory();
  openOverlay(overlayHistory);
});

btnNew.addEventListener("click", newChat);

toolSearch.addEventListener("input", () => renderToolList(toolSearch.value));

document.querySelectorAll(".panel-close").forEach((btn) => {
  btn.addEventListener("click", () => {
    closeOverlay(document.getElementById(btn.dataset.close));
  });
});

overlayTools.addEventListener("click", (e) => {
  if (e.target === overlayTools) closeOverlay(overlayTools);
});

overlayHistory.addEventListener("click", (e) => {
  if (e.target === overlayHistory) closeOverlay(overlayHistory);
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeAllOverlays();
});

form.addEventListener("submit", (e) => {
  e.preventDefault();
  sendMessage(input.value);
});

ensureSession();
loadTools().then(() => renderToolList()).then(syncToolFromSession);
renderHistory();
renderChat();
