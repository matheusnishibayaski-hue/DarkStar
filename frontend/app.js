const STORAGE_KEY = "chat-ia-kali-sessions";
const MODEL_STORAGE_KEY = "chat-ia-kali-model";
const HISTORY_LIMIT = 10;

const QUICK_PROMPTS = [
  { label: "Scan Nmap", text: "Faça um scan de portas e serviços em scanme.nmap.org" },
  { label: "Subdomínios", text: "Liste subdomínios de example.com com subfinder" },
  { label: "Whois", text: "Consulte whois e DNS de google.com" },
  { label: "Wi-Fi local", text: "Liste redes Wi-Fi visíveis ao redor" },
];

const QUICK_OBJECTIVES = [
  "Encontre subdomínios expostos e verifique se há takeover",
  "Mapeie portas abertas e identifique serviços desatualizados",
  "Faça reconhecimento web: tecnologias, diretórios e vulnerabilidades",
];

const HELP_HTML = `
<section class="help-section">
  <h3>Navegação</h3>
  <ul class="help-list">
    <li><kbd>M</kbd> ou <kbd>☰</kbd> — abrir/fechar menu lateral</li>
    <li>Sidebar — alternar entre conversas salvas</li>
    <li><kbd>Esc</kbd> — fechar painéis</li>
  </ul>
</section>
<section class="help-section">
  <h3>Ações</h3>
  <ul class="help-list">
    <li><kbd>Ctrl+N</kbd> — novo chat</li>
    <li><kbd>Ctrl+T</kbd> — selecionar ferramenta</li>
    <li><kbd>Ctrl+P</kbd> — modo Auto-Pilot</li>
    <li><kbd>Ctrl+R</kbd> — gerar relatório</li>
    <li><kbd>Ctrl+/</kbd> — esta ajuda</li>
    <li><kbd>Ctrl+K</kbd> — focar no prompt</li>
  </ul>
</section>
<section class="help-section">
  <h3>Prompt</h3>
  <ul class="help-list">
    <li><kbd>Enter</kbd> — enviar mensagem</li>
    <li><kbd>↑</kbd> / <kbd>↓</kbd> — histórico de comandos da sessão</li>
  </ul>
</section>
<section class="help-section">
  <h3>Modelo de IA</h3>
  <ul class="help-list">
    <li>Seletor no prompt (pill) — escolha Gemini ou DeepSeek</li>
    <li><strong>Economia</strong> — menos tokens, respostas rápidas</li>
    <li><strong>Equilibrado</strong> — uso geral do dia a dia</li>
    <li><strong>Raciocínio</strong> — análises complexas (mais tokens)</li>
  </ul>
</section>
<section class="help-section">
  <h3>Modos de uso</h3>
  <ul class="help-list">
    <li><strong>Chat</strong> — descreva o que precisa; a IA executa ferramentas Kali</li>
    <li><strong>tool:X</strong> — force uma ferramenta específica (ex: nmap, nuclei)</li>
    <li><strong>pilot</strong> — informe alvo + objetivo; o agente roda sozinho</li>
    <li><strong>report</strong> — baixa relatório Markdown da sessão atual</li>
  </ul>
</section>
<p class="help-note">Use apenas em alvos autorizados.</p>
`;

const chatEl = document.getElementById("chat");
const form = document.getElementById("form");
const input = document.getElementById("input");
const btnMenu = document.getElementById("btn-menu");
const btnTools = document.getElementById("btn-tools");
const btnAutopilot = document.getElementById("btn-autopilot");
const btnReport = document.getElementById("btn-report");
const btnHelp = document.getElementById("btn-help");
const btnNew = document.getElementById("btn-new");
const btnScrollBottom = document.getElementById("btn-scroll-bottom");
const toolBadge = document.getElementById("tool-badge");
const toolList = document.getElementById("tool-list");
const toolCategoriesEl = document.getElementById("tool-categories");
const toolSearch = document.getElementById("tool-search");
const modelTrigger = document.getElementById("model-trigger");
const modelMenu = document.getElementById("model-menu");
const modelLabel = document.getElementById("model-label");
const sessionsEl = document.getElementById("sidebar-sessions");
const sessionTitleEl = document.getElementById("session-title");
const statusBarText = document.getElementById("status-bar-text");
const sidebar = document.getElementById("sidebar");
const sidebarBackdrop = document.getElementById("sidebar-backdrop");
const sidebarClose = document.getElementById("sidebar-close");
const sidebarNew = document.getElementById("sidebar-new");
const sidebarHelp = document.getElementById("sidebar-help");
const overlayTools = document.getElementById("overlay-tools");
const overlayAutopilot = document.getElementById("overlay-autopilot");
const overlayHelp = document.getElementById("overlay-help");
const helpContent = document.getElementById("help-content");
const autopilotTarget = document.getElementById("autopilot-target");
const autopilotObjective = document.getElementById("autopilot-objective");
const autopilotStart = document.getElementById("autopilot-start");
const quickObjectivesEl = document.getElementById("quick-objectives");
const toastContainer = document.getElementById("toast-container");

let store = loadStore();
let loading = false;
let preferredTool = "auto";
let toolCategories = [];
let activeToolCategory = "all";
let modelCatalog = null;
let selectedModel = null;
let inputHistory = [];
let inputHistoryIdx = -1;
let healthData = null;

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
    title: "novo chat",
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
  if (session?.title && session.title !== "novo chat") return session.title;
  const first = session?.messages?.find((m) => m.role === "user");
  if (first) {
    const line = first.content.split("\n")[0];
    return line.slice(0, 48) + (line.length > 48 ? "…" : "");
  }
  return "novo chat";
}

function formatRelativeTime(ts) {
  const diff = Date.now() - ts;
  const min = Math.floor(diff / 60000);
  if (min < 1) return "agora";
  if (min < 60) return `${min}m`;
  const h = Math.floor(min / 60);
  if (h < 24) return `${h}h`;
  return `${Math.floor(h / 24)}d`;
}

function toast(msg, type = "info", ms = 4000) {
  const el = document.createElement("div");
  el.className = `toast toast-${type}`;
  el.textContent = msg;
  toastContainer.appendChild(el);
  setTimeout(() => {
    el.classList.add("toast-out");
    setTimeout(() => el.remove(), 300);
  }, ms);
}

function showToastError(msg) { toast(msg, "error", 6000); }

function isMobile() {
  return window.matchMedia("(max-width: 768px)").matches;
}

function openSidebar() {
  sidebar.classList.add("open");
  if (isMobile()) sidebarBackdrop.hidden = false;
}

function closeSidebar() {
  sidebar.classList.remove("open");
  sidebarBackdrop.hidden = true;
}

function toggleSidebar() {
  if (sidebar.classList.contains("open")) closeSidebar();
  else openSidebar();
}

function detectTool(t) {
  if (t.tool) return t.tool.toLowerCase();
  const cmd = (t.command || "").trim();
  return cmd.split(/\s+/)[0]?.split("/").pop()?.toLowerCase() || "";
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
  document.querySelectorAll(".tool-item, .tool-card").forEach((el) => {
    const nameEl = el.querySelector(".tool-item-name");
    if (nameEl) el.classList.toggle("active", nameEl.textContent === tool);
  });
  updateStatusBar();
}

function openOverlay(overlay) {
  closeSidebar();
  overlay.hidden = false;
  if (overlay === overlayTools) toolSearch.focus();
  if (overlay === overlayAutopilot) autopilotTarget.focus();
}

function closeOverlay(overlay) {
  overlay.hidden = true;
  input.focus();
}

function closeAllOverlays() {
  closeOverlay(overlayTools);
  closeOverlay(overlayAutopilot);
  closeOverlay(overlayHelp);
  closeModelMenu();
}

function closeModelMenu() {
  modelMenu.hidden = true;
  modelTrigger?.classList.remove("open");
}

function toggleModelMenu() {
  if (modelMenu.hidden) {
    renderModelMenu();
    modelMenu.hidden = false;
    modelTrigger.classList.add("open");
  } else {
    closeModelMenu();
  }
}

function loadSelectedModel() {
  try {
    const raw = localStorage.getItem(MODEL_STORAGE_KEY);
    if (raw) return JSON.parse(raw);
  } catch { /* ignore */ }
  return null;
}

function saveSelectedModel(model) {
  selectedModel = model;
  localStorage.setItem(MODEL_STORAGE_KEY, JSON.stringify(model));
  updateModelLabel();
  updateStatusBar();
}

function updateModelLabel() {
  if (!modelLabel || !selectedModel) return;
  modelLabel.textContent = selectedModel.name || "Flash";
  modelTrigger.title = `${selectedModel.name} (${selectedModel.provider || "ia"})`;
  modelTrigger.classList.toggle("model-gemini", selectedModel.provider === "gemini");
  modelTrigger.classList.toggle("model-deepseek", selectedModel.provider === "deepseek");
}

function getModelPayload() {
  if (!selectedModel) return {};
  return {
    model: selectedModel.id,
    fallback_model: selectedModel.fallback || "",
  };
}

function selectModel(model) {
  saveSelectedModel(model);
  closeModelMenu();
  toast(`${model.name} · ${model.tier_label || "modelo"}`, "success");
}

function renderModelMenu() {
  if (!modelCatalog?.tiers) return;
  modelMenu.innerHTML = "";

  for (let i = 0; i < modelCatalog.tiers.length; i++) {
    const tier = modelCatalog.tiers[i];
    if (i > 0) {
      const sep = document.createElement("div");
      sep.className = "model-menu-sep";
      modelMenu.appendChild(sep);
    }

    const head = document.createElement("div");
    head.className = "model-tier-head";
    head.innerHTML = `
      <span class="model-tier-label">${escapeHtml(tier.label)}</span>
      <span class="model-tier-desc">${escapeHtml(tier.description || "")}</span>
    `;
    modelMenu.appendChild(head);

    for (const m of tier.models) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = `model-option${selectedModel?.id === m.id ? " active" : ""}`;
      btn.innerHTML = `
        <span class="model-check">${selectedModel?.id === m.id ? "✓" : ""}</span>
        <span class="model-option-body">
          <span class="model-option-name">
            <span class="model-provider model-provider-${m.provider}">${m.provider === "deepseek" ? "DS" : "G"}</span>
            ${escapeHtml(m.name)}
          </span>
          <span class="model-option-desc">${escapeHtml(m.description)}</span>
        </span>
      `;
      btn.addEventListener("click", () => selectModel({
        id: m.id,
        name: m.name,
        fallback: m.fallback,
        provider: m.provider,
        tier_label: tier.label,
      }));
      modelMenu.appendChild(btn);
    }
  }
}

async function loadModels() {
  try {
    const res = await fetch("/api/models");
    if (!res.ok) return false;
    modelCatalog = await res.json();
    const saved = loadSelectedModel();
    if (saved?.id) {
      selectedModel = saved;
    } else {
      const defaultId = modelCatalog.default_model;
      for (const tier of modelCatalog.tiers) {
        const found = tier.models.find((m) => m.id === defaultId);
        if (found) {
          selectedModel = {
            id: found.id,
            name: found.name,
            fallback: found.fallback,
            provider: found.provider,
            tier_label: tier.label,
          };
          break;
        }
      }
    }
    updateModelLabel();
    return true;
  } catch { /* ignore */ }
  return false;
}

function renderToolCategoryTabs() {
  if (!toolCategoriesEl) return;
  toolCategoriesEl.innerHTML = "";

  const allBtn = document.createElement("button");
  allBtn.type = "button";
  allBtn.className = `tool-cat-tab${activeToolCategory === "all" ? " active" : ""}`;
  allBtn.textContent = "todas";
  allBtn.addEventListener("click", () => {
    activeToolCategory = "all";
    renderToolCategoryTabs();
    renderToolList(toolSearch.value);
  });
  toolCategoriesEl.appendChild(allBtn);

  for (const cat of toolCategories) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = `tool-cat-tab${activeToolCategory === cat.id ? " active" : ""}`;
    btn.textContent = cat.name;
    btn.addEventListener("click", () => {
      activeToolCategory = cat.id;
      renderToolCategoryTabs();
      renderToolList(toolSearch.value);
    });
    toolCategoriesEl.appendChild(btn);
  }
}

function updateSessionTitle() {
  const session = getActiveSession();
  const title = session ? sessionTitle(session) : "kali@ai";
  sessionTitleEl.textContent = title;
  document.title = `${title} — kali@ai`;
}

function updateStatusBar() {
  const session = getActiveSession();
  const execCount = collectSessionExecutions(session).length;
  const parts = [];

  if (healthData) {
    if (healthData.docker && healthData.kali_container) parts.push("kali ok");
    else if (!healthData.docker) parts.push("docker off");
    else parts.push("kali off");
  }
  parts.push(`tools:${preferredTool}`);
  if (selectedModel) parts.push(selectedModel.name);
  if (session) parts.push(`${session.messages.length} msg`);
  if (execCount) parts.push(`${execCount} exec`);
  if (loading) parts.push("…");

  statusBarText.textContent = parts.join(" · ") || "pronto";
}

async function refreshHealth() {
  try {
    const res = await fetch("/api/health");
    if (!res.ok) return;
    healthData = await res.json();
    updateStatusBar();
    if (healthData.docker && !healthData.kali_container) {
      statusBarText.title = healthData.kali_error || "Container Kali não está rodando";
    } else {
      statusBarText.title = "";
    }
  } catch { /* ignore */ }
}

function deleteSession(id, e) {
  e?.stopPropagation();
  store.sessions = store.sessions.filter((s) => s.id !== id);
  if (store.activeId === id) {
    store.activeId = store.sessions[0]?.id || null;
    if (!store.activeId) createSession();
  }
  saveStore();
  renderSessions();
  renderChat();
  syncToolFromSession();
  updateSessionTitle();
  toast("conversa excluída");
}

function switchSession(id) {
  store.activeId = id;
  saveStore();
  renderSessions();
  renderChat();
  syncToolFromSession();
  updateSessionTitle();
  closeSidebar();
  input.focus();
}

function renderSessions() {
  sessionsEl.innerHTML = "";
  if (store.sessions.length === 0) {
    sessionsEl.innerHTML = '<p class="history-empty">// nenhuma conversa</p>';
    return;
  }

  const sorted = [...store.sessions].sort((a, b) => b.updatedAt - a.updatedAt);
  for (const s of sorted) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = `history-item${s.id === store.activeId ? " active" : ""}`;
    const execCount = collectSessionExecutions(s).length;
    btn.innerHTML = `
      <span class="history-item-body">
        <span class="history-item-title">${escapeHtml(sessionTitle(s))}</span>
        <span class="history-item-meta">${formatRelativeTime(s.updatedAt)}${execCount ? ` · ${execCount} exec` : ""}</span>
      </span>
      <span class="history-item-del" title="excluir">×</span>
    `;
    btn.addEventListener("click", () => switchSession(s.id));
    btn.querySelector(".history-item-del").addEventListener("click", (e) => deleteSession(s.id, e));
    sessionsEl.appendChild(btn);
  }
}

function syncToolFromSession() {
  const session = getActiveSession();
  setPreferredTool(session?.preferredTool || "auto");
}

function renderWelcome() {
  const wrap = document.createElement("div");
  wrap.className = "welcome";
  wrap.innerHTML = `
    <p class="welcome-title">// bem-vindo ao Chat IA Kali</p>
    <p class="welcome-desc">Escolha um atalho ou digite no prompt abaixo. Use <strong>pilot</strong> para missões autônomas.</p>
    <div class="welcome-actions">
      <button type="button" class="welcome-btn welcome-btn-pilot" data-action="pilot">Auto-Pilot</button>
      <button type="button" class="welcome-btn" data-action="tools">Ferramentas</button>
      <button type="button" class="welcome-btn" data-action="help">Ajuda</button>
    </div>
    <p class="welcome-label">exemplos rápidos</p>
    <div class="welcome-prompts" id="welcome-prompts"></div>
  `;

  wrap.querySelector('[data-action="pilot"]').addEventListener("click", () => openOverlay(overlayAutopilot));
  wrap.querySelector('[data-action="tools"]').addEventListener("click", async () => {
    await loadTools();
    activeToolCategory = "all";
    renderToolCategoryTabs();
    renderToolList();
    openOverlay(overlayTools);
  });
  wrap.querySelector('[data-action="help"]').addEventListener("click", () => openOverlay(overlayHelp));

  const promptsEl = wrap.querySelector("#welcome-prompts");
  for (const p of QUICK_PROMPTS) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "welcome-prompt";
    btn.textContent = p.label;
    btn.title = p.text;
    btn.addEventListener("click", () => {
      input.value = p.text;
      input.focus();
    });
    promptsEl.appendChild(btn);
  }

  return wrap;
}

function renderQuickObjectives() {
  quickObjectivesEl.innerHTML = "";
  const label = document.createElement("span");
  label.className = "quick-obj-label";
  label.textContent = "objetivos rápidos:";
  quickObjectivesEl.appendChild(label);

  for (const obj of QUICK_OBJECTIVES) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "quick-obj-btn";
    btn.textContent = obj.length > 55 ? obj.slice(0, 55) + "…" : obj;
    btn.title = obj;
    btn.addEventListener("click", () => {
      autopilotObjective.value = obj;
      autopilotObjective.focus();
    });
    quickObjectivesEl.appendChild(btn);
  }
}

function renderToolList(filter = "") {
  const q = filter.toLowerCase().trim();
  toolList.innerHTML = "";

  const grid = document.createElement("div");
  grid.className = "tools-grid";

  const autoCard = document.createElement("div");
  autoCard.className = `tool-card tool-card-wide${preferredTool === "auto" ? " active" : ""}`;
  autoCard.innerHTML = `
    <div class="tool-card-main">
      <span class="tool-item-name">auto</span>
      <span class="tool-item-desc">A IA escolhe a ferramenta ideal para cada pedido — recomendado na maioria dos casos</span>
    </div>
  `;
  autoCard.addEventListener("click", () => selectTool("auto"));
  grid.appendChild(autoCard);

  for (const cat of toolCategories) {
    if (activeToolCategory !== "all" && cat.id !== activeToolCategory) continue;

    const tools = cat.tools.filter((t) => {
      const id = t.id || t;
      const summary = t.summary || "";
      return !q || id.toLowerCase().includes(q) || summary.toLowerCase().includes(q) || cat.name.toLowerCase().includes(q);
    });
    if (tools.length === 0) continue;

    for (const tool of tools) {
      const id = tool.id || tool;
      const summary = tool.summary || "";
      const example = tool.example || "";

      const card = document.createElement("div");
      card.className = `tool-card${preferredTool === id ? " active" : ""}`;

      const main = document.createElement("div");
      main.className = "tool-card-main";
      main.innerHTML = `
        <span class="tool-item-cat">${escapeHtml(cat.name)}</span>
        <span class="tool-item-name">${escapeHtml(id)}</span>
        <span class="tool-item-desc">${escapeHtml(summary)}</span>
        ${example ? `<code class="tool-item-example">${escapeHtml(example)}</code>` : ""}
      `;
      main.addEventListener("click", () => selectTool(id));

      const actions = document.createElement("div");
      actions.className = "tool-card-actions";

      if (example) {
        const useBtn = document.createElement("button");
        useBtn.type = "button";
        useBtn.className = "tool-use-btn";
        useBtn.textContent = "usar";
        useBtn.title = "Seleciona ferramenta e coloca exemplo no prompt";
        useBtn.addEventListener("click", (e) => {
          e.stopPropagation();
          selectTool(id, example);
        });
        actions.appendChild(useBtn);
      }

      card.appendChild(main);
      if (actions.childElementCount) card.appendChild(actions);
      grid.appendChild(card);
    }
  }

  toolList.appendChild(grid);
}

function selectTool(tool, exampleText = null) {
  setPreferredTool(tool);
  closeOverlay(overlayTools);
  if (exampleText) {
    input.value = exampleText;
    input.focus();
    toast(`ferramenta: ${tool} · exemplo no prompt`, "success");
  } else {
    toast(tool === "auto" ? "modo auto — IA escolhe" : `ferramenta fixa: ${tool}`);
  }
}

async function loadTools() {
  try {
    const res = await fetch("/api/tools");
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data.categories) && data.categories.length > 0) {
        toolCategories = data.categories;
        renderToolCategoryTabs();
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

function getCombinedOutput(t) {
  return [t.stdout, t.stderr].filter(Boolean).join("\n");
}

function parseNmapOutput(text) {
  const rows = [];
  const re = /^(\d+\/(tcp|udp))\s+(open|closed|filtered)\s+(\S+)(?:\s+(.*))?$/gim;
  let m;
  while ((m = re.exec(text)) !== null) {
    rows.push({
      port: m[1],
      state: m[3],
      service: m[4] || "—",
      version: (m[5] || "—").trim() || "—",
    });
  }
  return rows;
}

function parseNucleiOutput(text) {
  const findings = [];
  const re = /\[?(critical|high|medium|low|info)\]?[^\n]*/gi;
  let m;
  while ((m = re.exec(text)) !== null) {
    const full = m[0].trim();
    const sev = (m[1] || "info").toLowerCase();
    if (full.length > 5) findings.push({ severity: sev, text: full });
  }
  return findings;
}

function severityClass(sev) {
  const s = (sev || "info").toLowerCase();
  if (s === "critical" || s === "high") return "sev-critical";
  if (s === "medium") return "sev-medium";
  return "sev-info";
}

function buildNmapDashboard(rows) {
  if (!rows.length) return null;
  const wrap = document.createElement("div");
  wrap.className = "dash-panel dash-nmap";
  wrap.innerHTML = `
    <div class="dash-title">// nmap — portas detectadas (${rows.length})</div>
    <table class="dash-table">
      <thead><tr><th>Porta</th><th>Estado</th><th>Serviço</th><th>Versão</th></tr></thead>
      <tbody>
        ${rows.map((r) => `
          <tr class="${r.state === "open" ? "row-open" : ""}">
            <td>${escapeHtml(r.port)}</td>
            <td>${escapeHtml(r.state)}</td>
            <td>${escapeHtml(r.service)}</td>
            <td>${escapeHtml(r.version)}</td>
          </tr>`).join("")}
      </tbody>
    </table>
  `;
  return wrap;
}

function buildNucleiDashboard(findings) {
  if (!findings.length) return null;
  const wrap = document.createElement("div");
  wrap.className = "dash-panel dash-nuclei";
  wrap.innerHTML = `<div class="dash-title">// nuclei — achados (${findings.length})</div>`;
  for (const f of findings.slice(0, 30)) {
    const card = document.createElement("div");
    card.className = `vuln-card ${severityClass(f.severity)}`;
    card.textContent = f.text;
    wrap.appendChild(card);
  }
  if (findings.length > 30) {
    const more = document.createElement("div");
    more.className = "dash-more";
    more.textContent = `+ ${findings.length - 30} achados adicionais no log completo`;
    wrap.appendChild(more);
  }
  return wrap;
}

function buildExecBlock(t) {
  const badgeClass = t.blocked ? "status-blocked" : t.success ? "status-ok" : "status-fail";
  const badgeText = t.blocked ? "blocked" : t.success ? "ok" : `exit ${t.exit_code}`;
  const output = getCombinedOutput(t) || "(sem saída)";
  const tool = detectTool(t);

  const block = document.createElement("div");
  block.className = "term-exec";

  const header = document.createElement("div");
  header.className = "term-exec-header";
  header.innerHTML = `
    <span class="${badgeClass}">[${badgeText}]</span>
    <span class="exec-cmd">$ ${escapeHtml(t.command)}</span>
  `;

  const body = document.createElement("div");
  body.className = "term-exec-body";

  let hasDashboard = false;

  if (tool === "nmap" || output.match(/\d+\/tcp\s+open/i)) {
    const rows = parseNmapOutput(output);
    const dash = buildNmapDashboard(rows);
    if (dash) { body.appendChild(dash); hasDashboard = true; }
  }

  if (tool === "nuclei" || output.match(/\[(critical|high|medium)\]/i)) {
    const findings = parseNucleiOutput(output);
    const dash = buildNucleiDashboard(findings);
    if (dash) { body.appendChild(dash); hasDashboard = true; }
  }

  const rawWrap = document.createElement("div");
  rawWrap.className = hasDashboard ? "exec-raw hidden" : "exec-raw";
  rawWrap.textContent = output;
  body.appendChild(rawWrap);

  const actions = document.createElement("div");
  actions.className = "exec-actions";

  if (hasDashboard) {
    const toggleBtn = document.createElement("button");
    toggleBtn.type = "button";
    toggleBtn.className = "exec-btn";
    toggleBtn.textContent = "Ver Log Completo";
    toggleBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      rawWrap.classList.toggle("hidden");
      toggleBtn.textContent = rawWrap.classList.contains("hidden") ? "Ver Log Completo" : "Ocultar Log";
    });
    actions.appendChild(toggleBtn);
  }

  if (t.log_file_id) {
    const logBtn = document.createElement("a");
    logBtn.className = "exec-btn";
    logBtn.href = `/api/logs/${t.log_file_id}`;
    logBtn.target = "_blank";
    logBtn.rel = "noopener";
    logBtn.textContent = `Log #${t.log_file_id}`;
    actions.appendChild(logBtn);
  }

  body.appendChild(actions);
  block.appendChild(header);
  block.appendChild(body);

  header.addEventListener("click", (e) => {
    if (e.target.closest(".exec-btn")) return;
    block.classList.toggle("open");
  });

  if (hasDashboard) block.classList.add("open");
  return block;
}

function scrollChatToBottom(smooth = true) {
  chatEl.scrollTo({ top: chatEl.scrollHeight, behavior: smooth ? "smooth" : "auto" });
  btnScrollBottom.hidden = true;
}

function onChatScroll() {
  const nearBottom = chatEl.scrollHeight - chatEl.scrollTop - chatEl.clientHeight < 80;
  btnScrollBottom.hidden = nearBottom || chatEl.scrollHeight <= chatEl.clientHeight;
}

function renderChat() {
  const session = getActiveSession();
  chatEl.innerHTML = "";

  if (!session || session.messages.length === 0) {
    chatEl.appendChild(renderWelcome());
    scrollChatToBottom(false);
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
  scrollChatToBottom(false);
}

function appendUserLine(text) {
  chatEl.appendChild(line("prompt-line", `<span class="cmd">${escapeHtml(text)}</span>`));
  scrollChatToBottom();
}

function appendAssistant(content, toolExecutions = []) {
  chatEl.appendChild(line("assistant", escapeHtml(content)));
  for (const t of toolExecutions) {
    chatEl.appendChild(buildExecBlock(t));
  }
  scrollChatToBottom();
}

function showTyping(label = "processando") {
  hideTyping();
  const el = line("typing-line dim", label);
  el.id = "typing";
  chatEl.appendChild(el);
  scrollChatToBottom();
  updateStatusBar();
}

function hideTyping() {
  document.getElementById("typing")?.remove();
  updateStatusBar();
}

function showAutopilotProgress(text) {
  showTyping(text);
}

function downloadMarkdown(content, filename) {
  const blob = new Blob([content], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function collectSessionExecutions(session) {
  const all = [];
  for (const msg of session?.messages || []) {
    if (msg.role === "assistant" && msg.toolExecutions?.length) {
      all.push(...msg.toolExecutions);
    }
  }
  return all;
}

function collectSessionHistory(session) {
  return (session?.messages || []).map((m) => ({ role: m.role, content: m.content }));
}

function rebuildInputHistory() {
  const session = getActiveSession();
  inputHistory = (session?.messages || [])
    .filter((m) => m.role === "user")
    .map((m) => m.content);
  inputHistoryIdx = inputHistory.length;
}

async function downloadReport() {
  const session = getActiveSession();
  if (!session || session.messages.length === 0) {
    showToastError("Nenhuma conversa ativa para gerar relatório.");
    return;
  }

  const toolExecutions = collectSessionExecutions(session);
  if (toolExecutions.length === 0) {
    showToastError("Nenhuma ferramenta foi executada nesta sessão.");
    return;
  }

  btnReport.disabled = true;
  btnReport.textContent = "...";
  updateStatusBar();

  try {
    const res = await fetch("/api/generate-report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        history: collectSessionHistory(session),
        tool_executions: toolExecutions,
        title: `Relatório — ${sessionTitle(session)}`,
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      showToastError(`Erro ao gerar relatório: ${err.detail || res.statusText}`);
      return;
    }

    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "relatorio-pentest.md";
    a.click();
    URL.revokeObjectURL(url);
    toast("relatório baixado");
  } catch (e) {
    showToastError(`Erro de conexão: ${e.message}`);
  } finally {
    btnReport.disabled = false;
    btnReport.textContent = "report";
    updateStatusBar();
  }
}

async function startAutopilot() {
  const target = autopilotTarget.value.trim();
  const objective = autopilotObjective.value.trim();

  if (!target || !objective) {
    showToastError("Informe o alvo e o objetivo da missão.");
    return;
  }

  if (loading) return;

  ensureSession();
  const session = getActiveSession();
  closeOverlay(overlayAutopilot);

  const userMsg = `[Auto-Pilot]\nAlvo: ${target}\nObjetivo: ${objective}`;

  loading = true;
  input.disabled = true;
  autopilotStart.disabled = true;
  btnAutopilot.disabled = true;
  updateStatusBar();

  const isFirst = session.messages.length === 0;
  session.messages.push({ role: "user", content: userMsg });
  session.updatedAt = Date.now();
  if (isFirst || session.title === "novo chat") session.title = `pilot: ${target}`;
  saveStore();
  renderSessions();
  updateSessionTitle();
  renderChat();
  showAutopilotProgress("auto-pilot em execução — planejando, executando e analisando (pode levar vários minutos)");

  try {
    const res = await fetch("/api/autonomous", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target,
        objective,
        ...getModelPayload(),
      }),
    });

    hideTyping();

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      const errMsg = `erro auto-pilot: ${err.detail || res.statusText}`;
      session.messages.push({ role: "assistant", content: errMsg });
      saveStore();
      chatEl.appendChild(line("error", escapeHtml(errMsg)));
      showToastError(errMsg);
      return;
    }

    const data = await res.json();
    session.messages.push({
      role: "assistant",
      content: data.message,
      toolExecutions: data.tool_executions || [],
      autopilot: {
        objective_met: data.objective_met,
        rounds: data.rounds,
        stopped_reason: data.stopped_reason,
        tools_executed: data.tools_executed,
      },
    });
    session.updatedAt = Date.now();
    saveStore();
    renderSessions();
    appendAssistant(data.message, data.tool_executions || []);

    if (data.report) {
      const safeName = target.replace(/[^\w.-]+/g, "_").slice(0, 40);
      downloadMarkdown(data.report, `relatorio-autopilot-${safeName}.md`);
      chatEl.appendChild(line(
        "info",
        `relatório auto-pilot baixado · ${data.tools_executed} cmd(s) · ${data.rounds} rodada(s) · ${data.objective_met ? "objetivo atingido" : data.stopped_reason}`
      ));
      toast(`auto-pilot concluído · ${data.tools_executed} comandos`, "success");
    }
  } catch (e) {
    hideTyping();
    const errMsg = `erro de conexão auto-pilot: ${e.message}`;
    session.messages.push({ role: "assistant", content: errMsg });
    saveStore();
    chatEl.appendChild(line("error", escapeHtml(errMsg)));
    showToastError(errMsg);
  } finally {
    loading = false;
    input.disabled = false;
    autopilotStart.disabled = false;
    btnAutopilot.disabled = false;
    rebuildInputHistory();
    updateStatusBar();
    input.focus();
  }
}

function newChat() {
  createSession();
  syncToolFromSession();
  renderSessions();
  renderChat();
  updateSessionTitle();
  closeAllOverlays();
  rebuildInputHistory();
  input.value = "";
  input.focus();
  toast("novo chat");
}

async function sendMessage(text) {
  if (!text.trim() || loading) return;

  ensureSession();
  const session = getActiveSession();
  session.preferredTool = preferredTool;
  saveStore();

  const history = session.messages
    .slice(-HISTORY_LIMIT)
    .map((m) => ({ role: m.role, content: m.content }));

  loading = true;
  input.disabled = true;
  input.value = "";
  inputHistoryIdx = inputHistory.length;
  updateStatusBar();

  const isFirst = session.messages.length === 0;
  session.messages.push({ role: "user", content: text });
  session.updatedAt = Date.now();
  if (isFirst || session.title === "novo chat") session.title = sessionTitle(session);
  saveStore();
  renderSessions();
  updateSessionTitle();

  if (isFirst) renderChat();
  else appendUserLine(text);
  showTyping();

  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: text,
        history,
        preferred_tool: preferredTool,
        ...getModelPayload(),
      }),
    });

    hideTyping();

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      const errMsg = `erro: ${err.detail || res.statusText}`;
      session.messages.push({ role: "assistant", content: errMsg });
      saveStore();
      chatEl.appendChild(line("error", escapeHtml(errMsg)));
      showToastError(errMsg);
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
    renderSessions();
    appendAssistant(data.message, data.tool_executions || []);
  } catch (e) {
    hideTyping();
    const errMsg = `erro de conexão: ${e.message}`;
    session.messages.push({ role: "assistant", content: errMsg });
    saveStore();
    chatEl.appendChild(line("error", escapeHtml(errMsg)));
    showToastError(errMsg);
  } finally {
    loading = false;
    input.disabled = false;
    rebuildInputHistory();
    updateStatusBar();
    input.focus();
  }
}

function handleInputKeydown(e) {
  if (e.key === "ArrowUp") {
    if (inputHistory.length === 0) return;
    e.preventDefault();
    if (inputHistoryIdx > 0) inputHistoryIdx -= 1;
    input.value = inputHistory[inputHistoryIdx] || "";
  } else if (e.key === "ArrowDown") {
    if (inputHistory.length === 0) return;
    e.preventDefault();
    if (inputHistoryIdx < inputHistory.length - 1) {
      inputHistoryIdx += 1;
      input.value = inputHistory[inputHistoryIdx];
    } else {
      inputHistoryIdx = inputHistory.length;
      input.value = "";
    }
  }
}

function handleGlobalKeydown(e) {
  const tag = e.target.tagName;
  const inInput = tag === "INPUT" || tag === "TEXTAREA";

  if (e.key === "Escape") {
    closeAllOverlays();
    closeSidebar();
    return;
  }

  if (!(e.ctrlKey || e.metaKey)) {
    if (e.key === "m" || e.key === "M") {
      if (!inInput) { e.preventDefault(); toggleSidebar(); }
    }
    return;
  }

  const key = e.key.toLowerCase();
  const shortcuts = {
    n: () => { e.preventDefault(); newChat(); },
    t: () => { e.preventDefault(); btnTools.click(); },
    p: () => { e.preventDefault(); openOverlay(overlayAutopilot); },
    r: () => { e.preventDefault(); downloadReport(); },
    k: () => { e.preventDefault(); input.focus(); },
    "/": () => { e.preventDefault(); openOverlay(overlayHelp); },
  };

  if (shortcuts[key]) shortcuts[key]();
}

btnMenu.addEventListener("click", toggleSidebar);
sidebarClose.addEventListener("click", closeSidebar);
sidebarBackdrop.addEventListener("click", closeSidebar);
sidebarNew.addEventListener("click", newChat);
sidebarHelp.addEventListener("click", () => openOverlay(overlayHelp));

btnTools.addEventListener("click", async () => {
  await loadTools();
  toolSearch.value = "";
  activeToolCategory = "all";
  renderToolCategoryTabs();
  renderToolList();
  openOverlay(overlayTools);
});

modelTrigger.addEventListener("click", (e) => {
  e.stopPropagation();
  toggleModelMenu();
});

document.addEventListener("click", (e) => {
  if (!modelMenu.hidden && !e.target.closest(".model-picker-wrap")) {
    closeModelMenu();
  }
});

btnAutopilot.addEventListener("click", () => openOverlay(overlayAutopilot));
btnHelp.addEventListener("click", () => openOverlay(overlayHelp));
autopilotStart.addEventListener("click", startAutopilot);
btnReport.addEventListener("click", downloadReport);
btnNew.addEventListener("click", newChat);
btnScrollBottom.addEventListener("click", () => scrollChatToBottom());

toolSearch.addEventListener("input", () => renderToolList(toolSearch.value));
input.addEventListener("keydown", handleInputKeydown);
chatEl.addEventListener("scroll", onChatScroll);

document.querySelectorAll(".panel-close").forEach((btn) => {
  btn.addEventListener("click", () => {
    closeOverlay(document.getElementById(btn.dataset.close));
  });
});

overlayTools.addEventListener("click", (e) => {
  if (e.target === overlayTools) closeOverlay(overlayTools);
});
overlayAutopilot.addEventListener("click", (e) => {
  if (e.target === overlayAutopilot) closeOverlay(overlayAutopilot);
});
overlayHelp.addEventListener("click", (e) => {
  if (e.target === overlayHelp) closeOverlay(overlayHelp);
});

document.addEventListener("keydown", handleGlobalKeydown);

form.addEventListener("submit", (e) => {
  e.preventDefault();
  sendMessage(input.value);
});

helpContent.innerHTML = HELP_HTML;
renderQuickObjectives();

ensureSession();
loadModels();
loadTools().then(() => renderToolList()).then(syncToolFromSession);
renderSessions();
renderChat();
updateSessionTitle();
rebuildInputHistory();
refreshHealth();
setInterval(refreshHealth, 30000);

if (!isMobile()) sidebar.classList.add("open");
