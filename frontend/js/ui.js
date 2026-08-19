/** UI compartilhada: toasts, sidebar, overlays, status, health. */

import { selectedModel, getPreferredTool } from "./tools-panel.js";
import { collectSessionExecutions, getActiveSession } from "./sessions.js";
import { getHealth } from "./api/routes.js";
import { escapeHtml } from "./exec.js";
import { playSound } from "./audio.js";

let ctx = {};

export function initUi(context) {
  ctx = context;
}

export function toast(msg, type = "info", ms = 4000) {
  const { toastContainer } = ctx;
  if (!toastContainer) return;
  if (type === "error") playSound("error");
  else if (type === "warn") playSound("warn");
  else if (type === "success") playSound("success");
  const el = document.createElement("div");
  el.className = `toast toast-${type}`;
  el.textContent = msg;
  toastContainer.appendChild(el);
  setTimeout(() => {
    el.classList.add("toast-out");
    setTimeout(() => el.remove(), 300);
  }, ms);
}

export function showToastError(msg) {
  toast(msg, "error", 6000);
}

const SIDEBAR_COLLAPSE_KEY = "chat-ia-kali-sidebar-collapsed";

export function isMobile() {
  return window.matchMedia("(max-width: 768px)").matches;
}

function syncMenuButton() {
  const btn = document.getElementById("btn-menu");
  if (!btn) return;
  const expanded = isMobile()
    ? Boolean(ctx.sidebar?.classList.contains("open"))
    : !document.body.classList.contains("sidebar-collapsed");
  btn.setAttribute("aria-expanded", expanded ? "true" : "false");
  btn.title = expanded ? "Recolher barra lateral (M)" : "Expandir barra lateral (M)";
}

function syncCollapseButton() {
  const btn = document.getElementById("sidebar-collapse");
  if (!btn || isMobile()) return;
  const collapsed = document.body.classList.contains("sidebar-collapsed");
  btn.textContent = collapsed ? "›" : "‹";
  btn.title = collapsed ? "Expandir barra (M)" : "Recolher barra (M)";
  btn.setAttribute("aria-label", collapsed ? "Expandir barra lateral" : "Recolher barra lateral");
}

export function setSidebarCollapsed(collapsed) {
  document.body.classList.toggle("sidebar-collapsed", Boolean(collapsed));
  try {
    localStorage.setItem(SIDEBAR_COLLAPSE_KEY, collapsed ? "1" : "0");
  } catch {
    /* ignore */
  }
  if (!collapsed) ctx.sidebar?.classList.add("open");
  syncMenuButton();
  syncCollapseButton();
}

/** Restaura preferência no desktop; no mobile começa fechada. */
export function initSidebarState() {
  if (isMobile()) {
    document.body.classList.remove("sidebar-collapsed");
    ctx.sidebar?.classList.remove("open");
    if (ctx.sidebarBackdrop) ctx.sidebarBackdrop.hidden = true;
  } else {
    let collapsed = false;
    try {
      collapsed = localStorage.getItem(SIDEBAR_COLLAPSE_KEY) === "1";
    } catch {
      collapsed = false;
    }
    setSidebarCollapsed(collapsed);
    if (!collapsed) ctx.sidebar?.classList.add("open");
  }
  syncMenuButton();
  syncCollapseButton();
}

export function openSidebar() {
  const { sidebar, sidebarBackdrop } = ctx;
  if (isMobile()) {
    sidebar?.classList.add("open");
    if (sidebarBackdrop) sidebarBackdrop.hidden = false;
  } else {
    setSidebarCollapsed(false);
  }
  syncMenuButton();
}

export function closeSidebar() {
  const { sidebar, sidebarBackdrop } = ctx;
  if (isMobile()) {
    sidebar?.classList.remove("open");
    if (sidebarBackdrop) sidebarBackdrop.hidden = true;
  } else {
    setSidebarCollapsed(true);
  }
  syncMenuButton();
}

export function toggleSidebar() {
  if (isMobile()) {
    if (ctx.sidebar?.classList.contains("open")) closeSidebar();
    else openSidebar();
  } else {
    setSidebarCollapsed(!document.body.classList.contains("sidebar-collapsed"));
  }
}

/** Fecha só a gaveta no celular — não recolhe a barra no desktop. */
export function dismissSidebarDrawer() {
  if (!isMobile()) return;
  ctx.sidebar?.classList.remove("open");
  if (ctx.sidebarBackdrop) ctx.sidebarBackdrop.hidden = true;
  syncMenuButton();
}

export function openOverlay(overlay) {
  dismissSidebarDrawer();
  if (!overlay) return;
  overlay.hidden = false;
  overlay.classList.add("overlay-visible");
  document.body.classList.add("has-overlay");
  playSound("panel");
  if (overlay === ctx.overlayTools) ctx.toolSearch?.focus();
  if (overlay === ctx.overlayAutopilot) ctx.autopilotTarget?.focus();
}

export function closeOverlay(overlay) {
  if (!overlay) return;
  overlay.classList.remove("overlay-visible");
  overlay.hidden = true;
  if (!document.querySelector(".overlay:not([hidden])")) {
    document.body.classList.remove("has-overlay");
  }
  ctx.input?.focus();
}

export function closeAllOverlays(closeToolsPanelMenus) {
  for (const ov of [
    ctx.overlayAutopilot,
    ctx.overlayHelp,
    document.getElementById("overlay-master-key"),
    document.getElementById("overlay-login"),
    document.getElementById("overlay-remediation"),
    document.getElementById("overlay-onboarding"),
    document.getElementById("overlay-triage-gate"),
    document.getElementById("overlay-report-preview"),
    document.getElementById("overlay-github-tree"),
    document.getElementById("overlay-client-new"),
  ]) {
    if (ov) {
      ov.classList.remove("overlay-visible");
      ov.hidden = true;
    }
  }
  document.body.classList.remove("has-overlay");
  closeToolsPanelMenus?.();
  ctx.input?.focus();
}

export function updateStatusBar({ loading }) {
  const { statusBarText, healthData } = ctx;
  if (!statusBarText) return;

  const dockerTag = document.getElementById("status-pill-docker");
  const kaliTag = document.getElementById("status-pill-kali");
  const llmTag = document.getElementById("status-pill-llm");

  if (healthData && dockerTag && kaliTag) {
    dockerTag.textContent = healthData.docker ? "docker:ok" : "docker:off";
    dockerTag.className = "status-tag " + (healthData.docker ? "status-ok" : "status-off");
    if (healthData.kali_container) {
      kaliTag.textContent = "kali:ok";
      kaliTag.className = "status-tag status-ok";
    } else if (healthData.docker) {
      kaliTag.textContent = "kali:warn";
      kaliTag.className = "status-tag status-warn";
    } else {
      kaliTag.textContent = "kali:off";
      kaliTag.className = "status-tag status-off";
    }
  }

  if (llmTag) {
    const offline =
      healthData?.ai_offline === true ||
      healthData?.ai_provider === "ollama" ||
      healthData?.llm?.provider === "ollama";
    const llmOk = healthData?.llm?.ok !== false;
    if (offline) {
      llmTag.textContent = llmOk ? "llm:local" : "llm:ollama?";
      llmTag.className = "status-tag " + (llmOk ? "status-ok" : "status-warn");
      llmTag.title = "Modo offline (Ollama)";
    } else {
      llmTag.textContent = "llm:cloud";
      llmTag.className = "status-tag status-ok";
      llmTag.title = "Modo online (OpenRouter)";
    }
  }

  const session = getActiveSession();
  const execCount = collectSessionExecutions(session).length;
  const parts = [];

  parts.push(`tools:${getPreferredTool()}`);
  if (selectedModel) parts.push(selectedModel.name);
  if (session) parts.push(`${session.messages.length} msg`);
  if (execCount) parts.push(`${execCount} exec`);
  if (loading) parts.push("…");

  statusBarText.textContent = parts.join(" · ") || "pronto";
}

const HEALTH_BANNER_KEY = "kali-health-banner-dismiss";

function healthBannerFingerprint(data) {
  if (!data) return "";
  if (!data.docker) return "docker-off";
  if (!data.kali_container) return "kali-off";
  return "";
}

function updateScopeBanner() {
  const banner = document.getElementById("scope-banner");
  if (!banner) return;
  const data = ctx.healthData;
  if (data?.scope_warning) {
    banner.hidden = false;
    banner.className = "health-banner health-banner--warn scope-banner";
    banner.innerHTML = `
      <div class="health-banner-body">
        <strong class="health-banner-title">Escopo aberto</strong>
        <p class="health-banner-text">Defina alvos no cliente ativo (sidebar) ou <code>ALLOWED_TARGETS</code> no <code>.env</code>. Sem lista, qualquer alvo pode ser usado — apenas em lab com permissão.</p>
      </div>
    `;
  } else {
    banner.hidden = true;
    banner.innerHTML = "";
  }
}

export function updateHealthBanner() {
  const banner = document.getElementById("health-banner");
  if (!banner) return;

  const data = ctx.healthData;
  const fp = healthBannerFingerprint(data);

  if (!fp) {
    sessionStorage.removeItem(HEALTH_BANNER_KEY);
    banner.hidden = true;
    banner.innerHTML = "";
    updateScopeBanner();
    return;
  }

  if (sessionStorage.getItem(HEALTH_BANNER_KEY) === fp) {
    banner.hidden = true;
    return;
  }

  const isDocker = fp === "docker-off";
  const title = isDocker ? "Docker indisponível" : "Container Kali offline";
  const detail = isDocker
    ? 'Ferramentas Kali não executam sem Docker. Abra o Docker Desktop e rode <code>start.bat</code> ou <code>start.bat repair</code>.'
    : `${escapeHtml(data.kali_error || "Container Kali não está rodando.")} — <code>start.bat repair</code> ou <code>docker compose up -d</code> em <code>docker/</code>.`;

  banner.className = `health-banner health-banner--${isDocker ? "error" : "warn"}`;
  banner.hidden = false;
  banner.innerHTML = `
    <div class="health-banner-body">
      <strong class="health-banner-title">${title}</strong>
      <p class="health-banner-text">${detail}</p>
    </div>
    <button type="button" class="health-banner-close" aria-label="Dispensar aviso">×</button>
  `;

  banner.querySelector(".health-banner-close")?.addEventListener("click", () => {
    sessionStorage.setItem(HEALTH_BANNER_KEY, fp);
    banner.hidden = true;
  });

  updateScopeBanner();
}

export async function refreshHealth() {
  const { statusBarText } = ctx;
  try {
    const res = await getHealth();
    if (!res.ok) return;
    ctx.healthData = await res.json();
    updateStatusBar({ loading: ctx.loading });
    updateHealthBanner();
    updateScopeBanner();
    if (ctx.healthData.docker && !ctx.healthData.kali_container) {
      statusBarText.title = ctx.healthData.kali_error || "Container Kali não está rodando";
    } else if (statusBarText) {
      statusBarText.title = "";
    }
  } catch { /* ignore */ }
}

export function renderWelcome() {
  const wrap = document.createElement("div");
  wrap.className = "welcome boot";

  const brand = document.createElement("div");
  brand.className = "welcome-brand";
  brand.innerHTML = `<span class="brand-name">DarkStar</span>`;
  wrap.appendChild(brand);

  const ready = document.createElement("p");
  ready.className = "boot-ready";
  ready.innerHTML = `<span class="boot-msg">Digite o alvo autorizado ou abra o piloto.</span>`;
  wrap.appendChild(ready);

  const hint = document.createElement("p");
  hint.className = "boot-hint";
  hint.textContent = "Trilho à esquerda · chat no centro · seta à direita abre o workspace";
  wrap.appendChild(hint);

  return wrap;
}

export function downloadMarkdown(content, filename) {
  const blob = new Blob([content], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function setLoading(value) {
  ctx.loading = value;
  updateStatusBar({ loading: value });
}

export function getLoading() {
  return Boolean(ctx.loading);
}
