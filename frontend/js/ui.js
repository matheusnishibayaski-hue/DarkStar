/** UI compartilhada: toasts, sidebar, overlays, status, health. */

import { QUICK_PROMPTS } from "./constants.js";
import { selectedModel, getPreferredTool, openToolsPanel } from "./tools-panel.js";
import { collectSessionExecutions, getActiveSession } from "./sessions.js";
import { apiFetch } from "./api.js";

let ctx = {};

export function initUi(context) {
  ctx = context;
}

export function toast(msg, type = "info", ms = 4000) {
  const { toastContainer } = ctx;
  if (!toastContainer) return;
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

export function isMobile() {
  return window.matchMedia("(max-width: 768px)").matches;
}

export function openSidebar() {
  const { sidebar, sidebarBackdrop } = ctx;
  sidebar?.classList.add("open");
  if (isMobile() && sidebarBackdrop) sidebarBackdrop.hidden = false;
}

export function closeSidebar() {
  const { sidebar, sidebarBackdrop } = ctx;
  sidebar?.classList.remove("open");
  if (sidebarBackdrop) sidebarBackdrop.hidden = true;
}

export function toggleSidebar() {
  if (ctx.sidebar?.classList.contains("open")) closeSidebar();
  else openSidebar();
}

export function openOverlay(overlay) {
  closeSidebar();
  if (!overlay) return;
  overlay.hidden = false;
  if (overlay === ctx.overlayTools) ctx.toolSearch?.focus();
  if (overlay === ctx.overlayAutopilot) ctx.autopilotTarget?.focus();
}

export function closeOverlay(overlay) {
  if (!overlay) return;
  overlay.hidden = true;
  ctx.input?.focus();
}

export function closeAllOverlays(closeToolsPanelMenus) {
  closeOverlay(ctx.overlayTools);
  closeOverlay(ctx.overlayAutopilot);
  closeOverlay(ctx.overlayHelp);
  closeToolsPanelMenus?.();
}

export function updateStatusBar({ loading }) {
  const { statusBarText, healthData } = ctx;
  if (!statusBarText) return;

  const session = getActiveSession();
  const execCount = collectSessionExecutions(session).length;
  const parts = [];

  if (healthData) {
    if (healthData.docker && healthData.kali_container) parts.push("kali ok");
    else if (!healthData.docker) parts.push("docker off");
    else parts.push("kali off");
  }
  parts.push(`tools:${getPreferredTool()}`);
  if (selectedModel) parts.push(selectedModel.name);
  if (session) parts.push(`${session.messages.length} msg`);
  if (execCount) parts.push(`${execCount} exec`);
  if (loading) parts.push("…");

  statusBarText.textContent = parts.join(" · ") || "pronto";
}

export async function refreshHealth() {
  const { statusBarText } = ctx;
  try {
    const res = await apiFetch("/api/health");
    if (!res.ok) return;
    ctx.healthData = await res.json();
    updateStatusBar({ loading: ctx.loading });
    if (ctx.healthData.docker && !ctx.healthData.kali_container) {
      statusBarText.title = ctx.healthData.kali_error || "Container Kali não está rodando";
    } else if (statusBarText) {
      statusBarText.title = "";
    }
  } catch { /* ignore */ }
}

export function renderWelcome() {
  const { input, overlayAutopilot, overlayHelp } = ctx;
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
  wrap.querySelector('[data-action="tools"]').addEventListener("click", () => openToolsPanel());
  wrap.querySelector('[data-action="help"]').addEventListener("click", () => openOverlay(overlayHelp));

  const promptsEl = wrap.querySelector("#welcome-prompts");
  for (const p of QUICK_PROMPTS) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "welcome-prompt";
    btn.textContent = p.label;
    btn.title = p.text;
    btn.addEventListener("click", () => {
      if (input) {
        input.value = p.text;
        input.focus();
      }
    });
    promptsEl.appendChild(btn);
  }

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
