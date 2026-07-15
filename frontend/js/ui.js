/** UI compartilhada: toasts, sidebar, overlays, status, health. */

import { QUICK_PROMPTS } from "./constants.js";
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
  requestAnimationFrame(() => overlay.classList.add("overlay-visible"));
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
  for (const ov of [ctx.overlayTools, ctx.overlayAutopilot, ctx.overlayHelp, ctx.overlayIntel, ctx.overlayFiles]) {
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
        <strong class="health-banner-title">// AVISO: escopo aberto</strong>
        <p class="health-banner-text">Defina <code>ALLOWED_TARGETS</code> no <code>.env</code> para restringir scans a alvos autorizados.</p>
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
  const { input } = ctx;
  const wrap = document.createElement("div");
  wrap.className = "welcome boot";

  const bootLines = [
    "[ OK ] pentest-ai kernel 1.1.0 — local mode",
    "[ OK ] docker bridge .................... linked",
    "[ OK ] kali toolchain ................... ready",
    "[ OK ] openrouter agent ................. online",
    "[ OK ] intel db ......................... recon+threats",
    "[ OK ] output volume ..................... /tools/output",
  ];

  const log = document.createElement("div");
  log.className = "boot-log";
  for (const line of bootLines) {
    const row = document.createElement("div");
    row.className = "boot-line";
    row.innerHTML = `<span class="boot-tag">[ OK ]</span> ${escapeHtml(line.replace("[ OK ] ", ""))}`;
    log.appendChild(row);
  }
  wrap.appendChild(log);

  const ready = document.createElement("p");
  ready.className = "boot-ready";
  ready.innerHTML = `
    <span class="cmd-prompt-inline"><span class="cmd-user">kali@pentest</span><span class="cmd-at">:</span><span class="cmd-path">~</span><span class="cmd-sym">$</span></span>
    <span class="boot-msg"> session ready — awaiting input</span>
  `;
  wrap.appendChild(ready);

  const hint = document.createElement("p");
  hint.className = "boot-hint";
  hint.textContent = "# quick commands:";
  wrap.appendChild(hint);

  const promptsEl = document.createElement("div");
  promptsEl.className = "welcome-prompts";
  promptsEl.id = "welcome-prompts";
  wrap.appendChild(promptsEl);
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
