/**
 * Página Workspace — painel lateral (seta + resize).
 * Ferramentas/logs/relatórios/dashboard escopados à conversa.
 */

import { getActiveSession, sessionTitle } from "./sessions.js";
import { openToolsPanel, syncToolFromSession } from "./tools-panel.js";
import { openSessionLogsModal } from "./session-logs-modal.js";
import { openSessionReportModal } from "./session-report-modal.js";
import { refreshPortfolio } from "./portfolio.js";
import { refreshDashboard } from "./dashboard.js";
import { dismissSidebarDrawer } from "./ui.js";

const WIDTH_KEY = "darkstar.workspace-width";
const MIN_PCT = 32;
const MAX_PCT = 72;
const DEFAULT_PCT = 46;

let open = false;
let activeTab = "tools";
let workspacePct = DEFAULT_PCT;

const TABS = ["tools", "logs", "report", "dashboard"];
const TAB_ALIAS = { carteira: "report", triage: "report" };

export function isWorkspaceOpen() {
  return open;
}

function loadWidthPref() {
  try {
    const raw = Number(localStorage.getItem(WIDTH_KEY));
    if (Number.isFinite(raw) && raw >= MIN_PCT && raw <= MAX_PCT) {
      workspacePct = raw;
    }
  } catch {
    /* ignore */
  }
}

function saveWidthPref(pct) {
  try {
    localStorage.setItem(WIDTH_KEY, String(pct));
  } catch {
    /* ignore */
  }
}

function applyWidth() {
  const main = document.querySelector(".main-area");
  const value = `${workspacePct}%`;
  main?.style.setProperty("--workspace-pct", value);
}

function syncEdgeToggle() {
  const btn = document.getElementById("workspace-edge-toggle");
  const handle = document.getElementById("workspace-resize-handle");
  if (btn) {
    btn.classList.toggle("is-open", open);
    btn.setAttribute("aria-expanded", open ? "true" : "false");
    btn.title = open ? "Fechar workspace (Alt+T)" : "Abrir workspace (Alt+T)";
  }
  if (handle) {
    handle.hidden = false;
    handle.setAttribute("aria-hidden", open ? "false" : "true");
  }
}

let closeTimer = 0;

function toggleWorkspace() {
  if (open) closeWorkspace();
  else openWorkspace(activeTab || "tools");
  dismissSidebarDrawer();
}

function initResizeHandle() {
  const handle = document.getElementById("workspace-resize-handle");
  const main = document.querySelector(".main-area");
  if (!handle || !main) return;

  let dragging = false;

  const onMove = (clientX) => {
    if (!dragging) return;
    const rect = main.getBoundingClientRect();
    if (rect.width < 80) return;
    const fromRight = ((rect.right - clientX) / rect.width) * 100;
    workspacePct = Math.min(MAX_PCT, Math.max(MIN_PCT, fromRight));
    applyWidth();
  };

  handle.addEventListener("pointerdown", (e) => {
    if (!open) return;
    dragging = true;
    handle.classList.add("is-dragging");
    main.classList.add("is-resizing");
    handle.setPointerCapture?.(e.pointerId);
    e.preventDefault();
  });

  handle.addEventListener("pointermove", (e) => {
    if (!dragging) return;
    onMove(e.clientX);
  });

  const endDrag = (e) => {
    if (!dragging) return;
    dragging = false;
    handle.classList.remove("is-dragging");
    main.classList.remove("is-resizing");
    try {
      handle.releasePointerCapture?.(e.pointerId);
    } catch {
      /* ignore */
    }
    saveWidthPref(Math.round(workspacePct));
  };

  handle.addEventListener("pointerup", endDrag);
  handle.addEventListener("pointercancel", endDrag);

  handle.addEventListener("dblclick", () => {
    workspacePct = DEFAULT_PCT;
    applyWidth();
    saveWidthPref(DEFAULT_PCT);
  });
}

export function initWorkspace() {
  loadWidthPref();
  applyWidth();

  document.getElementById("workspace-edge-toggle")?.addEventListener("click", () => {
    toggleWorkspace();
  });
  document.getElementById("workspace-back")?.addEventListener("click", () => closeWorkspace());
  initResizeHandle();
  syncEdgeToggle();

  document.getElementById("workspace-tabs")?.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-ws-tab]");
    if (!btn) return;
    const tab = btn.getAttribute("data-ws-tab");
    if (tab) selectTab(tab);
  });
}

export function openWorkspace(tab = "tools") {
  const view = document.getElementById("view-workspace");
  const main = document.querySelector(".main-area");
  if (!view) return;
  if (closeTimer) {
    window.clearTimeout(closeTimer);
    closeTimer = 0;
  }
  open = true;
  view.hidden = false;
  applyWidth();
  syncEdgeToggle();
  // 2 frames: aplica estado fechado no layout, depois anima para aberto
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      main?.classList.add("workspace-open");
    });
  });
  syncHeader();
  const resolved = TAB_ALIAS[tab] || tab;
  selectTab(TABS.includes(resolved) ? resolved : "tools");
}

export function closeWorkspace() {
  const view = document.getElementById("view-workspace");
  const main = document.querySelector(".main-area");
  open = false;
  main?.classList.remove("workspace-open");
  syncEdgeToggle();
  if (closeTimer) window.clearTimeout(closeTimer);
  const reduce =
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  closeTimer = window.setTimeout(() => {
    closeTimer = 0;
    if (!open && view) view.hidden = true;
  }, reduce ? 20 : 340);
}

export function refreshWorkspaceIfOpen() {
  if (!open) return;
  syncHeader();
  selectTab(activeTab, true);
}

function syncHeader() {
  const session = getActiveSession();
  const title = document.getElementById("workspace-title");
  const hint = document.getElementById("workspace-session-hint");
  if (title) title.textContent = session ? sessionTitle(session) : "Sem conversa";
  if (hint) {
    hint.textContent = session
      ? `escopo: conversa ${String(session.id).slice(0, 8)}…`
      : "nenhuma conversa ativa";
  }
}

function selectTab(tab, force = false) {
  tab = TAB_ALIAS[tab] || tab;
  if (!TABS.includes(tab)) return;
  if (!force && tab === activeTab && open) {
    loadTab(tab);
    return;
  }
  activeTab = tab;
  document.querySelectorAll(".workspace-tab").forEach((el) => {
    el.classList.toggle("active", el.getAttribute("data-ws-tab") === tab);
  });
  document.querySelectorAll(".workspace-panel").forEach((el) => {
    const match = el.getAttribute("data-ws-panel") === tab;
    el.hidden = !match;
    el.classList.toggle("active", match);
  });
  loadTab(tab);
}

async function loadTab(tab) {
  syncToolFromSession?.();
  switch (tab) {
    case "tools":
      openToolsPanel();
      break;
    case "logs":
      openSessionLogsModal();
      break;
    case "report":
      openSessionReportModal();
      await refreshPortfolio();
      break;
    case "dashboard":
      await refreshDashboard();
      break;
    default:
      break;
  }
}
