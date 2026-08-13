/**
 * Página Workspace — ferramentas/logs/relatórios/mapa/dashboard
 * escopados à conversa ativa (sem modal). Carteira vive em Relatórios.
 */

import { getActiveSession, sessionTitle } from "./sessions.js";
import { openToolsPanel, syncToolFromSession } from "./tools-panel.js";
import { openSessionLogsModal } from "./session-logs-modal.js";
import { openSessionReportModal } from "./session-report-modal.js";
import { refreshPortfolio } from "./portfolio.js";
import { refreshDashboard } from "./dashboard.js";
import { refreshSessionMap } from "./threatmap.js";
import { dismissSidebarDrawer } from "./ui.js";

let open = false;
let activeTab = "tools";

const TABS = ["tools", "logs", "report", "mapa", "dashboard"];
const TAB_ALIAS = { carteira: "report" };

export function isWorkspaceOpen() {
  return open;
}

export function initWorkspace() {
  document.getElementById("btn-workspace")?.addEventListener("click", () => {
    openWorkspace(activeTab || "tools");
    dismissSidebarDrawer();
  });
  document.getElementById("workspace-back")?.addEventListener("click", () => closeWorkspace());
  document.getElementById("workspace-tabs")?.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-ws-tab]");
    if (!btn) return;
    const tab = btn.getAttribute("data-ws-tab");
    if (tab) selectTab(tab);
  });
}

export function openWorkspace(tab = "tools") {
  const view = document.getElementById("view-workspace");
  const terminal = document.getElementById("terminal");
  if (!view) return;
  open = true;
  view.hidden = false;
  if (terminal) terminal.hidden = true;
  syncHeader();
  const resolved = TAB_ALIAS[tab] || tab;
  selectTab(TABS.includes(resolved) ? resolved : "tools");
}

export function closeWorkspace() {
  const view = document.getElementById("view-workspace");
  const terminal = document.getElementById("terminal");
  open = false;
  if (view) view.hidden = true;
  if (terminal) terminal.hidden = false;
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
    case "mapa":
      await refreshSessionMap();
      break;
    case "dashboard":
      await refreshDashboard();
      break;
    default:
      break;
  }
}
