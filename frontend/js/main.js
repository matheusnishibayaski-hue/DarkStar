/**
 * Entry point — wiring de módulos ES6.
 */

import { HELP_HTML } from "./constants.js";
import { checkClientConfig } from "./api.js";
import {
  store,
  initSessions,
  loadStore,
  createSession,
  ensureSession,
  renderSessions,
  updateSessionTitle,
} from "./sessions.js";
import {
  initToolsPanel,
  syncToolFromSession,
  closeToolsPanelMenus,
  toggleModelMenu,
  loadModels,
  renderToolList,
  renderQuickObjectives,
  openToolsPanel,
  loadTools,
} from "./tools-panel.js";
import {
  initUi,
  toast,
  toggleSidebar,
  openSidebar,
  closeSidebar,
  openOverlay,
  closeOverlay,
  closeAllOverlays as closeAllUiOverlays,
  refreshHealth,
  updateStatusBar,
  getLoading,
} from "./ui.js";
import {
  initChatView,
  renderChat,
  scrollChatToBottom,
  onChatScroll,
} from "./chat-view.js";
import { initChat, sendMessage, downloadReport, rebuildInputHistoryRef } from "./chat.js";
import { initAutopilot, startAutopilot } from "./autopilot.js";
import { initMissionControl, cancelActiveMission } from "./mission.js";

const chatEl = document.getElementById("chat");
const form = document.getElementById("form");
const input = document.getElementById("input");
const btnMenu = document.getElementById("btn-menu");
const btnTools = document.getElementById("btn-tools");
const btnAutopilot = document.getElementById("btn-autopilot");
const btnCancelMission = document.getElementById("btn-cancel-mission");
const btnReport = document.getElementById("btn-report");
const btnHelp = document.getElementById("btn-help");
const btnNew = document.getElementById("btn-new");
const btnScrollBottom = document.getElementById("btn-scroll-bottom");
const toolSearch = document.getElementById("tool-search");
const modelTrigger = document.getElementById("model-trigger");
const modelMenu = document.getElementById("model-menu");
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
const toastContainer = document.getElementById("toast-container");

const inputHistory = { list: [], idx: -1 };

Object.assign(store, loadStore());

function refreshStatusBar() {
  updateStatusBar({ loading: getLoading() });
}

function closeAllOverlays() {
  closeAllUiOverlays(closeToolsPanelMenus);
}

function newChat() {
  createSession();
  syncToolFromSession();
  renderSessions();
  renderChat();
  updateSessionTitle();
  closeAllOverlays();
  rebuildInputHistoryRef();
  if (input) input.value = "";
  input?.focus();
  toast("novo chat");
}

function handleInputKeydown(e) {
  if (e.key === "ArrowUp") {
    if (inputHistory.list.length === 0) return;
    e.preventDefault();
    if (inputHistory.idx > 0) inputHistory.idx -= 1;
    if (input) input.value = inputHistory.list[inputHistory.idx] || "";
  } else if (e.key === "ArrowDown") {
    if (inputHistory.list.length === 0) return;
    e.preventDefault();
    if (inputHistory.idx < inputHistory.list.length - 1) {
      inputHistory.idx += 1;
      if (input) input.value = inputHistory.list[inputHistory.idx];
    } else {
      inputHistory.idx = inputHistory.list.length;
      if (input) input.value = "";
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
    t: () => { e.preventDefault(); btnTools?.click(); },
    p: () => { e.preventDefault(); openOverlay(overlayAutopilot); },
    r: () => { e.preventDefault(); downloadReport(); },
    k: () => { e.preventDefault(); input?.focus(); },
    "/": () => { e.preventDefault(); openOverlay(overlayHelp); },
  };

  if (shortcuts[key]) shortcuts[key]();
}

// --- Init modules ---
initUi({
  toastContainer,
  sidebar,
  sidebarBackdrop,
  input,
  toolSearch,
  overlayTools,
  overlayAutopilot,
  overlayHelp,
  autopilotTarget,
  statusBarText,
  healthData: null,
  loading: false,
});

initChatView({
  chatEl,
  btnScrollBottom,
  updateStatusBar: refreshStatusBar,
});

initChat({
  chatEl,
  input,
  inputHistory,
  btnReport,
  updateStatusBar: refreshStatusBar,
});

initAutopilot({
  chatEl,
  input,
  inputHistory,
  autopilotTarget,
  autopilotObjective,
  autopilotStart,
  btnAutopilot,
  overlayAutopilot,
  updateStatusBar: refreshStatusBar,
});

initMissionControl(btnCancelMission);

initSessions({
  sessionsEl,
  sessionTitleEl,
  afterSwitchSession: () => {
    renderChat();
    syncToolFromSession();
    closeSidebar();
    input?.focus();
  },
  afterDeleteSession: () => {
    renderChat();
    syncToolFromSession();
    toast("conversa excluída");
  },
});

initToolsPanel({
  toolBadge: document.getElementById("tool-badge"),
  toolList: document.getElementById("tool-list"),
  toolCategoriesEl: document.getElementById("tool-categories"),
  toolSearch,
  modelTrigger,
  modelMenu,
  modelLabel: document.getElementById("model-label"),
  quickObjectivesEl: document.getElementById("quick-objectives"),
  autopilotObjective,
  overlayTools,
  input,
  toast,
  updateStatusBar: refreshStatusBar,
  openOverlay,
  closeOverlay,
});

// --- Events ---
btnMenu?.addEventListener("click", toggleSidebar);
sidebarClose?.addEventListener("click", closeSidebar);
sidebarBackdrop?.addEventListener("click", closeSidebar);
sidebarNew?.addEventListener("click", newChat);
sidebarHelp?.addEventListener("click", () => openOverlay(overlayHelp));

btnTools?.addEventListener("click", () => openToolsPanel());
modelTrigger?.addEventListener("click", (e) => {
  e.stopPropagation();
  toggleModelMenu();
});
document.addEventListener("click", (e) => {
  if (!modelMenu?.hidden && !e.target.closest(".model-picker-wrap")) {
    closeToolsPanelMenus();
  }
});

btnAutopilot?.addEventListener("click", () => openOverlay(overlayAutopilot));
btnCancelMission?.addEventListener("click", () => cancelActiveMission(toast));
btnHelp?.addEventListener("click", () => openOverlay(overlayHelp));
autopilotStart?.addEventListener("click", startAutopilot);
btnReport?.addEventListener("click", downloadReport);
btnNew?.addEventListener("click", newChat);
btnScrollBottom?.addEventListener("click", () => scrollChatToBottom());

toolSearch?.addEventListener("input", () => renderToolList(toolSearch.value));
input?.addEventListener("keydown", handleInputKeydown);
chatEl?.addEventListener("scroll", onChatScroll);

document.querySelectorAll(".panel-close").forEach((btn) => {
  btn.addEventListener("click", () => {
    closeOverlay(document.getElementById(btn.dataset.close));
  });
});

for (const [overlay, id] of [[overlayTools, "overlay-tools"], [overlayAutopilot, "overlay-autopilot"], [overlayHelp, "overlay-help"]]) {
  overlay?.addEventListener("click", (e) => {
    if (e.target === overlay) closeOverlay(document.getElementById(id));
  });
}

document.addEventListener("keydown", handleGlobalKeydown);

form?.addEventListener("submit", (e) => {
  e.preventDefault();
  sendMessage(input?.value || "");
});

// --- Boot ---
if (helpContent) helpContent.innerHTML = HELP_HTML;
renderQuickObjectives();

ensureSession();
loadModels();
checkClientConfig(toast);
loadTools().then(() => renderToolList()).then(() => syncToolFromSession());
renderSessions();
renderChat();
updateSessionTitle();
rebuildInputHistoryRef();
refreshHealth();
setInterval(refreshHealth, 30000);

if (!window.matchMedia("(max-width: 768px)").matches) {
  sidebar?.classList.add("open");
}
