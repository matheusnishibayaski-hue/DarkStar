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
import { initShortcuts, handleGlobalKeydown } from "./shortcuts.js";
import { initIntelPanel, openIntelPanel } from "./intel.js";
import { initFilesPanel, openFilesPanel } from "./files.js";
import { initAudio, bindSoundButton } from "./audio.js";
import { initOnboarding, maybeShowOnboarding } from "./onboarding.js";

const chatEl = document.getElementById("chat");
const form = document.getElementById("form");
const input = document.getElementById("input");
const btnMenu = document.getElementById("btn-menu");
const btnTools = document.getElementById("btn-tools");
const btnAutopilot = document.getElementById("btn-autopilot");
const btnCancelMission = document.getElementById("btn-cancel-mission");
const btnReport = document.getElementById("btn-report");
const btnIntel = document.getElementById("btn-intel");
const btnFiles = document.getElementById("btn-files");
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
const overlayIntel = document.getElementById("overlay-intel");
const overlayFiles = document.getElementById("overlay-files");
const helpContent = document.getElementById("help-content");
const autopilotTarget = document.getElementById("autopilot-target");
const autopilotObjective = document.getElementById("autopilot-objective");
const autopilotStart = document.getElementById("autopilot-start");
const playbookSelect = document.getElementById("playbook-select");
const playbookRun = document.getElementById("playbook-run");
const btnToolbarMore = document.getElementById("btn-toolbar-more");
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
  if (e.altKey || e.ctrlKey || e.metaKey) return;
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

initShortcuts({
  onEscape: () => {
    closeAllOverlays();
    closeSidebar();
  },
  openTools: () => openToolsPanel(),
  openPilot: () => openOverlay(overlayAutopilot),
  openHelp: () => openOverlay(overlayHelp),
  openIntel: () => openIntelPanel("recon"),
  openThreats: () => openIntelPanel("threats"),
  openFiles: () => openFilesPanel(),
  downloadReport: () => downloadReport(),
  newChat: () => newChat(),
  focusInput: () => input?.focus(),
  toggleSidebar: () => toggleSidebar(),
});

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
  overlayIntel,
  overlayFiles,
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
  playbookSelect,
  playbookRun,
  btnAutopilot,
  overlayAutopilot,
  updateStatusBar: refreshStatusBar,
});

initMissionControl(btnCancelMission);

initIntelPanel({
  overlayIntel,
  intelPanel: document.getElementById("intel-panel"),
  tabRecon: document.getElementById("intel-tab-recon"),
  tabThreats: document.getElementById("intel-tab-threats"),
  tabTimeline: document.getElementById("intel-tab-timeline"),
  tabAudit: document.getElementById("intel-tab-audit"),
  paneRecon: document.getElementById("intel-pane-recon"),
  paneThreats: document.getElementById("intel-pane-threats"),
  paneTimeline: document.getElementById("intel-pane-timeline"),
  paneAudit: document.getElementById("intel-pane-audit"),
  timelineEl: document.getElementById("intel-timeline"),
  auditTableEl: document.getElementById("audit-table"),
  auditMetaEl: document.getElementById("audit-meta"),
  auditRefresh: document.getElementById("audit-refresh"),
  reconTableEl: document.getElementById("recon-table"),
  reconMetaEl: document.getElementById("recon-meta"),
  reconSearch: document.getElementById("recon-search"),
  reconSort: document.getElementById("recon-sort"),
  reconRefresh: document.getElementById("recon-refresh"),
  threatLegendEl: document.getElementById("threat-legend"),
  threatFrame: document.getElementById("threat-frame"),
  threatLoadingEl: document.getElementById("threat-loading"),
  threatModeLive: document.getElementById("threat-mode-live"),
  threatModeGlobe: document.getElementById("threat-mode-globe"),
  threatOpenFull: document.getElementById("threat-open-full"),
  input,
  onOpenFiles: (filter) => openFilesPanel(filter),
});

initFilesPanel({
  overlayFiles,
  filesListEl: document.getElementById("files-list"),
  filesMetaEl: document.getElementById("files-meta"),
  filesRefreshBtn: document.getElementById("files-refresh"),
  toast,
});

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

initOnboarding({
  onboardingOverlay: document.getElementById("overlay-onboarding"),
  onboardingBody: document.getElementById("onboarding-body"),
  onboardingTitle: document.getElementById("onboarding-title"),
  onboardingNext: document.getElementById("onboarding-next"),
  onboardingSkip: document.getElementById("onboarding-skip"),
  onboardingBackdrop: document.getElementById("overlay-onboarding"),
  input,
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
btnIntel?.addEventListener("click", () => openIntelPanel("recon"));
btnFiles?.addEventListener("click", () => openFilesPanel());
btnCancelMission?.addEventListener("click", () => cancelActiveMission(toast));
btnHelp?.addEventListener("click", () => openOverlay(overlayHelp));
autopilotStart?.addEventListener("click", startAutopilot);
btnReport?.addEventListener("click", downloadReport);
btnNew?.addEventListener("click", newChat);
btnScrollBottom?.addEventListener("click", () => scrollChatToBottom());

btnToolbarMore?.addEventListener("click", () => {
  document.getElementById("term-toolbar-extra")?.classList.toggle("open");
});

toolSearch?.addEventListener("input", () => renderToolList(toolSearch.value));
input?.addEventListener("keydown", handleInputKeydown);
chatEl?.addEventListener("scroll", onChatScroll);

document.querySelectorAll(".panel-close").forEach((btn) => {
  btn.addEventListener("click", () => {
    closeOverlay(document.getElementById(btn.dataset.close));
  });
});

for (const [overlay, id] of [
  [overlayTools, "overlay-tools"],
  [overlayAutopilot, "overlay-autopilot"],
  [overlayHelp, "overlay-help"],
  [overlayIntel, "overlay-intel"],
  [overlayFiles, "overlay-files"],
]) {
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
initAudio();
bindSoundButton(document.getElementById("btn-sound"));

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
maybeShowOnboarding();

const statusClock = document.getElementById("status-clock");
function tickClock() {
  if (!statusClock) return;
  const now = new Date();
  statusClock.textContent = now.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
tickClock();
setInterval(tickClock, 1000);

input?.addEventListener("focus", () => document.getElementById("cmd-cursor")?.classList.add("hidden"));
input?.addEventListener("blur", () => document.getElementById("cmd-cursor")?.classList.remove("hidden"));

if (!window.matchMedia("(max-width: 768px)").matches) {
  sidebar?.classList.add("open");
}
