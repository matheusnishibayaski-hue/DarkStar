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
  openToolsPanel,
  loadTools,
} from "./tools-panel.js";
import {
  initUi,
  toast,
  toggleSidebar,
  openSidebar,
  closeSidebar,
  dismissSidebarDrawer,
  initSidebarState,
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
import { initChat, sendMessage, rebuildInputHistoryRef } from "./chat.js";
import { initSessionLogsModal, openSessionLogsModal } from "./session-logs-modal.js";
import { initSessionReportModal, openReportFromShortcut } from "./session-report-modal.js";
import { initAutopilot, onPilotOffensiveModeChanged } from "./autopilot.js";
import { initOffensiveMode, onOffensiveModeChange } from "./offensive-mode.js";
import { initOfflineMode, onOfflineModeChange } from "./offline-mode.js";
import { initMissionControl, cancelActiveMission } from "./mission.js";
import { initShortcuts, handleGlobalKeydown } from "./shortcuts.js";
import { initFilesPanel, openFilesPanel } from "./files.js";
import { initThreatIntel, openThreatsPanel } from "./threatmap.js";
import { initAudio, bindSoundButton } from "./audio.js";
import { initOnboarding, maybeShowOnboarding } from "./onboarding.js";
import { initGuidedTour, startGuidedTour, stopGuidedTour, isGuidedTourActive } from "./guided-tour.js";
import { deleteSessionLogs, deleteIntelSession } from "./data-admin.js";
import { initMasterKey, isElevated } from "./master-key.js";
import { initClientWorkspace } from "./client-workspace.js";
import { initPortfolio } from "./portfolio.js";
import { initDashboard } from "./dashboard.js";
import { initRemediationWizard } from "./remediation-wizard.js";

const chatEl = document.getElementById("chat");
const form = document.getElementById("form");
const input = document.getElementById("input");
const btnMenu = document.getElementById("btn-menu");
const btnTools = document.getElementById("btn-tools");
const btnAutopilot = document.getElementById("btn-autopilot");
const btnCancelMission = document.getElementById("btn-cancel-mission");
const btnSessionLogs = document.getElementById("btn-session-logs");
const btnSessionReport = document.getElementById("btn-session-report");
const btnFiles = document.getElementById("btn-files");
const btnThreats = document.getElementById("btn-threats");
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
const sidebarCollapse = document.getElementById("sidebar-collapse");
const sidebarNew = document.getElementById("sidebar-new");
const sidebarHelp = document.getElementById("sidebar-help");
const overlayTools = document.getElementById("overlay-tools");
const overlayAutopilot = document.getElementById("overlay-autopilot");
const overlayHelp = document.getElementById("overlay-help");
const overlayFiles = document.getElementById("overlay-files");
const overlayThreats = document.getElementById("overlay-threats");
const helpContent = document.getElementById("help-content");
const autopilotTarget = document.getElementById("autopilot-target");
const autopilotStart = document.getElementById("autopilot-start");
const btnToolbarMore = document.getElementById("btn-toolbar-more");
const toastContainer = document.getElementById("toast-container");
void btnToolbarMore; // stub legado (tour / HTML)

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
    if (isGuidedTourActive()) {
      stopGuidedTour();
      return;
    }
    closeAllOverlays();
    dismissSidebarDrawer();
  },
  openTools: () => openToolsPanel(),
  openPilot: () => openOverlay(overlayAutopilot),
  openHelp: () => startGuidedTour(),
  openThreats: () => openThreatsPanel(),
  openFiles: () => openFilesPanel(),
  downloadReport: () => openReportFromShortcut(),
  openSessionLogs: () => openSessionLogsModal(),
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
  overlayFiles,
  overlayThreats,
  overlaySessionLogs: document.getElementById("overlay-session-logs"),
  overlaySessionReport: document.getElementById("overlay-session-report"),
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
  updateStatusBar: refreshStatusBar,
});

initSessionLogsModal({
  overlaySessionLogs: document.getElementById("overlay-session-logs"),
  logsModalBody: document.getElementById("session-logs-body"),
  btnSessionLogs,
  toast,
});

initSessionReportModal({
  overlaySessionReport: document.getElementById("overlay-session-report"),
  reportModalBody: document.getElementById("session-report-body"),
  reportModalMeta: document.getElementById("session-report-meta"),
  btnSessionReport,
  toast,
});

initAutopilot({
  chatEl,
  input,
  inputHistory,
  autopilotTarget,
  autopilotStart,
  pilotFoot: document.getElementById("pilot-foot"),
  pilotScanOptions: document.getElementById("pilot-scan-options"),
  pilotCustomTools: document.getElementById("pilot-custom-tools"),
  pilotToolGrid: document.getElementById("pilot-tool-grid"),
  pilotToolSearch: document.getElementById("pilot-tool-search"),
  btnAutopilot,
  overlayAutopilot,
  updateStatusBar: refreshStatusBar,
});

initOffensiveMode(document.getElementById("offensive-mode-toggle"));
onOffensiveModeChange(() => {
  void onPilotOffensiveModeChanged();
});

initOfflineMode(document.getElementById("offline-mode-toggle"));
initClientWorkspace();
initPortfolio();
initDashboard();
initRemediationWizard();
onOfflineModeChange(() => {
  refreshStatusBar();
});

initMasterKey({
  onChange: () => {
    refreshStatusBar();
  },
});

initMissionControl(btnCancelMission);

initFilesPanel({
  overlayFiles,
  filesListEl: document.getElementById("files-list"),
  filesMetaEl: document.getElementById("files-meta"),
  filesRefreshBtn: document.getElementById("files-refresh"),
  filesSearch: document.getElementById("files-search"),
  toast,
});

initThreatIntel({
  overlayThreats,
  threatPanel: document.getElementById("threat-panel"),
  threatLegendEl: document.getElementById("threat-legend"),
  threatFrame: document.getElementById("threat-frame"),
  threatLoadingEl: document.getElementById("threat-loading"),
  threatModeLive: document.getElementById("threat-mode-live"),
  threatModeGlobe: document.getElementById("threat-mode-globe"),
  threatOpenFull: document.getElementById("threat-open-full"),
});

initSessions({
  sessionsEl,
  sessionTitleEl,
  afterSwitchSession: () => {
    renderChat();
    syncToolFromSession();
    dismissSidebarDrawer();
    input?.focus();
  },
  afterDeleteSession: () => {
    renderChat();
    syncToolFromSession();
    toast("conversa excluída");
  },
  beforeDeleteSession: (sessionId, logIds) => {
    deleteSessionLogs(sessionId, logIds).catch(() => {});
    deleteIntelSession(sessionId).catch(() => {});
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

try {
  initGuidedTour({
    overlayHelp,
    overlayAutopilot,
    overlayTools,
    input,
    openToolsPanel,
    openFilesPanel,
    openThreatsPanel,
    closeAllOverlays,
  });
} catch (err) {
  console.error("Falha ao iniciar guided tour:", err);
}

// --- Events ---
btnMenu?.addEventListener("click", toggleSidebar);
sidebarClose?.addEventListener("click", closeSidebar);
sidebarCollapse?.addEventListener("click", toggleSidebar);
sidebarBackdrop?.addEventListener("click", closeSidebar);
let wasMobile = window.matchMedia("(max-width: 768px)").matches;
window.addEventListener("resize", () => {
  const mobile = window.matchMedia("(max-width: 768px)").matches;
  if (mobile !== wasMobile) {
    wasMobile = mobile;
    initSidebarState();
  }
});
sidebarNew?.addEventListener("click", newChat);
sidebarHelp?.addEventListener("click", () => startGuidedTour());
btnNew?.addEventListener("click", newChat);

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
btnFiles?.addEventListener("click", () => openFilesPanel());
btnThreats?.addEventListener("click", () => openThreatsPanel());
btnCancelMission?.addEventListener("click", () => cancelActiveMission(toast));
btnHelp?.addEventListener("click", () => startGuidedTour());
btnScrollBottom?.addEventListener("click", () => scrollChatToBottom());

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
  [overlayFiles, "overlay-files"],
  [overlayThreats, "overlay-threats"],
  [document.getElementById("overlay-session-logs"), "overlay-session-logs"],
  [document.getElementById("overlay-session-report"), "overlay-session-report"],
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

initSidebarState();
