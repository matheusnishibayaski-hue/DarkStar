/** Modal Intel — hub de alvos + painéis secundários (logs/audit/limpar). Sem mapa. */

import { openOverlay, closeOverlay } from "./ui.js";
import { initTargetsHub, loadHub, openTargetInHub } from "./targets-hub.js";
import { initTimeline, renderTimeline } from "./timeline.js";
import { initAuditTab, loadAuditTab } from "./audit-tab.js";
import { initDataTab, loadDataTab } from "./data-admin.js";
import { initLogsPanel, loadLogsTab } from "./logs-panel.js";

let ctx = {};

const SECONDARY = ["logs", "audit", "data", "timeline"];

export function initIntelPanel(context) {
  ctx = context;

  initTargetsHub({
    hubListEl: ctx.hubListEl,
    hubDetailEl: ctx.hubDetailEl,
    hubMetaEl: ctx.hubMetaEl,
    hubSearch: ctx.hubSearch,
    hubRefresh: ctx.hubRefresh,
    hubVerify: ctx.hubVerify,
    hubReportMd: ctx.hubReportMd,
    hubReportHtml: ctx.hubReportHtml,
    hubReportZip: ctx.hubReportZip,
    hubFiles: ctx.hubFiles,
    hubChat: ctx.hubChat,
    hubDelete: ctx.hubDelete,
    input: ctx.input,
    toast: ctx.toast,
    onClose: () => closeIntel(),
    onOpenFiles: (filter) => ctx.onOpenFiles?.(filter),
    onDeleted: () => ctx.onDataChanged?.(),
  });

  initTimeline({
    timelineEl: ctx.timelineEl,
    onOpenFiles: () => ctx.onOpenFiles?.(),
    onOpenLogs: () => showSecondary("logs"),
    toast: ctx.toast,
  });

  initAuditTab({
    auditTableEl: ctx.auditTableEl,
    auditMetaEl: ctx.auditMetaEl,
    auditRefresh: ctx.auditRefresh,
    auditPurge: ctx.auditPurge,
    toast: ctx.toast,
    onAuditDeleted: () => ctx.onDataChanged?.(),
  });

  initLogsPanel({
    logsListEl: ctx.logsListEl,
    logsMetaEl: ctx.logsMetaEl,
    logsRefresh: ctx.logsRefresh,
    logsSearch: ctx.logsSearch,
    toast: ctx.toast,
  });

  initDataTab({
    dataBodyEl: ctx.dataBodyEl,
    dataMetaEl: ctx.dataMetaEl,
    dataRefresh: ctx.dataRefresh,
    toast: ctx.toast,
    onDataChanged: () => ctx.onDataChanged?.(),
  });

  ctx.hubBack?.addEventListener("click", () => showHub());
  document.querySelectorAll("[data-intel-more]").forEach((btn) => {
    btn.addEventListener("click", () => showSecondary(btn.getAttribute("data-intel-more")));
  });
}

function closeIntel() {
  if (ctx.overlayIntel) closeOverlay(ctx.overlayIntel);
}

function showHub() {
  ctx.paneHub?.classList.remove("hidden");
  ctx.paneHub?.removeAttribute("hidden");
  SECONDARY.forEach((id) => {
    const pane = ctx[`pane${capitalize(id)}`];
    pane?.classList.add("hidden");
    pane?.setAttribute("hidden", "");
  });
  ctx.hubBack?.setAttribute("hidden", "");
  if (ctx.intelSubtitle) ctx.intelSubtitle.textContent = "escolha um alvo · verifique · baixe o relatório";
  loadHub();
}

function showSecondary(id) {
  ctx.paneHub?.classList.add("hidden");
  ctx.paneHub?.setAttribute("hidden", "");
  SECONDARY.forEach((sid) => {
    const pane = ctx[`pane${capitalize(sid)}`];
    const on = sid === id;
    pane?.classList.toggle("hidden", !on);
    pane?.toggleAttribute("hidden", !on);
  });
  ctx.hubBack?.removeAttribute("hidden");
  if (ctx.intelSubtitle) {
    const labels = { logs: "logs", audit: "auditoria", data: "limpar dados", timeline: "timeline" };
    ctx.intelSubtitle.textContent = labels[id] || id;
  }
  if (id === "logs") loadLogsTab();
  if (id === "audit") loadAuditTab();
  if (id === "data") loadDataTab();
  if (id === "timeline") renderTimeline();
}

function capitalize(s) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export function openIntelPanel(tab = "hub", target = "") {
  if (!ctx.overlayIntel) return;
  openOverlay(ctx.overlayIntel);
  if (SECONDARY.includes(tab)) {
    showSecondary(tab);
  } else {
    showHub();
    if (target) openTargetInHub(target);
  }
}
