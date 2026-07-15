/** Painel unificado /sys/intel — Recon + Threats + Timeline + Audit. */

import { openOverlay, closeOverlay } from "./ui.js";
import { initReconIntel, loadReconTab } from "./recon.js";
import { initThreatIntel, activateThreatsTab } from "./threatmap.js";
import { initTimeline, renderTimeline } from "./timeline.js";
import { initAuditTab, loadAuditTab } from "./audit-tab.js";

let ctx = {};

const TABS = ["recon", "threats", "timeline", "audit"];

export function initIntelPanel(context) {
  ctx = context;

  initReconIntel({
    reconTableEl: ctx.reconTableEl,
    reconMetaEl: ctx.reconMetaEl,
    reconSearch: ctx.reconSearch,
    reconSort: ctx.reconSort,
    reconRefresh: ctx.reconRefresh,
    input: ctx.input,
    onClose: () => closeIntel(),
    onOpenFiles: (filter) => ctx.onOpenFiles?.(filter),
  });

  initThreatIntel({
    intelPanel: ctx.intelPanel,
    threatLegendEl: ctx.threatLegendEl,
    threatFrame: ctx.threatFrame,
    threatLoadingEl: ctx.threatLoadingEl,
    threatModeLive: ctx.threatModeLive,
    threatModeGlobe: ctx.threatModeGlobe,
    threatOpenFull: ctx.threatOpenFull,
  });

  initTimeline({
    timelineEl: ctx.timelineEl,
    onOpenFiles: () => ctx.onOpenFiles?.(),
  });

  initAuditTab({
    auditTableEl: ctx.auditTableEl,
    auditMetaEl: ctx.auditMetaEl,
    auditRefresh: ctx.auditRefresh,
  });

  for (const tab of TABS) {
    ctx[`tab${capitalize(tab)}`]?.addEventListener("click", () => switchTab(tab));
  }
}

function capitalize(s) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function closeIntel() {
  if (ctx.overlayIntel) closeOverlay(ctx.overlayIntel);
}

function switchTab(tab) {
  for (const t of TABS) {
    const btn = ctx[`tab${capitalize(t)}`];
    const pane = ctx[`pane${capitalize(t)}`];
    const on = t === tab;
    btn?.classList.toggle("active", on);
    btn?.setAttribute("aria-selected", on ? "true" : "false");
    pane?.classList.toggle("hidden", !on);
    pane?.toggleAttribute("hidden", !on);
  }

  if (tab === "recon") loadReconTab();
  if (tab === "threats") activateThreatsTab();
  if (tab === "timeline") renderTimeline();
  if (tab === "audit") loadAuditTab();
}

export function openIntelPanel(tab = "recon") {
  if (!ctx.overlayIntel) return;
  openOverlay(ctx.overlayIntel);
  switchTab(tab);
}
