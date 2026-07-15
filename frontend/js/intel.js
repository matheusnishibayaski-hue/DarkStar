/** Painel unificado /sys/intel — Recon + CiberAmeaças. */

import { openOverlay, closeOverlay } from "./ui.js";
import { initReconIntel, loadReconTab } from "./recon.js";
import { initThreatIntel, activateThreatsTab } from "./threatmap.js";

let ctx = {};
let activeTab = "recon";

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

  ctx.tabRecon?.addEventListener("click", () => switchTab("recon"));
  ctx.tabThreats?.addEventListener("click", () => switchTab("threats"));
}

function closeIntel() {
  if (ctx.overlayIntel) closeOverlay(ctx.overlayIntel);
}

function switchTab(tab) {
  activeTab = tab;
  ctx.tabRecon?.classList.toggle("active", tab === "recon");
  ctx.tabThreats?.classList.toggle("active", tab === "threats");
  ctx.tabRecon?.setAttribute("aria-selected", tab === "recon" ? "true" : "false");
  ctx.tabThreats?.setAttribute("aria-selected", tab === "threats" ? "true" : "false");
  ctx.paneRecon?.classList.toggle("hidden", tab !== "recon");
  ctx.paneThreats?.classList.toggle("hidden", tab !== "threats");
  ctx.paneRecon?.toggleAttribute("hidden", tab !== "recon");
  ctx.paneThreats?.toggleAttribute("hidden", tab !== "threats");

  if (tab === "recon") loadReconTab();
  if (tab === "threats") activateThreatsTab();
}

export function openIntelPanel(tab = "recon") {
  if (!ctx.overlayIntel) return;
  openOverlay(ctx.overlayIntel);
  switchTab(tab);
}
