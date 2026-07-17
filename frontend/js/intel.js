/** Intel — painel único de pentest e relatório PDF. */

import { openOverlay, closeOverlay } from "./ui.js";
import { initTargetsHub, loadHub, openSessionInHub } from "./targets-hub.js";

let ctx = {};

export function initIntelPanel(context) {
  ctx = context;
  initTargetsHub({
    hubListEl: ctx.hubListEl,
    hubDetailEl: ctx.hubDetailEl,
    hubMetaEl: ctx.hubMetaEl,
    hubSearch: ctx.hubSearch,
    hubRefresh: ctx.hubRefresh,
    hubReportPdf: ctx.hubReportPdf,
    hubDelete: ctx.hubDelete,
    toast: ctx.toast,
  });
}

export function openIntelPanel(_tab = "hub", sessionId = "") {
  if (!ctx.overlayIntel) return;
  openOverlay(ctx.overlayIntel);
  loadHub(true);
  if (sessionId) openSessionInHub(sessionId);
}

export function closeIntel() {
  if (ctx.overlayIntel) closeOverlay(ctx.overlayIntel);
}
