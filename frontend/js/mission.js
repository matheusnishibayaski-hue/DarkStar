/** Controle compartilhado de missões (chat stream + auto-pilot). */

import { cancelMission } from "./auth.js";
import { closeAllLiveStreams } from "./stream.js";

let active = { id: null, abort: null, btn: null };

export function initMissionControl(cancelBtn) {
  active.btn = cancelBtn;
}

export function createMissionId() {
  return crypto.randomUUID?.() || `m-${Date.now()}`;
}

export function beginMission(missionId, abortController) {
  active.id = missionId;
  active.abort = abortController;
  if (active.btn) active.btn.hidden = false;
}

export function endMission() {
  active.id = null;
  active.abort = null;
  if (active.btn) active.btn.hidden = true;
}

export function getMissionAbortSignal() {
  return active.abort?.signal;
}

export async function cancelActiveMission(toast) {
  if (!active.id) return;
  active.abort?.abort();
  await cancelMission(active.id);
  closeAllLiveStreams();
  toast?.("cancelando…", "warn");
}

export function isMissionAborted() {
  return Boolean(active.abort?.signal.aborted);
}
