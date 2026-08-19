/** Controle compartilhado de missões (chat stream + auto-pilot). */

import { cancelMission } from "./auth.js";
import { closeAllLiveStreams } from "./stream.js";
import { getActiveSession } from "./sessions.js";
import { endRun, getRun, getRunAbort, isSessionBusy } from "./session-runs.js";

let cancelBtn = null;

export function initMissionControl(btn) {
  cancelBtn = btn;
}

export function createMissionId() {
  return crypto.randomUUID?.() || `m-${Date.now()}`;
}

export function syncMissionButton() {
  const sid = getActiveSession()?.id;
  if (cancelBtn) cancelBtn.hidden = !isSessionBusy(sid);
}

export function beginMission(missionId, abortController, sessionId) {
  void missionId;
  void abortController;
  void sessionId;
  syncMissionButton();
}

export function endMission(sessionId) {
  if (sessionId) endRun(sessionId);
  syncMissionButton();
}

export function getMissionAbortSignal() {
  const sid = getActiveSession()?.id;
  return getRunAbort(sid)?.signal;
}

export async function cancelActiveMission(toast) {
  const sid = getActiveSession()?.id;
  const run = getRun(sid);
  if (!run) return;
  run.abort?.abort();
  await cancelMission(run.missionId);
  closeAllLiveStreams();
  toast?.("cancelando…", "warn");
}

export function isMissionAborted(sessionId) {
  const sid = sessionId || getActiveSession()?.id;
  return Boolean(getRunAbort(sid)?.signal.aborted);
}
