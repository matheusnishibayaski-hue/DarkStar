/** Corridas de chat/piloto por sessão — o DOM pode mudar; o buffer não. */

/** @type {Map<string, {
 *   missionId: string,
 *   abort: AbortController,
 *   kind: string,
 *   typing: string,
 *   live: Array<{id: string, command: string, text: string}>,
 * }>} */
const runs = new Map();

let onChange = null;

export function setRunsOnChange(fn) {
  onChange = fn;
}

function notify() {
  onChange?.();
  document.body.classList.toggle("mission-live", runs.size > 0);
}

export function startRun(sessionId, { missionId, abort, kind = "chat" }) {
  if (!sessionId) return;
  runs.set(sessionId, {
    missionId,
    abort,
    kind,
    typing: "",
    live: [],
  });
  notify();
}

export function getRun(sessionId) {
  return sessionId ? runs.get(sessionId) || null : null;
}

export function isSessionBusy(sessionId) {
  return Boolean(sessionId && runs.has(sessionId));
}

export function busySessionIds() {
  return [...runs.keys()];
}

export function setRunTyping(sessionId, label) {
  const run = getRun(sessionId);
  if (run) run.typing = label || "";
}

export function addLiveExec(sessionId, executionId, command) {
  const run = getRun(sessionId);
  if (!run || !executionId) return;
  if (run.live.some((x) => x.id === executionId)) return;
  run.live.push({ id: executionId, command: command || "", text: "" });
}

export function appendLiveLog(sessionId, executionId, chunk) {
  const run = getRun(sessionId);
  if (!run) return;
  const row = run.live.find((x) => x.id === executionId);
  if (row) row.text += chunk;
}

export function endRun(sessionId) {
  if (sessionId) runs.delete(sessionId);
  notify();
}

export function getRunAbort(sessionId) {
  return getRun(sessionId)?.abort || null;
}
