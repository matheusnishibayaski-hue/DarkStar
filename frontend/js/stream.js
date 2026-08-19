import { consumeSseStream, logStreamUrl } from "./api.js";
import { buildExecBlock } from "./exec.js";
import { playSound } from "./audio.js";
import { getActiveSession } from "./sessions.js";
import {
  addLiveExec,
  appendLiveLog,
  getRun,
  setRunTyping,
} from "./session-runs.js";

const liveLogStreams = new Map();
const liveExecBlocks = new Map();

export function closeLiveStream(executionId) {
  const es = liveLogStreams.get(executionId);
  if (es) {
    es.close();
    liveLogStreams.delete(executionId);
  }
}

export function closeAllLiveStreams() {
  for (const id of [...liveLogStreams.keys()]) closeLiveStream(id);
}

function isViewing(sessionId) {
  return Boolean(sessionId && getActiveSession()?.id === sessionId);
}

export function createLiveExecBlock(chatEl, scrollChatToBottom, executionId, command) {
  const block = buildExecBlock({
    command,
    reason: "",
    success: false,
    exit_code: -1,
    blocked: false,
    stdout: "",
    stderr: "",
    log_file_id: executionId,
    tool: "",
  });
  block.classList.add("term-exec-live", "open");
  block.dataset.execId = executionId;

  const badge = block.querySelector(".term-exec-header span");
  if (badge) {
    badge.className = "status-live";
    badge.textContent = "[live]";
  }

  const rawWrap = block.querySelector(".exec-raw");
  if (rawWrap) {
    rawWrap.classList.remove("hidden");
    rawWrap.textContent = "";
    rawWrap.classList.add("exec-live-out");
  }

  block.querySelectorAll(".dash-panel").forEach((el) => el.remove());
  const actions = block.querySelector(".exec-actions");
  if (actions) actions.style.display = "none";

  chatEl?.appendChild(block);
  liveExecBlocks.set(executionId, block);
  scrollChatToBottom?.();
  return block;
}

export function attachLogStream(executionId, scrollChatToBottom, sessionId) {
  if (liveLogStreams.has(executionId)) return;

  const es = new EventSource(logStreamUrl(executionId));
  liveLogStreams.set(executionId, es);

  es.addEventListener("line", (e) => {
    try {
      const data = JSON.parse(e.data);
      const prefix = data.stream === "stderr" ? "[stderr] " : "";
      const chunk = prefix + data.text + "\n";
      if (sessionId) appendLiveLog(sessionId, executionId, chunk);
      if (isViewing(sessionId)) {
        const block = liveExecBlocks.get(executionId);
        const rawEl = block?.querySelector(".exec-live-out");
        if (rawEl) rawEl.textContent += chunk;
        scrollChatToBottom?.(false);
      }
    } catch { /* ignore */ }
  });

  es.addEventListener("done", () => closeLiveStream(executionId));
  es.onerror = () => closeLiveStream(executionId);
}

export function restoreLiveBlocks(chatEl, sessionId, scrollChatToBottom) {
  const run = getRun(sessionId);
  if (!run || !chatEl) return;
  for (const row of run.live) {
    const block = createLiveExecBlock(chatEl, scrollChatToBottom, row.id, row.command);
    const rawEl = block.querySelector(".exec-live-out");
    if (rawEl) rawEl.textContent = row.text;
    attachLogStream(row.id, scrollChatToBottom, sessionId);
  }
}

export function finalizeLiveExecBlock(chatEl, exec) {
  closeLiveStream(exec.log_file_id);
  const existing = liveExecBlocks.get(exec.log_file_id);
  if (existing && existing.isConnected) {
    existing.replaceWith(buildExecBlock(exec));
    liveExecBlocks.delete(exec.log_file_id);
  } else if (chatEl) {
    chatEl.appendChild(buildExecBlock(exec));
  }
  if (exec.blocked) playSound("exec_blocked");
  else if (exec.success) playSound("exec_ok");
  else playSound("exec_fail");
}

/** Handlers SSE reutilizáveis para chat e auto-pilot. */
export function createToolStreamHandlers({
  chatEl,
  showTyping,
  hideTyping,
  scrollChatToBottom,
  sessionId,
}) {
  return {
    tool_start(data) {
      if (sessionId) addLiveExec(sessionId, data.execution_id, data.command);
      if (isViewing(sessionId)) {
        createLiveExecBlock(chatEl, scrollChatToBottom, data.execution_id, data.command);
      }
      attachLogStream(data.execution_id, scrollChatToBottom, sessionId);
      const label = `executando: ${(data.command || "").split(" ")[0] || "tool"}`;
      if (sessionId) setRunTyping(sessionId, label);
      if (isViewing(sessionId)) showTyping(label);
    },
    tool_done(data) {
      if (isViewing(sessionId)) {
        hideTyping();
        showTyping("analisando resultado…");
      }
      if (sessionId) setRunTyping(sessionId, "analisando resultado…");
      window.dispatchEvent(new CustomEvent("darkstar:tool-done", { detail: data || {} }));
    },
    round_start(data) {
      const label = `rodada ${data.round}/${data.max_rounds} · ${data.tools_executed} cmd(s)`;
      if (sessionId) setRunTyping(sessionId, label);
      if (isViewing(sessionId)) showTyping(label);
    },
    mission_start(data) {
      const label = `auto-pilot: ${data.target}`;
      if (sessionId) setRunTyping(sessionId, label);
      if (isViewing(sessionId)) showTyping(label);
    },
  };
}

export function finalizeToolExecutions(chatEl, toolExecutions) {
  for (const exec of toolExecutions || []) {
    finalizeLiveExecBlock(chatEl, exec);
  }
}

export async function consumeChatStream(response, handlers, options = {}) {
  const mapped = {
    tool_start: handlers.onToolStart || handlers.tool_start,
    tool_done: handlers.onToolDone || handlers.tool_done,
    mission_start: handlers.onMissionStart || handlers.mission_start,
    round_start: handlers.onRoundStart || handlers.round_start,
    done: handlers.onDone || handlers.done,
    error: handlers.onError || handlers.error,
  };
  await consumeSseStream(response, mapped, options);
}
