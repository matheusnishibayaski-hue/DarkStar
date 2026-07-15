import { consumeSseStream, logStreamUrl } from "./api.js";
import { buildExecBlock } from "./exec.js";

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

  chatEl.appendChild(block);
  liveExecBlocks.set(executionId, block);
  scrollChatToBottom();
  return block;
}

export function attachLogStream(executionId, scrollChatToBottom) {
  if (liveLogStreams.has(executionId)) return;

  const block = liveExecBlocks.get(executionId);
  const rawEl = block?.querySelector(".exec-live-out");
  if (!rawEl) return;

  const es = new EventSource(logStreamUrl(executionId));
  liveLogStreams.set(executionId, es);

  es.addEventListener("line", (e) => {
    try {
      const data = JSON.parse(e.data);
      const prefix = data.stream === "stderr" ? "[stderr] " : "";
      rawEl.textContent += prefix + data.text + "\n";
      scrollChatToBottom(false);
    } catch { /* ignore */ }
  });

  es.addEventListener("done", () => closeLiveStream(executionId));
  es.onerror = () => closeLiveStream(executionId);
}

export function finalizeLiveExecBlock(chatEl, exec) {
  closeLiveStream(exec.log_file_id);
  const existing = liveExecBlocks.get(exec.log_file_id);
  if (existing) {
    existing.replaceWith(buildExecBlock(exec));
    liveExecBlocks.delete(exec.log_file_id);
    return;
  }
  chatEl.appendChild(buildExecBlock(exec));
}

/** Handlers SSE reutilizáveis para chat e auto-pilot. */
export function createToolStreamHandlers({ chatEl, showTyping, hideTyping, scrollChatToBottom }) {
  return {
    tool_start(data) {
      createLiveExecBlock(chatEl, scrollChatToBottom, data.execution_id, data.command);
      attachLogStream(data.execution_id, scrollChatToBottom);
      showTyping(`executando: ${(data.command || "").split(" ")[0] || "tool"}`);
    },
    tool_done() {
      hideTyping();
      showTyping("analisando resultado…");
    },
    round_start(data) {
      showTyping(`rodada ${data.round}/${data.max_rounds} · ${data.tools_executed} cmd(s)`);
    },
    mission_start(data) {
      showTyping(`auto-pilot: ${data.target}`);
    },
  };
}

export function finalizeToolExecutions(chatEl, toolExecutions) {
  for (const exec of toolExecutions || []) {
    finalizeLiveExecBlock(chatEl, exec);
  }
}

export async function consumeChatStream(response, handlers) {
  const mapped = {
    tool_start: handlers.onToolStart || handlers.tool_start,
    tool_done: handlers.onToolDone || handlers.tool_done,
    mission_start: handlers.onMissionStart || handlers.mission_start,
    round_start: handlers.onRoundStart || handlers.round_start,
    done: handlers.onDone || handlers.done,
    error: handlers.onError || handlers.error,
  };
  await consumeSseStream(response, mapped);
}
