/** Modo Auto-Pilot autônomo. */

import { apiFetch } from "./api.js";
import {
  getActiveSession,
  ensureSession,
  saveStore,
  renderSessions,
  updateSessionTitle,
  rebuildInputHistory,
} from "./sessions.js";
import { getModelPayload } from "./tools-panel.js";
import {
  closeAllLiveStreams,
  createToolStreamHandlers,
  consumeChatStream,
  finalizeLiveExecBlock,
} from "./stream.js";
import {
  beginMission,
  endMission,
  createMissionId,
  isMissionAborted,
} from "./mission.js";
import {
  renderChat,
  appendAssistantLine,
  appendLine,
  showAutopilotProgress,
  hideTyping,
  scrollChatToBottom,
} from "./chat-view.js";
import { toast, showToastError, downloadMarkdown, setLoading, getLoading, closeOverlay } from "./ui.js";

let ctx = {};

export function initAutopilot(context) {
  ctx = context;
}

function setBusy(busy) {
  setLoading(busy);
  if (ctx.input) ctx.input.disabled = busy;
  if (ctx.autopilotStart) ctx.autopilotStart.disabled = busy;
  if (ctx.btnAutopilot) ctx.btnAutopilot.disabled = busy;
  ctx.updateStatusBar?.();
}

export async function startAutopilot() {
  const target = ctx.autopilotTarget?.value.trim();
  const objective = ctx.autopilotObjective?.value.trim();

  if (!target || !objective) {
    showToastError("Informe o alvo e o objetivo da missão.");
    return;
  }

  if (getLoading()) return;

  ensureSession();
  const session = getActiveSession();
  closeOverlay(ctx.overlayAutopilot);

  const userMsg = `[Auto-Pilot]\nAlvo: ${target}\nObjetivo: ${objective}`;
  const missionId = createMissionId();
  const abortController = new AbortController();
  beginMission(missionId, abortController);
  setBusy(true);

  const isFirst = session.messages.length === 0;
  session.messages.push({ role: "user", content: userMsg });
  session.updatedAt = Date.now();
  if (isFirst || session.title === "novo chat") session.title = `pilot: ${target}`;
  saveStore();
  renderSessions();
  updateSessionTitle();
  renderChat();
  showAutopilotProgress("auto-pilot em execução — planejando, executando e analisando (pode levar vários minutos)");

  try {
    let finalData = null;

    const res = await apiFetch("/api/autonomous/stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target,
        objective,
        mission_id: missionId,
        ...getModelPayload(),
      }),
      signal: abortController.signal,
    });

    hideTyping();

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      const errMsg = `erro auto-pilot: ${err.detail || res.statusText}`;
      session.messages.push({ role: "assistant", content: errMsg });
      saveStore();
      appendLine("error", errMsg);
      showToastError(errMsg);
      return;
    }

    await consumeChatStream(res, {
      ...createToolStreamHandlers({
        chatEl: ctx.chatEl,
        showTyping: showAutopilotProgress,
        hideTyping,
        scrollChatToBottom,
      }),
      done(data) {
        finalData = data;
      },
      error(data) {
        throw new Error(data.detail || "Erro no stream");
      },
    }, { signal: abortController.signal });

    hideTyping();
    closeAllLiveStreams();

    if (isMissionAborted()) {
      throw new DOMException("Missão cancelada.", "AbortError");
    }

    if (!finalData) {
      throw new Error("Resposta incompleta do auto-pilot");
    }

    const data = finalData;
    session.messages.push({
      role: "assistant",
      content: data.message,
      toolExecutions: data.tool_executions || [],
      autopilot: {
        objective_met: data.objective_met,
        rounds: data.rounds,
        stopped_reason: data.stopped_reason,
        tools_executed: data.tools_executed,
      },
    });
    session.updatedAt = Date.now();
    saveStore();
    renderSessions();

    appendAssistantLine(data.message);
    for (const exec of data.tool_executions || []) {
      finalizeLiveExecBlock(ctx.chatEl, exec);
    }
    scrollChatToBottom();

    if (data.report && data.stopped_reason !== "cancelled") {
      const safeName = target.replace(/[^\w.-]+/g, "_").slice(0, 40);
      downloadMarkdown(data.report, `relatorio-autopilot-${safeName}.md`);
      appendLine(
        "info",
        `relatório auto-pilot baixado · ${data.tools_executed} cmd(s) · ${data.rounds} rodada(s) · ${data.objective_met ? "objetivo atingido" : data.stopped_reason}`
      );
      toast(`auto-pilot concluído · ${data.tools_executed} comandos`, "success");
    } else if (data.stopped_reason === "cancelled") {
      toast("auto-pilot cancelado", "warn");
    }
  } catch (e) {
    hideTyping();
    closeAllLiveStreams();
    if (e.name === "AbortError") {
      const errMsg = "auto-pilot cancelado pelo usuário.";
      session.messages.push({ role: "assistant", content: errMsg });
      saveStore();
      appendLine("info", errMsg);
      toast("missão cancelada", "warn");
    } else {
      const errMsg = `erro de conexão auto-pilot: ${e.message}`;
      session.messages.push({ role: "assistant", content: errMsg });
      saveStore();
      appendLine("error", errMsg);
      showToastError(errMsg);
    }
  } finally {
    endMission();
    setBusy(false);
    rebuildInputHistory(ctx.inputHistory);
    ctx.input?.focus();
  }
}
