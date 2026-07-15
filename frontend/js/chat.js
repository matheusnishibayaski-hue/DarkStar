/** Envio de mensagens e relatório da sessão. */

import { HISTORY_LIMIT } from "./constants.js";
import { apiFetch } from "./api.js";
import {
  getActiveSession,
  ensureSession,
  sessionTitle,
  saveStore,
  renderSessions,
  updateSessionTitle,
  collectSessionExecutions,
  collectSessionHistory,
  rebuildInputHistory,
} from "./sessions.js";
import { preferredTool, getModelPayload } from "./tools-panel.js";
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
  appendUserLine,
  appendAssistantLine,
  appendLine,
  showTyping,
  hideTyping,
  scrollChatToBottom,
} from "./chat-view.js";
import { toast, showToastError, downloadMarkdown, setLoading, getLoading } from "./ui.js";
import { playSound } from "./audio.js";

let ctx = {};

export function initChat(context) {
  ctx = context;
}

function setBusy(busy) {
  setLoading(busy);
  if (ctx.input) ctx.input.disabled = busy;
  ctx.updateStatusBar?.();
}

export async function downloadReport() {
  const session = getActiveSession();
  if (!session || session.messages.length === 0) {
    showToastError("Nenhuma conversa ativa para gerar relatório.");
    return;
  }

  const toolExecutions = collectSessionExecutions(session);
  if (toolExecutions.length === 0) {
    showToastError("Nenhuma ferramenta foi executada nesta sessão.");
    return;
  }

  const { btnReport } = ctx;
  if (btnReport) {
    btnReport.disabled = true;
    btnReport.textContent = "...";
  }
  ctx.updateStatusBar?.();

  try {
    const res = await apiFetch("/api/generate-report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        history: collectSessionHistory(session),
        tool_executions: toolExecutions,
        title: `Relatório — ${sessionTitle(session)}`,
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      showToastError(`Erro ao gerar relatório: ${err.detail || res.statusText}`);
      return;
    }

    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "relatorio-pentest.md";
    a.click();
    URL.revokeObjectURL(url);
    toast("relatório baixado");
  } catch (e) {
    showToastError(`Erro de conexão: ${e.message}`);
  } finally {
    if (btnReport) {
      btnReport.disabled = false;
      btnReport.textContent = "report";
    }
    ctx.updateStatusBar?.();
  }
}

export async function sendMessage(text) {
  if (!text.trim() || getLoading()) return;

  ensureSession();
  const session = getActiveSession();
  session.preferredTool = preferredTool;
  saveStore();

  const history = session.messages
    .slice(-HISTORY_LIMIT)
    .map((m) => ({ role: m.role, content: m.content }));

  const missionId = createMissionId();
  const abortController = new AbortController();
  beginMission(missionId, abortController);
  setBusy(true);
  playSound("send");

  if (ctx.input) {
    ctx.input.value = "";
    ctx.inputHistory.idx = ctx.inputHistory.list.length;
  }

  const isFirst = session.messages.length === 0;
  session.messages.push({ role: "user", content: text });
  session.updatedAt = Date.now();
  if (isFirst || session.title === "novo chat") session.title = sessionTitle(session);
  saveStore();
  renderSessions();
  updateSessionTitle();

  if (isFirst) renderChat();
  else appendUserLine(text);
  showTyping();

  try {
    const res = await apiFetch("/api/chat/stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: text,
        history,
        preferred_tool: preferredTool,
        mission_id: missionId,
        ...getModelPayload(),
      }),
      signal: abortController.signal,
    });

    hideTyping();

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      const errMsg = `erro: ${err.detail || res.statusText}`;
      session.messages.push({ role: "assistant", content: errMsg });
      saveStore();
      appendLine("error", errMsg);
      showToastError(errMsg);
      return;
    }

    let finalData = null;

    await consumeChatStream(res, {
      ...createToolStreamHandlers({
        chatEl: ctx.chatEl,
        showTyping,
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
      throw new DOMException("Operação cancelada.", "AbortError");
    }

    if (!finalData) {
      throw new Error("Resposta incompleta do servidor");
    }

    if (finalData.stopped_reason === "cancelled") {
      session.messages.push({ role: "assistant", content: finalData.message });
      saveStore();
      appendAssistantLine(finalData.message);
      toast("operação cancelada", "warn");
      return;
    }

    session.messages.push({
      role: "assistant",
      content: finalData.message,
      toolExecutions: finalData.tool_executions || [],
    });
    session.updatedAt = Date.now();
    saveStore();
    renderSessions();

    appendAssistantLine(finalData.message);
    for (const exec of finalData.tool_executions || []) {
      finalizeLiveExecBlock(ctx.chatEl, exec);
    }
    if ((finalData.tool_executions || []).length === 0) {
      playSound("success");
    }
    scrollChatToBottom();
  } catch (e) {
    hideTyping();
    closeAllLiveStreams();
    if (e.name === "AbortError") {
      const errMsg = "Operação cancelada pelo usuário.";
      session.messages.push({ role: "assistant", content: errMsg });
      saveStore();
      appendLine("info", errMsg);
      toast("cancelado", "warn");
    } else {
      const errMsg = `erro de conexão: ${e.message}`;
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

export function rebuildInputHistoryRef() {
  rebuildInputHistory(ctx.inputHistory);
}
