/** Envio de mensagens — relatório via modal session-report-modal.js */

import { HISTORY_LIMIT } from "./constants.js";
import { apiFetch } from "./api.js";
import {
  getActiveSession,
  getSessionById,
  ensureSession,
  sessionTitle,
  saveStore,
  saveStoreNow,
  renderSessions,
  updateSessionTitle,
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
  syncMissionButton,
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
import { toast, showToastError } from "./ui.js";
import { playSound } from "./audio.js";
import { startRun, isSessionBusy } from "./session-runs.js";
import { getChatMode, getAttachments, clearAttachments } from "./composer-extras.js";
import { isOffensiveModeEnabled } from "./offensive-mode.js";
import { isOfflineModeEnabled } from "./offline-mode.js";

let ctx = {};

/** Prompt fixo: pasta/repo anexado → relatório de achados. */
export function buildFolderPentestPrompt(folderName) {
  const name = (folderName || "projeto anexado").trim() || "projeto anexado";
  return (
    `[Pentest white-box automático]\n` +
    `Projeto: ${name}\n\n` +
    `Analise o mapa e os arquivos em [Anexos]/[PROJECT INTEL] ANTES de qualquer resposta ao usuário.\n` +
    `Missão: pentest white-box do repositório. Entregue SOMENTE o relatório final com achados.\n\n` +
    `Formato obrigatório:\n` +
    `## Resumo\n` +
    `## Achados (crítico → baixo, com path/evidência)\n` +
    `## Superfície / alvos derivados do código\n` +
    `## Recomendações priorizadas\n\n` +
    `Regras:\n` +
    `- Não cumprimente, não peça confirmação, não diga que vai analisar.\n` +
    `- Cite paths do código como evidência.\n` +
    `- Se o intel tiver host/URL do próprio app (não dependências npm/pypi), use ferramentas Kali e incorpore no relatório.\n` +
    `- Sem alvo de rede: foque em achados estáticos (secrets, auth, injeção, misconfig, exposição).`
  );
}

/**
 * Dispara pentest assim que a pasta/repo fica pronta.
 * @param {{ folderName?: string, error?: string }} [summary]
 */
export async function startFolderPentest(summary = {}) {
  if (summary?.error) return;
  ensureSession();
  const session = getActiveSession();
  if (!session) return;
  if (isSessionBusy(session.id)) {
    toast("Pasta anexada — o pentest automático começa quando a missão atual terminar", "warn");
    return;
  }
  if (!getAttachments().length) {
    toast("Pasta anexada sem conteúdo legível para pentest", "warn");
    return;
  }
  toast("Pentest automático do projeto…", "info");
  await sendMessage(buildFolderPentestPrompt(summary.folderName), {
    typingLabel: "analisando projeto…",
    folderName: summary.folderName,
  });
}

export function initChat(context) {
  ctx = context;
}

function isViewing(sessionId) {
  return getActiveSession()?.id === sessionId;
}

function persistSession(session) {
  if (!session) return;
  session.updatedAt = Date.now();
  saveStoreNow(session).catch((err) => console.warn("chat_persist_failed", err));
}

function setViewBusy(sessionId) {
  const viewing = isViewing(sessionId);
  if (ctx.input) ctx.input.disabled = viewing && isSessionBusy(sessionId);
  syncMissionButton();
  ctx.updateStatusBar?.();
}

export async function sendMessage(text, opts = {}) {
  ensureSession();
  const session = getActiveSession();
  if (!session || !text.trim() || isSessionBusy(session.id)) return;

  const sessionId = session.id;
  session.preferredTool = preferredTool;
  saveStore();

  const history = session.messages
    .filter((m) => m && m.kind !== "folder-ingest" && m.kind !== "pending-attachments" && m.role !== "system")
    .slice(-HISTORY_LIMIT)
    .map((m) => ({ role: m.role, content: m.content }));

  const missionId = createMissionId();
  const abortController = new AbortController();
  startRun(sessionId, { missionId, abort: abortController, kind: "chat" });
  beginMission(missionId, abortController, sessionId);
  setViewBusy(sessionId);
  playSound("send");

  const attachments = getAttachments();
  clearAttachments({ persist: true });

  if (ctx.input) {
    ctx.input.value = "";
    ctx.inputHistory.idx = ctx.inputHistory.list.length;
  }

  const isAutoPentest = text.includes("[Pentest white-box automático]");
  const displayText = isAutoPentest
    ? `Pentest automático · ${String(opts.folderName || "projeto").trim() || "projeto"}`
    : text;

  const isFirst = session.messages.length === 0;
  const now = Date.now();
  session.messages.push({
    role: "user",
    content: text,
    display: isAutoPentest ? displayText : undefined,
    at: now,
  });
  persistSession(session);
  if (isFirst || session.title === "novo chat") {
    if (isAutoPentest) {
      const label = String(opts.folderName || "projeto").trim().slice(0, 40) || "projeto";
      session.title = `pentest: ${label}`;
    } else {
      session.title = sessionTitle(session);
    }
  }
  saveStore();
  renderSessions();
  updateSessionTitle();

  const typingLabel = opts.typingLabel || "processando";

  if (isViewing(sessionId)) {
    if (isFirst) renderChat();
    else appendUserLine(displayText);
    showTyping(typingLabel);
  }

  const target = () => getSessionById(sessionId) || session;

  const chatMode = isAutoPentest ? "agent" : getChatMode();

  try {
    const res = await apiFetch("/api/chat/stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: text,
        history,
        preferred_tool: preferredTool,
        mission_id: missionId,
        chat_session_id: sessionId,
        chat_mode: chatMode,
        offensive: isOffensiveModeEnabled(),
        offline: isOfflineModeEnabled(),
        attachments,
        ...getModelPayload(),
      }),
      signal: abortController.signal,
    });

    if (isViewing(sessionId)) hideTyping();

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      const errMsg = `erro: ${err.detail || res.statusText}`;
      target().messages.push({ role: "assistant", content: errMsg, at: Date.now() });
      persistSession(target());
      if (isViewing(sessionId)) {
        appendLine("error", errMsg);
        showToastError(errMsg);
      }
      return;
    }

    let finalData = null;

    await consumeChatStream(res, {
      ...createToolStreamHandlers({
        chatEl: ctx.chatEl,
        showTyping,
        hideTyping,
        scrollChatToBottom,
        sessionId,
      }),
      done(data) {
        finalData = data;
      },
      error(data) {
        throw new Error(data.detail || "Erro no stream");
      },
    }, { signal: abortController.signal });

    if (isViewing(sessionId)) hideTyping();
    closeAllLiveStreams();

    if (isMissionAborted(sessionId)) {
      throw new DOMException("Operação cancelada.", "AbortError");
    }

    if (!finalData) {
      throw new Error("Resposta incompleta do servidor");
    }

    const sess = target();
    if (finalData.stopped_reason === "cancelled") {
      sess.messages.push({ role: "assistant", content: finalData.message, at: Date.now() });
      persistSession(sess);
      if (isViewing(sessionId)) {
        appendAssistantLine(finalData.message);
        toast("operação cancelada", "warn");
      }
      return;
    }

    sess.messages.push({
      role: "assistant",
      content: finalData.message,
      toolExecutions: finalData.tool_executions || [],
      at: Date.now(),
    });
    persistSession(sess);
    renderSessions();
    window.dispatchEvent(new CustomEvent("darkstar:session-updated"));

    if (isViewing(sessionId)) {
      appendAssistantLine(finalData.message);
      for (const exec of finalData.tool_executions || []) {
        finalizeLiveExecBlock(ctx.chatEl, exec);
      }
      if ((finalData.tool_executions || []).length === 0) playSound("success");
      scrollChatToBottom();
    }
  } catch (e) {
    if (isViewing(sessionId)) hideTyping();
    closeAllLiveStreams();
    const sess = target();
    if (e.name === "AbortError") {
      const errMsg = "Operação cancelada pelo usuário.";
      sess.messages.push({ role: "assistant", content: errMsg, at: Date.now() });
      persistSession(sess);
      if (isViewing(sessionId)) {
        appendLine("info", errMsg);
        toast("cancelado", "warn");
      }
    } else {
      const errMsg = `erro de conexão: ${e.message}`;
      sess.messages.push({ role: "assistant", content: errMsg, at: Date.now() });
      persistSession(sess);
      if (isViewing(sessionId)) {
        appendLine("error", errMsg);
        showToastError(errMsg);
      }
    }
  } finally {
    endMission(sessionId);
    setViewBusy(sessionId);
    rebuildInputHistory(ctx.inputHistory);
    if (isViewing(sessionId)) ctx.input?.focus();
  }
}

export function rebuildInputHistoryRef() {
  rebuildInputHistory(ctx.inputHistory);
}
