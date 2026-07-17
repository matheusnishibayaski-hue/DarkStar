/** Piloto automático — missão com IA ou roteiro fixo (playbook). */

import { apiFetch } from "./api.js";
import { listPlaybooks, runPlaybook } from "./api/routes.js";
import { QUICK_OBJECTIVES } from "./constants.js";
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
let playbooksCache = [];
/** @type {string} id do roteiro selecionado, ou "" para missão com IA */
let selectedPlaybookId = "";

export function initAutopilot(context) {
  ctx = context;
  renderQuickObjectives();
  loadPlaybookCards();
  ctx.autopilotStart?.addEventListener("click", onPrimaryAction);
  ctx.pilotClearPlaybook?.addEventListener("click", () => selectPlaybook(""));
  ctx.autopilotObjective?.addEventListener("input", () => {
    if (selectedPlaybookId) selectPlaybook("");
  });
  ctx.autopilotTarget?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      onPrimaryAction();
    }
  });
}

function setBusy(busy) {
  setLoading(busy);
  if (ctx.input) ctx.input.disabled = busy;
  if (ctx.autopilotStart) ctx.autopilotStart.disabled = busy;
  if (ctx.btnAutopilot) ctx.btnAutopilot.disabled = busy;
  ctx.updateStatusBar?.();
}

function renderQuickObjectives() {
  const wrap = ctx.quickObjectivesEl;
  if (!wrap) return;
  wrap.innerHTML = "";
  const label = document.createElement("span");
  label.className = "quick-obj-label";
  label.textContent = "Sugestões:";
  wrap.appendChild(label);

  for (const obj of QUICK_OBJECTIVES) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "quick-obj-btn";
    btn.textContent = obj.length > 52 ? `${obj.slice(0, 52)}…` : obj;
    btn.title = obj;
    btn.addEventListener("click", () => {
      selectPlaybook("");
      if (ctx.autopilotObjective) {
        ctx.autopilotObjective.value = obj;
        ctx.autopilotObjective.focus();
      }
      updatePrimaryButton();
    });
    wrap.appendChild(btn);
  }
}

async function loadPlaybookCards() {
  const root = ctx.pilotPlaybooksEl;
  if (!root) return;
  try {
    const res = await listPlaybooks();
    if (!res.ok) return;
    playbooksCache = (await res.json()).playbooks || [];
  } catch {
    playbooksCache = [];
  }

  if (!playbooksCache.length) {
    root.innerHTML = `<p class="pilot-advanced-desc">Nenhum roteiro instalado.</p>`;
    return;
  }

  root.innerHTML = playbooksCache
    .map((pb) => {
      const title = friendlyPlaybookName(pb);
      const desc = pb.description || `${pb.steps_count || "?"} passos`;
      return `
        <button type="button" class="pilot-pb-card" data-pb="${escapeAttr(pb.id)}" aria-pressed="false">
          <strong>${escapeHtml(title)}</strong>
          <span>${escapeHtml(desc)}</span>
          <em>${pb.steps_count || 0} passo(s) · sem IA</em>
        </button>`;
    })
    .join("");

  root.querySelectorAll("[data-pb]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-pb") || "";
      selectPlaybook(selectedPlaybookId === id ? "" : id);
    });
  });
}

function friendlyPlaybookName(pb) {
  const map = {
    "port-scan": "Scan de portas (nmap)",
    "recon-web": "Recon web (subdomínios + HTTP)",
  };
  return map[pb.id] || pb.name || pb.id;
}

function selectPlaybook(id) {
  selectedPlaybookId = id || "";
  const wrap = ctx.autopilotObjectiveWrap;
  const clearBtn = ctx.pilotClearPlaybook;
  const cards = ctx.pilotPlaybooksEl?.querySelectorAll("[data-pb]") || [];

  cards.forEach((c) => {
    const on = c.getAttribute("data-pb") === selectedPlaybookId;
    c.classList.toggle("is-selected", on);
    c.setAttribute("aria-pressed", on ? "true" : "false");
  });

  if (wrap) wrap.classList.toggle("is-dimmed", Boolean(selectedPlaybookId));
  if (clearBtn) clearBtn.hidden = !selectedPlaybookId;

  // Abre o details se escolheu roteiro
  const adv = ctx.pilotAdvanced;
  if (selectedPlaybookId && adv) adv.open = true;

  updatePrimaryButton();
}

function updatePrimaryButton() {
  const btn = ctx.autopilotStart;
  const foot = ctx.pilotFoot;
  if (!btn) return;
  if (selectedPlaybookId) {
    const pb = playbooksCache.find((p) => p.id === selectedPlaybookId);
    const name = pb ? friendlyPlaybookName(pb) : selectedPlaybookId;
    btn.textContent = `Rodar roteiro: ${name}`;
    btn.classList.add("autopilot-start--playbook");
    if (foot) {
      foot.textContent = "Roteiro fixo: mesmos comandos sempre, sem planejamento da IA.";
    }
  } else {
    btn.textContent = "Iniciar missão com IA";
    btn.classList.remove("autopilot-start--playbook");
    if (foot) {
      foot.textContent = "Só use alvos que você tem autorização para testar.";
    }
  }
}

function onPrimaryAction() {
  if (selectedPlaybookId) {
    runSelectedPlaybook();
  } else {
    startAutopilot();
  }
}

async function runSelectedPlaybook() {
  const id = selectedPlaybookId;
  const target = ctx.autopilotTarget?.value.trim();
  if (!id) {
    showToastError("Escolha um roteiro ou inicie a missão com IA.");
    return;
  }
  if (!target) {
    showToastError("Informe o alvo.");
    ctx.autopilotTarget?.focus();
    return;
  }
  if (getLoading()) return;

  setBusy(true);
  closeOverlay(ctx.overlayAutopilot);
  const label = friendlyPlaybookName(playbooksCache.find((p) => p.id === id) || { id });
  appendLine("info", `Roteiro “${label}” → ${target} …`);

  try {
    const res = await runPlaybook(id, {
      target,
      mission_id: createMissionId(),
      chat_session_id: getActiveSession()?.id || "",
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      showToastError(data.detail || "Falha ao executar roteiro");
      return;
    }
    const ok = (data.results || []).filter((r) => r.success).length;
    appendLine("info", `Roteiro concluído: ${ok}/${data.steps_run} passo(s) ok · veja Intel e Arquivos`);
    toast(`Roteiro concluído (${ok} ok)`, "success");
  } catch (e) {
    showToastError(e.message);
  } finally {
    setBusy(false);
    ctx.input?.focus();
  }
}

export async function startAutopilot() {
  const target = ctx.autopilotTarget?.value.trim();
  const objective = ctx.autopilotObjective?.value.trim();

  if (!target) {
    showToastError("Informe o alvo.");
    ctx.autopilotTarget?.focus();
    return;
  }
  if (!objective) {
    showToastError("Descreva o que fazer, ou escolha uma sugestão.");
    ctx.autopilotObjective?.focus();
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
  showAutopilotProgress("Piloto em execução — planejando e testando (pode levar vários minutos)");

  try {
    let finalData = null;

    const res = await apiFetch("/api/autonomous/stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target,
        objective,
        mission_id: missionId,
        chat_session_id: session.id,
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

    await consumeChatStream(
      res,
      {
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
      },
      { signal: abortController.signal }
    );

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
        `Relatório baixado · ${data.tools_executed} cmd(s) · ${data.rounds} rodada(s) · ${
          data.objective_met ? "objetivo atingido" : data.stopped_reason
        }`
      );
      toast(`Missão concluída · ${data.tools_executed} comandos`, "success");
    } else if (data.stopped_reason === "cancelled") {
      toast("Missão cancelada", "warn");
    }
  } catch (e) {
    hideTyping();
    closeAllLiveStreams();
    if (e.name === "AbortError") {
      const errMsg = "Missão cancelada pelo usuário.";
      session.messages.push({ role: "assistant", content: errMsg });
      saveStore();
      appendLine("info", errMsg);
      toast("Missão cancelada", "warn");
    } else {
      const errMsg = `Erro de conexão no piloto: ${e.message}`;
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

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function escapeAttr(s) {
  return escapeHtml(s).replace(/'/g, "&#39;");
}
