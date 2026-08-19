/** Piloto automático — missão com IA por perfil de scan. */

import { apiFetch } from "./api.js";
import { isOffensiveModeEnabled, onOffensiveModeChange } from "./offensive-mode.js";
import { isOfflineModeEnabled, onOfflineModeChange } from "./offline-mode.js";
import {
  getActiveSession,
  getSessionById,
  ensureSession,
  saveStore,
  renderSessions,
  updateSessionTitle,
  rebuildInputHistory,
} from "./sessions.js";
import { getModelPayload, loadTools, toolCategories } from "./tools-panel.js";
import { downloadSessionPdf } from "./session-report-pdf.js";
import { openSessionReportModal } from "./session-report-modal.js";
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
  appendAssistantLine,
  appendLine,
  showAutopilotProgress,
  hideTyping,
  scrollChatToBottom,
} from "./chat-view.js";
import { toast, showToastError, closeOverlay } from "./ui.js";
import { getActiveClientId } from "./client-workspace.js";
import { startRun, isSessionBusy } from "./session-runs.js";
import { getAttachments } from "./composer-extras.js";

let ctx = {};
/** @type {"basic"|"intermediate"|"full"|"custom"} */
let selectedScanProfile = "basic";
/** @type {Set<string>} */
const customToolSelection = new Set();
/** @type {Array<{id:string,label:string,description:string,tool_count:number}>} */
let scanProfileMeta = [];

/** @returns {"safe"|"offensive"|"offline"} */
export function currentEngagementMode() {
  if (isOfflineModeEnabled()) return "offline";
  if (isOffensiveModeEnabled()) return "offensive";
  return "safe";
}

const MODE_OBJECTIVES = {
  safe: {
    basic:
      "Mapear a superfície do alvo autorizado (DNS/portas/HTTP), identificar candidatos relevantes e verificar o que for confirmável com evidência.",
    intermediate:
      "Recon e enumeração ampliada no alvo autorizado; priorizar achados confirmáveis e cobrir a fila da fase atual (não o catálogo inteiro).",
    full: "Engajamento amplo finding-driven: cobrir superfícies quentes, verificar high/critical e documentar gaps — sem checklist cosmética.",
    custom:
      "Usar as ferramentas selecionadas de forma finding-driven no alvo autorizado; evidência antes de finish.",
  },
  offensive: {
    basic:
      "Kill chain curta no alvo autorizado: enum → hipótese de abuso → PoC mínimo (auth/IDOR/injection/misconfig).",
    intermediate:
      "Comprometer evidência: encadear enum→vetores de abuso; priorizar auth bypass, IDOR, API e high/critical.",
    full: "Engajamento ofensivo autorizado: maximizar superfície de abuso verificável; não parar no primeiro 200 OK.",
    custom:
      "Ferramentas escolhidas com mentalidade adversária no alvo autorizado; hipótese → PoC → próximo vetor.",
  },
  offline: {
    basic:
      "Recon low-noise no alvo autorizado: passive-first, pegada mínima, evidência limpa; só escalar ruído se necessário.",
    intermediate:
      "Mapear e verificar com OPSEC: rate baixo, artefatos em /tools/output/, próximo passo o mais silencioso de maior valor.",
    full: "Cobertura fantasma: superfícies quentes com mínimo rastro; PoC cirúrgico; documentar o que foi tocado.",
    custom:
      "Ferramentas selecionadas em modo fantasma — quieto, preciso, só no alvo autorizado.",
  },
};

const MODE_LABELS = { safe: "Safe", offensive: "Offensive", offline: "Offline (fantasma)" };

function defaultObjectiveForSelection() {
  const mode = currentEngagementMode();
  const map = MODE_OBJECTIVES[mode] || MODE_OBJECTIVES.safe;
  return map[selectedScanProfile] || map.basic;
}

function syncPilotModeUi() {
  const mode = currentEngagementMode();
  const badge = document.getElementById("pilot-mode-badge");
  if (badge) badge.textContent = MODE_LABELS[mode] || mode;
  const obj = document.getElementById("autopilot-objective");
  if (obj && (!obj.dataset.touched || obj.value.trim() === "")) {
    obj.value = defaultObjectiveForSelection();
    delete obj.dataset.touched;
  }
}

const DEFAULT_OBJECTIVES = MODE_OBJECTIVES.safe;

async function refreshOffensiveDependentUi() {
  await refreshScanProfileUi();
  if (selectedScanProfile === "custom") {
    await reloadPilotToolCatalog();
    renderPilotToolGrid();
  }
}

export async function onPilotOffensiveModeChanged() {
  await refreshOffensiveDependentUi();
}

async function fetchScanProfiles() {
  const offensive = isOffensiveModeEnabled();
  try {
    const res = await apiFetch(`/api/scan-profiles?offensive=${offensive ? "1" : "0"}`);
    if (res.ok) {
      const data = await res.json();
      scanProfileMeta = data.profiles || [];
      return;
    }
  } catch {
    /* fallback abaixo */
  }
  scanProfileMeta = [
    { id: "basic", label: "Básico", description: "Recon essencial.", tool_count: 12 },
    { id: "intermediate", label: "Intermediário", description: "Mais ferramentas.", tool_count: 35 },
    {
      id: "full",
      label: "Completo",
      description: offensive ? "Todas permitidas no servidor." : "Catálogo da UI.",
      tool_count: offensive ? 150 : 78,
    },
    { id: "custom", label: "Personalizado", description: "Escolha manual.", tool_count: 0 },
  ];
}

async function reloadPilotToolCatalog() {
  const offensive = isOffensiveModeEnabled();
  try {
    const res = await apiFetch(`/api/tools?offensive=${offensive ? "1" : "0"}`);
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data.categories) && data.categories.length > 0) {
        toolCategories.length = 0;
        toolCategories.push(...data.categories);
        return;
      }
    }
  } catch {
    /* ignore */
  }
  await loadTools();
}

function renderScanProfileOptions() {
  const root = ctx.pilotScanOptions;
  if (!root) return;

  root.innerHTML = scanProfileMeta
    .map((p) => {
      const count =
        p.id === "custom"
          ? "você escolhe"
          : `${p.tool_count || "?"} ferramenta(s)`;
      return `
        <label class="pilot-scan-card">
          <input type="radio" name="pilot-scan" value="${escapeAttr(p.id)}" ${
        p.id === selectedScanProfile ? "checked" : ""
      } />
          <span class="pilot-scan-card-body">
            <strong>${escapeHtml(p.label)}</strong>
            <span>${escapeHtml(p.description || "")}</span>
            <em>${escapeHtml(count)}</em>
          </span>
        </label>`;
    })
    .join("");

  root.querySelectorAll('input[name="pilot-scan"]').forEach((input) => {
    input.addEventListener("change", () => {
      if (!input.checked) return;
      selectedScanProfile = input.value || "basic";
      syncCustomToolsPanel();
      const obj = document.getElementById("autopilot-objective");
      if (obj && !obj.dataset.touched) {
        obj.value = defaultObjectiveForSelection();
      }
    });
  });
  syncCustomToolsPanel();
}

async function refreshScanProfileUi() {
  await fetchScanProfiles();
  renderScanProfileOptions();
}

export function initAutopilot(context) {
  ctx = context;
  initScanProfileUi();
  ctx.autopilotStart?.addEventListener("click", () => startAutopilot());
  ctx.autopilotTarget?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      startAutopilot();
    }
  });
  const repeatCb = document.getElementById("autopilot-repeat");
  const daysWrap = document.getElementById("autopilot-repeat-days-wrap");
  repeatCb?.addEventListener("change", () => {
    if (daysWrap) daysWrap.hidden = !repeatCb.checked;
  });
  const obj = document.getElementById("autopilot-objective");
  obj?.addEventListener("input", () => {
    obj.dataset.touched = "1";
  });
  syncPilotModeUi();
  onOffensiveModeChange(() => {
    void refreshOffensiveDependentUi();
    syncPilotModeUi();
  });
  onOfflineModeChange(() => syncPilotModeUi());
}

async function initScanProfileUi() {
  if (!ctx.pilotScanOptions) return;
  ctx.pilotToolSearch?.addEventListener("input", () => {
    if (selectedScanProfile === "custom") renderPilotToolGrid();
  });
  await refreshScanProfileUi();
  await reloadPilotToolCatalog();
  syncCustomToolsPanel();
}

function syncCustomToolsPanel() {
  const panel = ctx.pilotCustomTools;
  const isCustom = selectedScanProfile === "custom";
  if (panel) panel.hidden = !isCustom;
  if (!isCustom) {
    if (ctx.pilotToolGrid) ctx.pilotToolGrid.innerHTML = "";
    if (ctx.pilotToolSearch) ctx.pilotToolSearch.value = "";
    return;
  }
  void reloadPilotToolCatalog().then(() => renderPilotToolGrid());
}

function renderPilotToolGrid() {
  if (selectedScanProfile !== "custom") return;
  const grid = ctx.pilotToolGrid;
  if (!grid) return;
  const q = (ctx.pilotToolSearch?.value || "").trim().toLowerCase();
  const items = [];
  for (const cat of toolCategories) {
    for (const t of cat.tools || []) {
      if (q && !t.id.includes(q) && !(t.summary || "").toLowerCase().includes(q)) continue;
      items.push(t);
    }
  }
  if (!items.length) {
    grid.innerHTML = `<p class="pilot-advanced-desc">Nenhuma ferramenta encontrada.</p>`;
    return;
  }
  grid.innerHTML = items
    .map(
      (t) => `
    <label class="pilot-tool-check">
      <input type="checkbox" data-tool="${escapeAttr(t.id)}" ${
        customToolSelection.has(t.id) ? "checked" : ""
      } />
      <span><strong>${escapeHtml(t.id)}</strong> — ${escapeHtml(t.summary || "")}</span>
    </label>`
    )
    .join("");

  grid.querySelectorAll("input[data-tool]").forEach((cb) => {
    cb.addEventListener("change", () => {
      const id = cb.getAttribute("data-tool") || "";
      if (cb.checked) customToolSelection.add(id);
      else customToolSelection.delete(id);
    });
  });
}

function getCustomToolsList() {
  return [...customToolSelection];
}

async function scheduleRepeat({ target, scanProfile, customTools, intervalDays, sessionId }) {
  const res = await apiFetch("/api/schedules", {
    method: "POST",
    body: JSON.stringify({
      target,
      client_id: getActiveClientId() || "default",
      job_type: "repeat",
      interval: "custom",
      interval_days: intervalDays,
      scan_profile: scanProfile,
      custom_tools: customTools || [],
      chat_session_id: sessionId || "",
      risk_profile: isOffensiveModeEnabled() ? "full" : "safe-active",
    }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || "falha ao agendar");
  const next = String(data.next_run_at || "").replace("T", " ").slice(0, 16);
  toast(
    `Repetição a cada ${intervalDays} dia(s)` + (next ? ` · próximo: ${next}` : ""),
    "success"
  );
}

function scanProfileLabel(id) {
  return scanProfileMeta.find((p) => p.id === id)?.label || id;
}

function isViewing(sessionId) {
  return getActiveSession()?.id === sessionId;
}

function setBusy(sessionId) {
  const viewing = isViewing(sessionId);
  if (ctx.input) ctx.input.disabled = viewing && isSessionBusy(sessionId);
  if (ctx.autopilotStart) ctx.autopilotStart.disabled = isSessionBusy(sessionId);
  if (ctx.btnAutopilot) ctx.btnAutopilot.disabled = isSessionBusy(sessionId);
  syncMissionButton();
  ctx.updateStatusBar?.();
}

export async function startAutopilot() {
  const target = ctx.autopilotTarget?.value.trim();
  const scanProfile = selectedScanProfile;
  const mode = currentEngagementMode();
  const objEl = document.getElementById("autopilot-objective");
  const objective = (objEl?.value || "").trim() || defaultObjectiveForSelection();
  const customTools = scanProfile === "custom" ? getCustomToolsList() : [];

  if (scanProfile === "custom" && !customTools.length) {
    showToastError("No perfil personalizado, marque ao menos uma ferramenta.");
    ctx.pilotCustomTools?.scrollIntoView({ behavior: "smooth", block: "nearest" });
    return;
  }

  if (!target) {
    showToastError("Informe o alvo.");
    ctx.autopilotTarget?.focus();
    return;
  }

  if (isSessionBusy(getActiveSession()?.id)) return;

  ensureSession();
  const session = getActiveSession();
  const sessionId = session.id;
  const repeatOn = Boolean(document.getElementById("autopilot-repeat")?.checked);
  let intervalDays = 30;
  if (repeatOn) {
    const raw = Number(document.getElementById("autopilot-repeat-days")?.value || 30);
    intervalDays = Math.max(1, Math.min(365, Number.isFinite(raw) ? Math.round(raw) : 30));
  }
  closeOverlay(ctx.overlayAutopilot);

  const modeTag =
    mode === "offensive" ? " · ofensivo" : mode === "offline" ? " · offline" : "";
  const userMsg = `[Auto-Pilot · ${scanProfileLabel(scanProfile)}${modeTag}]\nAlvo: ${target}\nObjetivo: ${objective}`;
  const missionId = createMissionId();
  const abortController = new AbortController();
  startRun(sessionId, { missionId, abort: abortController, kind: "pilot" });
  beginMission(missionId, abortController, sessionId);
  setBusy(sessionId);

  const isFirst = session.messages.length === 0;
  session.messages.push({ role: "user", content: userMsg });
  session.updatedAt = Date.now();
  if (isFirst || session.title === "novo chat") session.title = `pilot: ${target}`;
  saveStore();
  renderSessions();
  updateSessionTitle();
  renderChat();
  showAutopilotProgress("Piloto em execução — preflight e missão (pode levar vários minutos)");

  if (repeatOn) {
    scheduleRepeat({
      target,
      scanProfile,
      customTools,
      intervalDays,
      sessionId: session.id,
    }).catch((err) => {
      toast(err.message || "Não foi possível agendar a repetição", "warn");
    });
  }

  try {
    let finalData = null;
    const attachments = getAttachments() || [];
    if (attachments.length) {
      toast("Piloto com contexto da pasta/anexos", "info");
    }

    const res = await apiFetch("/api/autonomous/stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target,
        objective,
        mission_id: missionId,
        chat_session_id: session.id,
        scan_profile: scanProfile,
        custom_tools: customTools,
        engagement_mode: mode,
        offline: mode === "offline",
        risk_profile: mode === "offensive" ? "full" : "safe-active",
        attachments,
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
          sessionId,
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

    if (isViewing(sessionId)) hideTyping();
    closeAllLiveStreams();

    if (isMissionAborted(sessionId)) {
      throw new DOMException("Missão cancelada.", "AbortError");
    }

    if (!finalData) {
      throw new Error("Resposta incompleta do auto-pilot");
    }

    const data = finalData;
    const sess = getSessionById(sessionId) || session;
    sess.messages.push({
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
    sess.updatedAt = Date.now();
    saveStore();
    renderSessions();
    window.dispatchEvent(new CustomEvent("darkstar:session-updated"));

    if (isViewing(sessionId)) {
      appendAssistantLine(data.message);
      for (const exec of data.tool_executions || []) {
        finalizeLiveExecBlock(ctx.chatEl, exec);
      }
      scrollChatToBottom();
    }

    if ((data.tool_executions || []).length > 0) {
      const cancelled = data.stopped_reason === "cancelled";
      if (isViewing(sessionId)) {
        appendLine(
          "info",
          `${cancelled ? "Missão interrompida" : "Missão concluída"} · ${data.tools_executed} cmd(s) · ${data.rounds} rodada(s) · ${
            data.objective_met ? "objetivo atingido" : data.stopped_reason
          } · gerando PDF…`
        );
      }
      try {
        await downloadSessionPdf(sess, { silent: true });
        if (isViewing(sessionId)) {
          appendLine(
            "info",
            cancelled
              ? "Relatório parcial PDF gerado e salvo em Relatórios (Alt+F)."
              : "Relatório PDF gerado e salvo em Relatórios (Alt+F)."
          );
        }
        toast(
          cancelled ? "Relatório parcial pronto" : "Missão concluída · PDF do relatório pronto",
          cancelled ? "warn" : "success"
        );
        if (isViewing(sessionId) && !cancelled) openSessionReportModal();
      } catch (pdfErr) {
        if (isViewing(sessionId)) appendLine("warn", `PDF automático: ${pdfErr.message}`);
        toast(`PDF falhou: ${pdfErr.message}`, "warn");
      }
    } else if (data.stopped_reason === "cancelled") {
      toast("Missão cancelada", "warn");
    }
  } catch (e) {
    if (isViewing(sessionId)) hideTyping();
    closeAllLiveStreams();
    const sess = getSessionById(sessionId) || session;
    if (e.name === "AbortError") {
      const errMsg = "Missão cancelada pelo usuário.";
      sess.messages.push({ role: "assistant", content: errMsg });
      saveStore();
      if (isViewing(sessionId)) appendLine("info", errMsg);
      toast("Missão cancelada", "warn");
    } else {
      const errMsg = `Erro de conexão no piloto: ${e.message}`;
      sess.messages.push({ role: "assistant", content: errMsg });
      saveStore();
      if (isViewing(sessionId)) {
        appendLine("error", errMsg);
        showToastError(errMsg);
      }
    }
  } finally {
    endMission(sessionId);
    setBusy(sessionId);
    rebuildInputHistory(ctx.inputHistory);
    if (isViewing(sessionId)) ctx.input?.focus();
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
