/** Piloto automático — missão com IA por perfil de scan. */

import { apiFetch } from "./api.js";
import { isOffensiveModeEnabled } from "./offensive-mode.js";
import {
  getActiveSession,
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
} from "./mission.js";
import {
  renderChat,
  appendAssistantLine,
  appendLine,
  showAutopilotProgress,
  hideTyping,
  scrollChatToBottom,
} from "./chat-view.js";
import { toast, showToastError, setLoading, getLoading, closeOverlay } from "./ui.js";

let ctx = {};
/** @type {"basic"|"intermediate"|"full"|"custom"} */
let selectedScanProfile = "basic";
/** @type {Set<string>} */
const customToolSelection = new Set();
/** @type {Array<{id:string,label:string,description:string,tool_count:number}>} */
let scanProfileMeta = [];

const DEFAULT_OBJECTIVES = {
  basic:
    "Scan básico: executar as ferramentas essenciais do perfil (portas, DNS, HTTP, nuclei, nikto) e resumir achados.",
  intermediate:
    "Scan intermediário: recon ampliado, enumeração web e checks adicionais do perfil; priorizar achados confirmáveis.",
  full:
    "Scan completo: percorrer o catálogo de ferramentas do perfil no alvo autorizado e documentar tudo relevante.",
  custom: "Scan personalizado: executar cada ferramenta selecionada e consolidar achados com evidências.",
};

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

function scanProfileLabel(id) {
  return scanProfileMeta.find((p) => p.id === id)?.label || id;
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
  const scanProfile = selectedScanProfile;
  const objective = DEFAULT_OBJECTIVES[scanProfile] || DEFAULT_OBJECTIVES.basic;
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

  if (getLoading()) return;

  ensureSession();
  const session = getActiveSession();
  closeOverlay(ctx.overlayAutopilot);

  const offensive = isOffensiveModeEnabled();
  const userMsg = `[Auto-Pilot · ${scanProfileLabel(scanProfile)}${
    offensive ? " · modo ofensivo" : ""
  }]\nAlvo: ${target}\nObjetivo: ${objective}`;
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
        scan_profile: scanProfile,
        custom_tools: customTools,
        risk_profile: isOffensiveModeEnabled() ? "full" : "safe-active",
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

    if (data.stopped_reason !== "cancelled" && (data.tool_executions || []).length > 0) {
      appendLine(
        "info",
        `Missão concluída · ${data.tools_executed} cmd(s) · ${data.rounds} rodada(s) · ${
          data.objective_met ? "objetivo atingido" : data.stopped_reason
        } · gerando PDF…`
      );
      try {
        await downloadSessionPdf(session, { silent: true });
        appendLine("info", "Relatório PDF gerado e salvo em Relatórios (Alt+F).");
        toast(`Missão concluída · PDF do relatório pronto`, "success");
        openSessionReportModal();
      } catch (pdfErr) {
        appendLine("warn", `PDF automático: ${pdfErr.message}`);
        toast(`Missão ok, mas PDF falhou: ${pdfErr.message}`, "warn");
      }
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
