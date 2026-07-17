/** Aba Logs — listagem e exclusão individual. */

import { apiFetch } from "./api.js";
import { escapeHtml } from "./exec.js";
import { bindLogDeleteButtons, formatBytes, renderLogRow } from "./row-actions.js";
import { deleteLog } from "./data-admin.js";

let ctx = {};
let logsCache = null;
let searchQuery = "";
let unbindDeletes = null;

export function initLogsPanel(context) {
  ctx = context;
  ctx.logsRefresh?.addEventListener("click", () => loadLogsTab(true));
  ctx.logsSearch?.addEventListener("input", () => {
    searchQuery = (ctx.logsSearch?.value || "").trim().toLowerCase();
    if (logsCache) renderLogs(logsCache);
  });
}

async function fetchLogs() {
  const res = await apiFetch("/api/data/logs?limit=200");
  if (!res.ok) throw new Error("Falha ao listar logs");
  return (await res.json()).logs || [];
}

function filterLogs(logs) {
  if (!searchQuery) return logs;
  return logs.filter((l) => {
    const id = (l.id || "").toLowerCase();
    const cmd = (l.command || l.tool || "").toLowerCase();
    return id.includes(searchQuery) || cmd.includes(searchQuery);
  });
}

function renderLogs(logs) {
  const { logsListEl, logsMetaEl } = ctx;
  if (!logsListEl) return;

  const visible = filterLogs(logs);
  if (logsMetaEl) {
    logsMetaEl.textContent = `${visible.length} log(s) · backend/logs`;
  }

  if (!visible.length) {
    logsListEl.innerHTML = searchQuery
      ? '<p class="record-empty">Nenhum log corresponde à busca.</p>'
      : `<p class="record-empty">Nenhum log salvo ainda.</p>
         <p class="record-hint">Logs aparecem aqui quando ferramentas são executadas no chat ou no piloto automático.</p>`;
    return;
  }

  logsListEl.innerHTML = `
    <div class="record-list" role="list">
      ${visible.map((log) => renderLogRow(log, { showCommand: true })).join("")}
    </div>`;

  unbindDeletes?.();
  unbindDeletes = bindLogDeleteButtons(logsListEl, {
    deleteFn: deleteLog,
    toast: ctx.toast,
    onDeleted: () => loadLogsTab(true),
  });
}

export async function loadLogsTab(force = false) {
  const { logsListEl } = ctx;
  if (!logsListEl) return;

  if (!force && logsCache) {
    renderLogs(logsCache);
    return;
  }

  logsListEl.innerHTML = '<p class="record-empty">carregando logs…</p>';

  try {
    logsCache = await fetchLogs();
    renderLogs(logsCache);
  } catch (e) {
    logsListEl.innerHTML = `<p class="record-empty">${escapeHtml(e.message)}</p>`;
  }
}

export function getLogsCount() {
  return logsCache?.length ?? 0;
}
