/** Biblioteca de PDFs — filtrada pela conversa ativa (workspace). */

import {
  listDownloadedReports,
  deleteDownloadedReport,
  downloadReportRecord,
  openReportRecord,
  onReportsChanged,
} from "./reports-store.js";
import { attachDeleteAction, formatBytes, formatDate } from "./row-actions.js";
import { escapeHtml } from "./exec.js";
import { getActiveSession } from "./sessions.js";

let ctx = {};
let reportsCache = [];
let filter = "";
let unsubReports = null;

export function initFilesPanel(context) {
  ctx = context;
  ctx.filesRefreshBtn?.addEventListener("click", () => loadReports(true));
  ctx.filesSearch?.addEventListener("input", () => {
    filter = (ctx.filesSearch.value || "").trim().toLowerCase();
    render();
  });
  unsubReports?.();
  unsubReports = onReportsChanged(() => {
    if (!document.getElementById("ws-panel-pdfs")?.hidden) loadReports(true);
  });
}

function render() {
  const { filesListEl, filesMetaEl } = ctx;
  if (!filesListEl) return;
  const session = getActiveSession();
  const sid = session?.id || "";

  let list = reportsCache.filter((r) => !sid || r.sessionId === sid);
  if (filter) {
    list = list.filter((r) => {
      const hay = `${r.title} ${r.fileName} ${r.sessionId}`.toLowerCase();
      return hay.includes(filter);
    });
  }

  if (filesMetaEl) {
    filesMetaEl.textContent = list.length
      ? `${list.length} PDF(s) desta conversa`
      : "nenhum PDF nesta conversa";
  }

  if (!list.length) {
    filesListEl.innerHTML = `
      <div class="files-simple-empty">
        <p>${filter ? "Nada corresponde à busca." : "Nenhum relatório nesta conversa ainda."}</p>
        <p class="files-simple-hint">
          Gere PDFs na aba <strong>relatório</strong> (classifique achados e use <strong>Baixar PDF</strong>).
        </p>
      </div>`;
    return;
  }

  filesListEl.innerHTML = `
    <div class="files-record-list" role="list">
      ${list
        .map(
          (r) => `
        <div class="files-simple-row files-report-row" data-report-id="${escapeHtml(r.id)}">
          <div class="files-simple-info">
            <span class="files-simple-name">${escapeHtml(r.title || r.fileName || "Relatório")}</span>
            <span class="files-simple-meta">
              ${escapeHtml(formatBytes(r.size))} · ${escapeHtml(formatDate(new Date(r.createdAt).toISOString()))}
              ${r.fileName ? ` · ${escapeHtml(r.fileName)}` : ""}
            </span>
          </div>
          <div class="files-simple-actions">
            <button type="button" class="files-simple-btn files-open-btn">Abrir</button>
            <button type="button" class="files-simple-btn files-dl-btn">Baixar</button>
            <button type="button" class="files-simple-btn files-simple-btn--danger files-del-btn">Excluir</button>
          </div>
        </div>`
        )
        .join("")}
    </div>`;

  filesListEl.querySelectorAll(".files-report-row").forEach((row) => {
    const id = row.dataset.reportId;
    const record = reportsCache.find((x) => x.id === id);
    if (!record) return;
    row.querySelector(".files-open-btn")?.addEventListener("click", () => {
      openReportRecord(record).catch((e) => ctx.toast?.(e.message || "erro ao abrir PDF"));
    });
    row.querySelector(".files-dl-btn")?.addEventListener("click", () => {
      downloadReportRecord(record).catch((e) => ctx.toast?.(e.message || "erro ao baixar PDF"));
    });
    const delBtn = row.querySelector(".files-del-btn");
    if (delBtn) {
      attachDeleteAction(delBtn, {
        label: record.title || record.fileName,
        toast: ctx.toast,
        onDelete: async () => {
          await deleteDownloadedReport(id);
          await loadReports(true);
        },
      });
    }
  });
}

async function loadReports(force = false) {
  const { filesListEl } = ctx;
  if (!force && reportsCache.length) {
    render();
    return;
  }
  if (filesListEl) filesListEl.innerHTML = `<p class="files-simple-empty">carregando…</p>`;
  try {
    reportsCache = await listDownloadedReports();
    render();
  } catch (e) {
    if (filesListEl) {
      filesListEl.innerHTML = `<p class="files-simple-empty">${escapeHtml(e.message)}</p>`;
    }
  }
}

export async function openFilesPanel(nameFilter = "") {
  filter = (nameFilter || "").trim().toLowerCase();
  if (ctx.filesSearch) ctx.filesSearch.value = filter;
  await loadReports(true);
}

/** Compat: chamado por código legado */
export async function loadFilesInto() {
  await loadReports(true);
}
