/** Aba Dados — limpeza por categoria (sem lista de logs; ver aba Logs). */

import { apiFetch } from "./api.js";
import { escapeHtml } from "./exec.js";
import { attachDeleteAction, formatBytes } from "./row-actions.js";

let ctx = {};
let summaryCache = null;

export function initDataTab(context) {
  ctx = context;
  ctx.dataRefresh?.addEventListener("click", () => loadDataTab(true));
}

async function fetchSummary() {
  const res = await apiFetch("/api/data/summary");
  if (!res.ok) throw new Error("Falha ao carregar resumo");
  return res.json();
}

async function purgeCategory(category, target = null) {
  const res = await apiFetch("/api/data/purge", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ categories: [category], target, confirm: true }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "Falha ao excluir");
  }
  return res.json();
}

function renderSummary(data) {
  const { dataBodyEl, dataMetaEl } = ctx;
  if (!dataBodyEl) return;

  const cats = data.categories || {};
  const keys = Object.keys(cats).filter((k) => k !== "logs");

  if (dataMetaEl) {
    const total = keys.reduce((n, k) => n + (cats[k]?.count || 0), 0);
    dataMetaEl.textContent = `${total} registro(s) · categorias`;
  }

  dataBodyEl.innerHTML = `
    <p class="data-intro">
      Limpeza por tipo de dado. Para <strong>logs de execução</strong>, use a aba
      <em>logs</em> e exclua um por um.
    </p>
    <div class="data-cards">
      ${keys
        .map((key) => {
          const c = cats[key];
          const count = c.count || 0;
          return `
        <div class="data-card" data-category="${escapeHtml(key)}" data-delete-scope>
          <div class="data-card-head">
            <strong>${escapeHtml(c.label || key)}</strong>
            <span class="data-card-stat">${count} · ${formatBytes(c.bytes)}</span>
          </div>
          <p class="data-card-path">${escapeHtml(c.path || "")}</p>
          <button type="button" class="row-action row-action--danger data-card-purge"
            data-purge-cat="${escapeHtml(key)}" ${count ? "" : "disabled"}>
            limpar categoria
          </button>
        </div>`;
        })
        .join("")}
    </div>
    <div class="data-target-row">
      <label class="data-target-label" for="data-target-filter">Filtrar por alvo (opcional)</label>
      <input type="text" class="panel-field data-target-input" id="data-target-filter"
        placeholder="ex: scanme.nmap.org" spellcheck="false" />
      <span class="data-target-hint">Válido para recon, surface, evidence e artefatos.</span>
    </div>
  `;

  dataBodyEl.querySelectorAll("[data-purge-cat]").forEach((btn) => {
    const cat = btn.getAttribute("data-purge-cat");
    attachDeleteAction(btn, {
      label: cats[cat]?.label || cat,
      toast: ctx.toast,
      removeOnSuccess: false,
      onDelete: async () => {
        const target = getTargetFilter();
        const result = await purgeCategory(cat, target);
        summaryCache = result.summary;
        renderSummary(summaryCache);
        ctx.onDataChanged?.();
      },
    });
  });
}

function getTargetFilter() {
  const el = document.getElementById("data-target-filter");
  return (el?.value || "").trim() || null;
}

export async function loadDataTab(force = false) {
  const { dataBodyEl } = ctx;
  if (!dataBodyEl) return;
  if (!force && summaryCache) {
    renderSummary(summaryCache);
    return;
  }
  dataBodyEl.innerHTML = '<p class="record-empty">carregando…</p>';
  try {
    summaryCache = await fetchSummary();
    renderSummary(summaryCache);
  } catch (e) {
    dataBodyEl.innerHTML = `<p class="record-empty">${escapeHtml(e.message)}</p>`;
  }
}

export async function deleteFile(path) {
  const encoded = path.split("/").map(encodeURIComponent).join("/");
  const res = await apiFetch(`/api/data/files/${encoded}`, { method: "DELETE" });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "Falha ao excluir arquivo");
  }
  return res.json();
}

export async function deleteReconTarget(target) {
  const res = await apiFetch(`/api/data/recon/${encodeURIComponent(target)}`, { method: "DELETE" });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "Falha ao excluir recon");
  }
  return res.json();
}

export async function deleteEngagement(target) {
  const res = await apiFetch(`/api/engagements/${encodeURIComponent(target)}`, { method: "DELETE" });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "Falha ao excluir engajamento");
  }
  return res.json();
}

export async function deleteAuditAll() {
  const res = await apiFetch("/api/audit?all=true", { method: "DELETE" });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "Falha ao excluir auditoria");
  }
  return res.json();
}

export async function deleteLog(logId) {
  const res = await apiFetch(`/api/data/logs/${encodeURIComponent(logId)}`, { method: "DELETE" });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "Falha ao excluir log");
  }
  return res.json();
}

export async function deleteSessionLogs(sessionId, logIds = []) {
  const res = await apiFetch("/api/data/logs/session", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ session_id: sessionId, log_ids: logIds }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "Falha ao excluir logs da conversa");
  }
  return res.json();
}

export async function deleteIntelSession(sessionId) {
  const res = await apiFetch(`/api/intel/sessions/${encodeURIComponent(sessionId)}`, {
    method: "DELETE",
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "Falha ao excluir intel da conversa");
  }
  return res.json();
}
