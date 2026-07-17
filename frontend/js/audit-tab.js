/** Aba de auditoria no painel Intel. */

import { listAudit } from "./api/routes.js";
import { apiFetch } from "./api.js";
import { deleteAuditAll, deleteLog } from "./data-admin.js";
import { attachDeleteAction, bindLogDeleteButtons } from "./row-actions.js";
import { escapeHtml } from "./exec.js";

let ctx = {};
let unbindDeletes = null;

export function initAuditTab(context) {
  ctx = context;
  ctx.auditRefresh?.addEventListener("click", () => loadAuditTab(true));
  if (ctx.auditPurge) {
    attachDeleteAction(ctx.auditPurge, {
      label: "toda a auditoria",
      toast: ctx.toast,
      onDelete: async () => {
        await deleteAuditAll();
        auditTableElClearLoaded();
        await loadAuditTab(true);
        ctx.onAuditDeleted?.();
      },
    });
  }
}

function auditTableElClearLoaded() {
  ctx.auditTableEl?.removeAttribute("data-loaded");
}

function formatTs(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" });
  } catch {
    return iso;
  }
}

export async function loadAuditTab(force = false) {
  const { auditTableEl, auditMetaEl } = ctx;
  if (!auditTableEl) return;

  if (!force && auditTableEl.dataset.loaded === "1") return;

  auditTableEl.innerHTML = '<p class="record-empty">carregando auditoria…</p>';

  try {
    const res = await listAudit({ limit: 100 });
    if (!res.ok) throw new Error("Falha ao listar auditoria");
    const events = (await res.json()).events || [];
    const logsRes = await apiFetch("/api/data/logs?limit=500");
    const logIdsWithFile = new Set();
    if (logsRes.ok) {
      for (const l of (await logsRes.json()).logs || []) {
        if (l.has_file !== false) logIdsWithFile.add(l.id);
      }
    }
    if (auditMetaEl) auditMetaEl.textContent = `${events.length} evento(s)`;
    renderAudit(events, logIdsWithFile);
    auditTableEl.dataset.loaded = "1";
  } catch (e) {
    auditTableEl.innerHTML = `<p class="record-empty">${escapeHtml(e.message)}</p>`;
  }
}

function renderAudit(events, logIdsWithFile = new Set()) {
  const { auditTableEl } = ctx;
  if (!auditTableEl) return;

  if (!events.length) {
    auditTableEl.innerHTML = `
      <p class="record-empty">Nenhum evento registrado ainda.</p>
      <p class="record-hint">Execuções de ferramentas são gravadas em backend/audit/.</p>
    `;
    return;
  }

  auditTableEl.innerHTML = `
    <div class="record-list record-list--audit" role="list">
      ${events
        .map((ev) => {
          const st = ev.blocked ? "blocked" : ev.success ? "ok" : "fail";
          const logId = ev.log_file_id || "";
          const cmd = ev.command || "";
          const hasFile = logId && logIdsWithFile.has(logId);
          return `
        <article class="record-row record-row--audit" ${logId ? `data-row-id="${escapeHtml(logId)}"` : ""} role="row">
          <div class="record-row-main">
            <span class="record-badge record-badge--${st}">${st}</span>
            <span class="record-tool">${escapeHtml(ev.tool || "—")}</span>
            <span class="record-sub" title="${escapeHtml(cmd)}">${escapeHtml(cmd.slice(0, 56))}${cmd.length > 56 ? "…" : ""}</span>
            <span class="record-meta"><span>${formatTs(ev.ts)}</span>${logId && !hasFile ? `<span class="record-tag">só auditoria</span>` : ""}</span>
          </div>
          <div class="record-row-actions">
            ${
              logId
                ? `${hasFile ? `<a class="row-action row-action--ghost" href="/api/logs/${encodeURIComponent(logId)}" target="_blank" rel="noopener">abrir</a>` : ""}
                   <button type="button" class="row-action row-action--danger" data-delete-log="${escapeHtml(logId)}">excluir</button>`
                : `<span class="record-muted">—</span>`
            }
          </div>
        </article>`;
        })
        .join("")}
    </div>`;

  unbindDeletes?.();
  unbindDeletes = bindLogDeleteButtons(auditTableEl, {
    deleteFn: deleteLog,
    toast: ctx.toast,
    onDeleted: () => {
      auditTableElClearLoaded();
      loadAuditTab(true);
      ctx.onAuditDeleted?.();
    },
  });
}
