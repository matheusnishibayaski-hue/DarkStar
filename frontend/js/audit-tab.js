/** Aba de auditoria no painel Intel. */

import { listAudit } from "./api/routes.js";
import { escapeHtml } from "./exec.js";

let ctx = {};

export function initAuditTab(context) {
  ctx = context;
  ctx.auditRefresh?.addEventListener("click", () => loadAuditTab(true));
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

  auditTableEl.innerHTML = '<p class="audit-empty">carregando auditoria…</p>';

  try {
    const res = await listAudit({ limit: 100 });
    if (!res.ok) throw new Error("Falha ao listar auditoria");
    const events = (await res.json()).events || [];
    if (auditMetaEl) auditMetaEl.textContent = `${events.length} evento(s) · JSONL`;
    renderAudit(events);
    auditTableEl.dataset.loaded = "1";
  } catch (e) {
    auditTableEl.innerHTML = `<p class="audit-empty">${escapeHtml(e.message)}</p>`;
  }
}

function renderAudit(events) {
  const { auditTableEl } = ctx;
  if (!auditTableEl) return;

  if (!events.length) {
    auditTableEl.innerHTML = `
      <p class="audit-empty">Nenhum evento registrado ainda.</p>
      <p class="audit-hint">Execuções de ferramentas são gravadas automaticamente em backend/audit/.</p>
    `;
    return;
  }

  auditTableEl.innerHTML = "";
  const table = document.createElement("div");
  table.className = "audit-table";
  table.setAttribute("role", "table");

  const head = document.createElement("div");
  head.className = "audit-row audit-row-head";
  head.innerHTML = `
    <span class="audit-col audit-col-ts">hora</span>
    <span class="audit-col audit-col-tool">tool</span>
    <span class="audit-col audit-col-cmd">comando</span>
    <span class="audit-col audit-col-st">status</span>
    <span class="audit-col audit-col-log">log</span>
  `;
  table.appendChild(head);

  for (const ev of events) {
    const row = document.createElement("div");
    row.className = "audit-row";
    const st = ev.blocked ? "blocked" : (ev.success ? "ok" : "fail");
    const logId = ev.log_file_id || "";
    row.innerHTML = `
      <span class="audit-col audit-col-ts">${formatTs(ev.ts)}</span>
      <span class="audit-col audit-col-tool">${escapeHtml(ev.tool || "—")}</span>
      <span class="audit-col audit-col-cmd" title="${escapeHtml(ev.command || "")}">${escapeHtml((ev.command || "").slice(0, 48))}${(ev.command || "").length > 48 ? "…" : ""}</span>
      <span class="audit-col audit-col-st audit-st--${st}">${st}</span>
      <span class="audit-col audit-col-log">${logId ? `<a href="/api/logs/${encodeURIComponent(logId)}" target="_blank" rel="noopener">${escapeHtml(logId.slice(0, 8))}</a>` : "—"}</span>
    `;
    table.appendChild(row);
  }

  auditTableEl.appendChild(table);
}
