/**
 * Painel carteira de engajamentos (uso interno — sem portal do cliente).
 */

import { apiFetch } from "./api.js";
import { openOverlay, closeOverlay, toast } from "./ui.js";

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function loadPortfolio() {
  const body = document.getElementById("portfolio-body");
  if (!body) return;
  body.innerHTML = "<p class='panel-callout'>carregando…</p>";
  try {
    const res = await apiFetch("/api/portfolio");
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "falha");
    const rows = data.engagements || [];
    if (!rows.length) {
      body.innerHTML = "<p class='panel-callout'>Nenhum engajamento ainda.</p>";
      return;
    }
    const table = document.createElement("table");
    table.className = "portfolio-table";
    table.innerHTML = `
      <thead><tr>
        <th>Alvo</th><th>Cliente</th><th>Risco</th><th>Delta</th><th>Lifecycle</th><th>Próx. scan</th>
      </tr></thead><tbody></tbody>`;
    const tb = table.querySelector("tbody");
    for (const r of rows) {
      const tr = document.createElement("tr");
      const risk = r.risk || {};
      const d = r.delta || {};
      const next = r.next_schedule;
      tr.innerHTML = `
        <td>${escapeHtml(r.target || "")}</td>
        <td>${escapeHtml(r.client_id || r.client || "—")}</td>
        <td>${escapeHtml(String(risk.score ?? "—"))} <span class="muted">${escapeHtml(risk.label || "")}</span></td>
        <td>+${d.new || 0} / −${d.fixed || 0} / open ${d.still_open || 0}</td>
        <td>${escapeHtml(r.lifecycle || "active")}</td>
        <td>${escapeHtml(next ? String(next.next_run_at || "").slice(0, 16) : "—")}</td>`;
      tb.appendChild(tr);
    }
    body.innerHTML = "";
    body.appendChild(table);
    const meta = document.createElement("p");
    meta.className = "panel-callout";
    meta.textContent = `${rows.length} engajamento(s) · ${data.schedules_count || 0} agenda(s) · cliente ativo: ${data.active_client_id || "default"}`;
    body.appendChild(meta);
  } catch (err) {
    body.innerHTML = `<p class="panel-callout">${escapeHtml(err.message || "erro")}</p>`;
    toast(err.message || "Falha ao carregar carteira", "err");
  }
}

export function openPortfolioPanel() {
  const overlay = document.getElementById("overlay-portfolio");
  openOverlay(overlay);
  loadPortfolio();
}

export function initPortfolio() {
  const btn = document.getElementById("btn-portfolio");
  const closeBtn = document.getElementById("portfolio-close");
  if (btn) btn.addEventListener("click", () => openPortfolioPanel());
  if (closeBtn) {
    closeBtn.addEventListener("click", () => {
      closeOverlay(document.getElementById("overlay-portfolio"));
    });
  }
}
