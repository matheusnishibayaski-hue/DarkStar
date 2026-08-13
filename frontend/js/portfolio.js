/**
 * Carteira de engajamentos — alvos da conversa ativa (aba Relatórios).
 */

import { apiFetch } from "./api.js";
import { toast } from "./ui.js";
import { getActiveSession } from "./sessions.js";

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function riskBand(risk) {
  const band = String(risk?.band || risk?.label || "").toLowerCase();
  if (band.includes("critic") || band.includes("crít")) return "critical";
  if (band.includes("high") || band.includes("alto")) return "high";
  if (band.includes("medium") || band.includes("médi")) return "medium";
  if (band.includes("low") || band.includes("baixo")) return "low";
  return "info";
}

function deltaText(d) {
  if (!d || !d.has_baseline) return "Primeiro scan — ainda sem comparação.";
  const parts = [];
  if (d.new) parts.push(`${d.new} novo${d.new === 1 ? "" : "s"}`);
  if (d.fixed) parts.push(`${d.fixed} corrigido${d.fixed === 1 ? "" : "s"}`);
  parts.push(`${d.still_open || 0} ainda aberto${(d.still_open || 0) === 1 ? "" : "s"}`);
  return parts.join(" · ");
}

function nextScanText(next) {
  if (!next) return "sem agenda";
  const at = String(next.next_run_at || "").replace("T", " ").slice(0, 16);
  return at || "agendado";
}

export async function refreshPortfolio() {
  const body = document.getElementById("portfolio-body");
  const meta = document.getElementById("portfolio-meta");
  if (!body) return;
  const session = getActiveSession();
  if (!session) {
    body.innerHTML = "<p class='panel-callout'>Nenhuma conversa ativa.</p>";
    if (meta) meta.textContent = "";
    return;
  }
  body.innerHTML = "<p class='panel-callout'>carregando carteira…</p>";
  try {
    const res = await apiFetch(
      `/api/portfolio?session_id=${encodeURIComponent(session.id)}`
    );
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "falha");
    const rows = data.engagements || [];
    if (meta) {
      meta.textContent = rows.length
        ? `${rows.length} alvo(s) · ${data.schedules_count || 0} agenda(s)`
        : "";
    }
    if (!rows.length) {
      body.innerHTML =
        "<p class='panel-callout'>Nenhum alvo nesta conversa ainda. Quando a Argus escanear um host, o risco e o delta aparecem aqui — o mesmo escopo do PDF.</p>";
      return;
    }
    body.innerHTML = `<div class="portfolio-cards">${rows.map(cardHtml).join("")}</div>`;
  } catch (err) {
    body.innerHTML = `<p class="panel-callout">${escapeHtml(err.message || "erro")}</p>`;
    toast(err.message || "Falha ao carregar carteira", "error");
  }
}

function cardHtml(r) {
  const risk = r.risk || {};
  const band = riskBand(risk);
  const score = risk.score ?? "—";
  const label = risk.label || band;
  return `
    <article class="portfolio-card portfolio-card--${escapeHtml(band)}">
      <header class="portfolio-card-head">
        <h3 class="portfolio-card-target">${escapeHtml(r.target || "—")}</h3>
        <span class="portfolio-risk">${escapeHtml(String(score))} · ${escapeHtml(label)}</span>
      </header>
      <p class="portfolio-card-counts">
        ${r.findings_confirmed || 0} confirmado(s)
        · ${r.findings_pending || 0} pendente(s)
        · ${r.findings_fp || 0} falso(s) positivo(s)
      </p>
      <p class="portfolio-card-delta">${escapeHtml(deltaText(r.delta))}</p>
      <p class="portfolio-card-foot">
        <span>${escapeHtml(r.lifecycle_label || r.lifecycle || "ativo")}</span>
        <span>próx. scan: ${escapeHtml(nextScanText(r.next_schedule))}</span>
      </p>
    </article>`;
}

/** @deprecated use openWorkspace('report') */
export function openPortfolioPanel() {
  return refreshPortfolio();
}

export function initPortfolio() {
  /* vive na aba Relatórios */
}
