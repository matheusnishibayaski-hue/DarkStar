/** Mapa da conversa — alvos/findings da sessão (cybermap só como link externo). */

import { apiFetch } from "./api.js";
import { escapeHtml } from "./exec.js";
import { getActiveSession } from "./sessions.js";

const FULL_MAP_URL = "https://cybermap.kaspersky.com/pt";

let ctx = {};

export function initThreatIntel(context) {
  ctx = context || {};
}

/** @deprecated use openWorkspace('mapa') */
export function activateThreatsTab() {
  openThreatsPanel();
}

export function openThreatsPanel() {
  refreshSessionMap();
}

export function closeThreatsPanel() {
  /* no-op: painel vive no workspace */
}

export async function refreshSessionMap() {
  const body = document.getElementById("workspace-map-body");
  const meta = document.getElementById("workspace-map-meta");
  const session = getActiveSession();
  if (!body) return;
  if (!session) {
    if (meta) meta.textContent = "Nenhuma conversa ativa";
    body.innerHTML = `<p class="panel-callout">Selecione ou crie um chat.</p>`;
    return;
  }
  if (meta) meta.textContent = `Alvos e achados · ${session.id.slice(0, 8)}…`;
  body.innerHTML = `<p class="panel-callout">carregando…</p>`;
  try {
    const res = await apiFetch(`/api/intel/sessions/${encodeURIComponent(session.id)}`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "falha ao carregar intel");
    const targets = data.targets || data.session?.targets || [];
    const findings = data.findings || data.session_findings || data.session?.session_findings || [];
    if (!targets.length && !findings.length) {
      body.innerHTML = `
        <p class="panel-callout">Nenhum alvo nesta conversa ainda.</p>
        <p class="files-simple-hint">Rode scans no chat ou no Piloto — o mapa lista só o que esta sessão tocou.</p>
        <p><a class="threatmap-link" href="${FULL_MAP_URL}" target="_blank" rel="noopener noreferrer">Abrir cybermap Kaspersky (externo)</a></p>`;
      return;
    }
    const targetHtml = targets.length
      ? `<ul class="workspace-map-targets">${targets
          .map((t) => `<li><code>${escapeHtml(String(t))}</code></li>`)
          .join("")}</ul>`
      : "<p class='panel-callout'>Sem alvos indexados.</p>";
    const findingHtml = findings.length
      ? `<table class="portfolio-table"><thead><tr><th>Achado</th><th>Sev</th><th>Status</th><th>Alvo</th></tr></thead><tbody>${findings
          .slice(0, 80)
          .map(
            (f) => `<tr>
              <td>${escapeHtml(f.title || f.id || "—")}</td>
              <td>${escapeHtml(f.severity || "—")}</td>
              <td>${escapeHtml(f.status || "—")}</td>
              <td>${escapeHtml(f.host || f.target || "—")}</td>
            </tr>`
          )
          .join("")}</tbody></table>`
      : "<p class='panel-callout'>Sem findings nesta conversa.</p>";
    body.innerHTML = `
      <h3 class="dashboard-section-title">Alvos (${targets.length})</h3>
      ${targetHtml}
      <h3 class="dashboard-section-title">Findings (${findings.length})</h3>
      ${findingHtml}`;
  } catch (err) {
    body.innerHTML = `<p class="panel-callout">${escapeHtml(err.message || "erro")}</p>`;
  }
}
