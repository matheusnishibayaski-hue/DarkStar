/**
 * Aba Triagem do workspace — achados da conversa ativa (sem Kanban).
 */

import { getActiveSession } from "./sessions.js";
import { getIntelSession, patchSessionFinding } from "./api/routes.js";
import { escapeHtml } from "./exec.js";
import { toast } from "./ui.js";

const STATUSES = [
  ["candidate", "candidato"],
  ["confirmed", "confirmado"],
  ["inconclusive", "inconclusivo"],
  ["false_positive", "falso positivo"],
];

export async function refreshWorkspaceTriage() {
  const body = document.getElementById("workspace-triage-body");
  const meta = document.getElementById("workspace-triage-meta");
  if (!body) return;
  const session = getActiveSession();
  if (!session?.id) {
    if (meta) meta.textContent = "nenhuma conversa ativa";
    body.innerHTML = `<p class="recon-empty">Abra uma conversa para triar achados.</p>`;
    return;
  }
  if (meta) meta.textContent = "carregando…";
  body.innerHTML = `<p class="recon-empty">carregando achados…</p>`;
  try {
    const res = await getIntelSession(session.id);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || "Falha ao carregar intel");
    const findings = Array.isArray(data.findings) ? data.findings : [];
    if (meta) meta.textContent = `${findings.length} achado(s) nesta conversa`;
    if (!findings.length) {
      body.innerHTML = `<p class="recon-empty">Nenhum achado nesta conversa ainda.</p>`;
      return;
    }
    body.innerHTML = findings
      .map((f) => renderFinding(session.id, f))
      .join("");
  } catch (err) {
    if (meta) meta.textContent = "erro";
    body.innerHTML = `<p class="recon-empty">${escapeHtml(err.message || "falha")}</p>`;
  }
}

function renderFinding(sessionId, f) {
  const id = String(f.id || "");
  const status = String(f.status || "candidate");
  const title = f.plain_title || f.title || "Achado";
  const host = f.surface_target || f.host || "—";
  const refs = [f.cwe, f.owasp].filter(Boolean).join(" · ");
  const buttons = STATUSES.map(([value, label]) => {
    const active = status === value ? " active" : "";
    return `<button type="button" class="ws-triage-status${active}" data-ws-triage-status="${value}">${label}</button>`;
  }).join("");
  return `
    <article class="ws-triage-card" data-finding-id="${escapeHtml(id)}" data-session-id="${escapeHtml(sessionId)}" data-surface="${escapeHtml(String(f.surface_target || f.host || "_session"))}">
      <p class="ws-triage-title">${escapeHtml(title)}</p>
      <p class="ws-triage-meta-line">${escapeHtml(f.severity || "info")} · ${escapeHtml(host)}${refs ? ` · ${escapeHtml(refs)}` : ""}</p>
      <div class="ws-triage-actions">${buttons}</div>
    </article>`;
}

export function initWorkspaceTriage() {
  document.getElementById("workspace-triage-body")?.addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-ws-triage-status]");
    const card = e.target.closest(".ws-triage-card");
    if (!btn || !card) return;
    const sessionId = card.getAttribute("data-session-id") || "";
    const findingId = card.getAttribute("data-finding-id") || "";
    const surface = card.getAttribute("data-surface") || "_session";
    const status = btn.getAttribute("data-ws-triage-status") || "";
    if (!sessionId || !findingId || !status) return;
    btn.disabled = true;
    try {
      const res = await patchSessionFinding(sessionId, findingId, {
        surface_target: surface,
        status,
        evidence: `workspace-triage:${status}`,
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Falha ao salvar");
      }
      toast("Status atualizado", "ok");
      await refreshWorkspaceTriage();
    } catch (err) {
      toast(err.message || "Falha ao classificar", "err");
      btn.disabled = false;
    }
  });
}
