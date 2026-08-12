/** Relatório da conversa: triagem de achados + download PDF (workspace). */

import { escapeHtml } from "./exec.js";
import { getIntelSession, patchSessionFinding, syncIntelSessionExecutions } from "./api/routes.js";
import { getActiveSession, collectSessionExecutions } from "./sessions.js";
import { downloadSessionPdf } from "./session-report-pdf.js";

let ctx = {};
let findings = [];
let sessionId = "";
let pdfBusy = false;

const STATUS_LABEL = {
  confirmed: "Vulnerabilidade",
  false_positive: "Falso positivo",
  discarded: "Descartado",
  candidate: "Pendente",
  inconclusive: "Pendente",
};

const SEV_ORDER = [
  { key: "alto", label: "Severidade alta" },
  { key: "medio", label: "Severidade média" },
  { key: "baixo", label: "Severidade baixa" },
];

function sevBucket(sev) {
  const s = (sev || "").toLowerCase();
  if (s === "critical" || s === "high") return "alto";
  if (s === "medium") return "medio";
  return "baixo";
}

function countByStatus(list) {
  const c = { confirmed: 0, false_positive: 0, discarded: 0, pending: 0 };
  for (const f of list) {
    const st = f.status || "candidate";
    if (st === "confirmed") c.confirmed += 1;
    else if (st === "false_positive") c.false_positive += 1;
    else if (st === "discarded") c.discarded += 1;
    else c.pending += 1;
  }
  return c;
}

export function initSessionReportModal(context) {
  ctx = context;
  const body = ctx.reportModalBody || document.getElementById("session-report-body");
  body?.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-status]");
    if (!btn || !body?.contains(btn)) return;
    setStatus(btn.getAttribute("data-id"), btn.getAttribute("data-target"), btn.getAttribute("data-status"));
  });

  document.getElementById("session-report-download")?.addEventListener("click", () => handleDownloadPdf());
}

export function openSessionReportModal() {
  const body = ctx.reportModalBody || document.getElementById("session-report-body");
  const session = getActiveSession();
  if (!session) {
    if (body) body.innerHTML = `<p class="session-modal-empty">Nenhuma conversa ativa.</p>`;
    ctx.toast?.("Nenhuma conversa ativa", "warn");
    return;
  }
  if (!collectSessionExecutions(session).length) {
    if (body) {
      body.innerHTML = `<p class="session-modal-empty">Execute ferramentas no chat antes do relatório.</p>`;
    }
    ctx.toast?.("Execute ferramentas no chat antes do relatório", "warn");
    return;
  }
  sessionId = session.id;
  loadFindings();
}

export function closeSessionReportModal() {
  /* painel no workspace */
}

async function handleDownloadPdf() {
  if (pdfBusy) return;
  const session = getActiveSession();
  if (!session) return;
  const btn = document.getElementById("session-report-download");
  pdfBusy = true;
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Gerando PDF…";
  }
  try {
    await downloadSessionPdf(session);
    ctx.toast?.("PDF baixado — também em Relatórios (Alt+F)", "success");
  } catch (e) {
    ctx.toast?.(e.message || "Falha ao gerar PDF", "error");
  } finally {
    pdfBusy = false;
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Baixar PDF";
    }
  }
}

async function loadFindings() {
  const el = ctx.reportModalBody;
  if (!el) return;
  const session = getActiveSession();
  el.innerHTML = `<p class="session-modal-hint session-report-loading">Carregando achados…</p>`;
  try {
    const res = await getIntelSession(sessionId);
    if (res.ok) {
      const data = await res.json();
      findings = data.findings || [];
    } else {
      findings = [];
    }
  } catch {
    findings = [];
  }

  if (!findings.length && session) {
    const execs = collectSessionExecutions(session);
    if (execs.length) {
      try {
        const syncRes = await syncIntelSessionExecutions(sessionId, execs);
        if (syncRes.ok) {
          const reload = await getIntelSession(sessionId);
          if (reload.ok) {
            const data = await reload.json();
            findings = data.findings || [];
          }
        }
      } catch {
        /* ignore */
      }
    }
  }

  renderFindings();
}

function renderSummaryBar() {
  const counts = countByStatus(findings);
  return `
    <div class="session-report-summary" role="status">
      <div class="session-report-stat session-report-stat--total">
        <span class="session-report-stat-n">${findings.length}</span>
        <span class="session-report-stat-l">achados</span>
      </div>
      <div class="session-report-stat session-report-stat--ok">
        <span class="session-report-stat-n">${counts.confirmed}</span>
        <span class="session-report-stat-l">vulnerabilidade</span>
      </div>
      <div class="session-report-stat session-report-stat--fp">
        <span class="session-report-stat-n">${counts.false_positive}</span>
        <span class="session-report-stat-l">falso +</span>
      </div>
      <div class="session-report-stat session-report-stat--drop">
        <span class="session-report-stat-n">${counts.discarded}</span>
        <span class="session-report-stat-l">descartado</span>
      </div>
      <div class="session-report-stat session-report-stat--pend">
        <span class="session-report-stat-n">${counts.pending}</span>
        <span class="session-report-stat-l">pendente</span>
      </div>
    </div>`;
}

function renderFindingRow(f) {
  const id = f.id || "";
  const surfaceTarget = f.surface_target || f.host || "";
  const status = f.status || "candidate";
  const bucket = sevBucket(f.severity);
  const statusClass =
    status === "confirmed"
      ? "session-finding-status--ok"
      : status === "false_positive"
        ? "session-finding-status--fp"
        : status === "discarded"
          ? "session-finding-status--drop"
          : "session-finding-status--pend";
  return `
    <li class="session-finding-card" data-fid="${escapeHtml(id)}">
      <div class="session-finding-main">
        <div class="session-finding-head">
          <span class="session-finding-sev session-finding-sev--${bucket}">${escapeHtml(SEV_ORDER.find((x) => x.key === bucket)?.label?.replace("Severidade ", "") || "—")}</span>
          <span class="session-finding-status ${statusClass}">${escapeHtml(STATUS_LABEL[status] || status)}</span>
        </div>
        <p class="session-finding-title">${escapeHtml(f.title || "—")}</p>
        <p class="session-finding-meta">
          ${f.tool ? `<span class="session-finding-tag">${escapeHtml(f.tool)}</span>` : ""}
          ${surfaceTarget && surfaceTarget !== "_session" ? `<span class="session-finding-tag">${escapeHtml(surfaceTarget)}</span>` : ""}
        </p>
        ${f.evidence ? `<p class="session-finding-evidence">${escapeHtml(String(f.evidence).slice(0, 320))}</p>` : ""}
      </div>
      ${
        id
          ? `<div class="session-finding-btns" role="group" aria-label="Classificar achado">
              <button type="button" class="intel-triage-btn intel-triage-btn--ok${status === "confirmed" ? " is-on" : ""}" data-status="confirmed" data-id="${escapeHtml(id)}" data-target="${escapeHtml(surfaceTarget || "_session")}">Vulnerabilidade</button>
              <button type="button" class="intel-triage-btn intel-triage-btn--fp${status === "false_positive" ? " is-on" : ""}" data-status="false_positive" data-id="${escapeHtml(id)}" data-target="${escapeHtml(surfaceTarget || "_session")}">Falso positivo</button>
              <button type="button" class="intel-triage-btn intel-triage-btn--drop${status === "discarded" ? " is-on" : ""}" data-status="discarded" data-id="${escapeHtml(id)}" data-target="${escapeHtml(surfaceTarget || "_session")}">Descartar</button>
            </div>`
          : ""
      }
    </li>`;
}

function renderFindings() {
  const el = ctx.reportModalBody;
  const meta = ctx.reportModalMeta;
  const footerHint = document.getElementById("session-report-footer-hint");
  if (!el) return;

  const execCount = collectSessionExecutions(getActiveSession() || {}).length;

  if (!findings.length) {
    el.innerHTML = `
      <div class="session-report-empty">
        <p class="session-modal-empty">Nenhum achado estruturado ainda</p>
        <p class="session-modal-hint">${
          execCount
            ? `Há ${execCount} execução(ões) nesta conversa. Scans com nuclei/nmap costumam gerar itens aqui; você ainda pode baixar um PDF com o resumo das execuções.`
            : "Rode ferramentas nesta conversa para popular o relatório."
        }</p>
      </div>`;
    if (meta) meta.textContent = execCount ? `${execCount} execução(ões) · 0 achados` : "0 achados";
    if (footerHint) {
      footerHint.textContent =
        "Sem achados para triar. Use Baixar PDF para um relatório das execuções desta conversa.";
    }
    return;
  }

  const counts = countByStatus(findings);
  if (meta) {
    meta.textContent = `${findings.length} achado(s) · ${counts.pending} pendente(s) · ${counts.confirmed} no PDF`;
  }
  if (footerHint) {
    footerHint.textContent =
      counts.pending > 0
        ? `${counts.pending} item(ns) ainda pendente(s). O PDF prioriza o que você marcou como vulnerabilidade.`
        : "Triagem concluída. Baixe o PDF quando quiser.";
  }

  let html = renderSummaryBar();
  html += `<p class="session-modal-hint session-report-intro">Escolha como tratar cada achado. Nada é baixado até você clicar em <strong>Baixar PDF</strong>.</p>`;

  for (const { key, label } of SEV_ORDER) {
    const items = groupsFor(findings, key);
    if (!items.length) continue;
    html += `
      <section class="session-report-sev">
        <h3 class="session-report-sev-title">${label} <em>${items.length}</em></h3>
        <ul class="session-findings-list">${items.map(renderFindingRow).join("")}</ul>
      </section>`;
  }
  el.innerHTML = html;
}

function groupsFor(list, key) {
  return list.filter((f) => sevBucket(f.severity) === key);
}

async function setStatus(fid, surfaceTarget, status) {
  if (!sessionId || !fid || !surfaceTarget) return;
  try {
    const res = await patchSessionFinding(sessionId, fid, {
      surface_target: surfaceTarget,
      status,
      evidence: `manual:${status}`,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Falha ao salvar");
    }
    const row = findings.find((f) => f.id === fid);
    if (row) row.status = status;
    ctx.toast?.(`Marcado: ${STATUS_LABEL[status] || status}`, "success");
    renderFindings();
  } catch (e) {
    ctx.toast?.(e.message || "Erro ao salvar", "error");
  }
}

/** Atalho legado: abre o modal em vez de baixar direto. */
export function openReportFromShortcut() {
  openSessionReportModal();
}
