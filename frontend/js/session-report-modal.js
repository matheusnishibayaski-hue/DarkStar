/** Relatório da conversa: pré-visualização ao vivo + download PDF. */

import { apiFetch } from "./api.js";
import {
  getActiveSession,
  sessionTitle,
  collectSessionExecutions,
  collectSessionHistory,
} from "./sessions.js";
import { downloadSessionPdf } from "./session-report-pdf.js";
import { openFilesPanel } from "./files.js";
import { runTriageGate } from "./triage-gate.js";
import { refreshPortfolio } from "./portfolio.js";

let ctx = {};
let pdfBusy = false;
let previewTimer = null;
let lastFingerprint = "";
let listening = false;
let pendingExecs = [];

function inferSurfaceTarget(session, history, toolExecutions) {
  const texts = [
    ...(history || []).map((m) => m.content || ""),
    ...(toolExecutions || []).map((e) => e.command || ""),
  ].join("\n");
  const urlMatch = texts.match(/https?:\/\/([a-z0-9][-a-z0-9.]+[a-z0-9])/i);
  if (urlMatch) return urlMatch[1].toLowerCase();
  const hostMatch = texts.match(
    /\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\.[a-z]{2,})\b/i
  );
  return hostMatch ? hostMatch[1].toLowerCase() : "";
}

function collectReportExecutions(session) {
  const saved = collectSessionExecutions(session);
  const seen = new Set(saved.map((e) => `${e.command}|${e.log_file_id || ""}`));
  const extras = pendingExecs.filter((e) => !seen.has(`${e.command}|${e.log_file_id || ""}`));
  return [...saved, ...extras];
}

function fingerprint(session) {
  if (!session) return "none";
  const execs = collectSessionExecutions(session);
  const last = session.messages?.[session.messages.length - 1];
  return [
    session.id,
    session.messages?.length || 0,
    execs.length,
    pendingExecs.length,
    last?.at || session.updatedAt || 0,
    (last?.content || "").length,
  ].join(":");
}

function isReportTabOpen() {
  const panel = document.getElementById("ws-panel-report");
  return Boolean(panel && !panel.hidden);
}

export function initSessionReportModal(context) {
  ctx = context;
  document.getElementById("session-report-download")?.addEventListener("click", () => handleDownloadPdf());
  if (!listening) {
    listening = true;
    window.addEventListener("darkstar:session-updated", () => {
      pendingExecs = [];
      schedulePreviewRefresh();
    });
    window.addEventListener("darkstar:tool-done", (e) => {
      const d = e.detail || {};
      if (d.command) {
        pendingExecs.push({
          command: d.command,
          success: Boolean(d.success),
          blocked: Boolean(d.blocked),
          exit_code: d.exit_code ?? 0,
          stdout: d.stdout || "",
          stderr: d.stderr || "",
          reason: d.reason || "execução nesta conversa",
          tool: d.tool || "",
          log_file_id: d.log_file_id || d.execution_id || "",
        });
      }
      schedulePreviewRefresh();
    });
  }
}

export function openSessionReportModal() {
  const session = getActiveSession();
  lastFingerprint = "";
  updateToolbar(session);
  refreshPreview(true);
  openFilesPanel().catch(() => {});
  refreshPortfolio().catch(() => {});
}

export function closeSessionReportModal() {
  /* painel no workspace */
}

export function schedulePreviewRefresh() {
  if (!isReportTabOpen()) return;
  if (previewTimer) clearTimeout(previewTimer);
  previewTimer = setTimeout(() => refreshPreview(false), 700);
}

function updateToolbar(session) {
  const meta = ctx.reportModalMeta || document.getElementById("session-report-meta");
  const btn = document.getElementById("session-report-download");
  const hint = document.getElementById("session-report-footer-hint");
  const execs = session ? collectSessionExecutions(session) : [];
  const msgs = session?.messages || [];
  const canPdf = execs.length > 0 || msgs.some((m) => m.role === "user");
  if (meta) {
    meta.textContent = session
      ? `prévia ao vivo · ${execs.length} teste(s) · ${msgs.length} msg`
      : "nenhuma conversa ativa";
  }
  if (hint) {
    hint.textContent = canPdf
      ? "Baixar PDF abre a triagem do que ainda precisa da sua validação."
      : "Rode testes no chat — a prévia do relatório aparece aqui.";
  }
  if (btn) {
    btn.disabled = pdfBusy || !canPdf;
    if (!pdfBusy) btn.textContent = "Baixar PDF";
  }
}

async function refreshPreview(force = false) {
  const iframe = document.getElementById("session-report-preview");
  const session = getActiveSession();
  updateToolbar(session);
  if (!iframe) return;
  if (!session) {
    iframe.removeAttribute("src");
    iframe.removeAttribute("srcdoc");
    return;
  }
  const fp = fingerprint(session);
  if (!force && fp === lastFingerprint) return;
  lastFingerprint = fp;

  const history = collectSessionHistory(session);
  const toolExecutions = collectReportExecutions(session);
  const surfaceTarget = inferSurfaceTarget(session, history, toolExecutions);
  try {
    const res = await apiFetch("/api/generate-report/preview", {
      method: "POST",
      body: JSON.stringify({
        history,
        tool_executions: toolExecutions,
        title: `Relatório — ${sessionTitle(session)}`,
        chat_session_id: session.id,
        surface_target: surfaceTarget,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Falha na prévia");
    }
    const html = await res.text();
    iframe.removeAttribute("src");
    iframe.removeAttribute("sandbox");
    iframe.srcdoc = html;
  } catch (e) {
    iframe.srcdoc = `<p style="font-family:sans-serif;padding:2rem;color:#666">${
      e.message || "Não foi possível gerar a prévia."
    }</p>`;
  }
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
    if (btn) btn.textContent = "Triagem…";
    const proceed = await runTriageGate(session.id, collectReportExecutions(session));
    if (!proceed) {
      ctx.toast?.("Download cancelado — triagem incompleta", "warn");
      return;
    }
    if (btn) btn.textContent = "Gerando PDF…";
    await downloadSessionPdf(session);
    ctx.toast?.("PDF baixado e salvo nesta aba", "success");
    await openFilesPanel();
    await refreshPreview(true);
    await refreshPortfolio();
  } catch (e) {
    ctx.toast?.(e.message || "Falha ao gerar PDF", "error");
  } finally {
    pdfBusy = false;
    updateToolbar(getActiveSession());
  }
}

/** Atalho legado: abre o painel de relatório. */
export function openReportFromShortcut() {
  openSessionReportModal();
}
