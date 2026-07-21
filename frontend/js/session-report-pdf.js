/** Download do PDF da conversa ativa. */

import { apiFetch } from "./api.js";
import {
  getActiveSession,
  sessionTitle,
  collectSessionExecutions,
  collectSessionHistory,
} from "./sessions.js";

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

export async function downloadSessionPdf(session, { silent = false } = {}) {
  if (!session) throw new Error("Nenhuma conversa ativa.");
  const toolExecutions = collectSessionExecutions(session);
  if (!toolExecutions.length) throw new Error("Nenhuma ferramenta executada nesta conversa.");

  const history = collectSessionHistory(session);
  const surfaceTarget = inferSurfaceTarget(session, history, toolExecutions);
  const res = await apiFetch("/api/generate-report", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
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
    throw new Error(err.detail || res.statusText || "Falha ao gerar PDF");
  }

  const blob = await res.blob();
  const title = `Relatório — ${sessionTitle(session)}`;
  const fileName = `relatorio-${sessionTitle(session)
    .replace(/[^\w\s.-áàâãéêíóôõúç-]/gi, "")
    .trim()
    .replace(/\s+/g, "-")
    .slice(0, 48) || "pentest"}-${new Date().toISOString().slice(0, 10)}.pdf`;

  try {
    const { saveDownloadedReport } = await import("./reports-store.js");
    await saveDownloadedReport({
      blob,
      sessionId: session.id,
      title,
      fileName,
    });
  } catch {
    /* biblioteca local opcional */
  }

  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  a.click();
  URL.revokeObjectURL(url);
  if (!silent) return true;
  return true;
}
