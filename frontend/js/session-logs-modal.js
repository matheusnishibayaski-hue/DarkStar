/** Modal de logs da conversa ativa. */

import { openOverlay, closeOverlay } from "./ui.js";
import { escapeHtml } from "./exec.js";
import { getLog, listDataLogs } from "./api/routes.js";
import {
  getActiveSession,
  collectSessionExecutionsDetailed,
} from "./sessions.js";

let ctx = {};
let expandedId = "";

export function initSessionLogsModal(context) {
  ctx = context;
  ctx.btnSessionLogs?.addEventListener("click", () => openSessionLogsModal());
  ctx.overlaySessionLogs
    ?.querySelector('[data-close="overlay-session-logs"]')
    ?.addEventListener("click", () => closeSessionLogsModal());
}

export function openSessionLogsModal() {
  if (!ctx.overlaySessionLogs) return;
  const session = getActiveSession();
  if (!session) {
    ctx.toast?.("Nenhuma conversa ativa", "warn");
    return;
  }
  openOverlay(ctx.overlaySessionLogs);
  renderLogs(session);
}

export function closeSessionLogsModal() {
  if (ctx.overlaySessionLogs) closeOverlay(ctx.overlaySessionLogs);
}

function formatWhen(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return String(ts);
  return d.toLocaleString("pt-BR", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function truncate(text, max = 1200) {
  const s = String(text || "").trim();
  if (s.length <= max) return s;
  return `${s.slice(0, max)}\n… (truncado)`;
}

function outputPreview(ex) {
  const out = [ex.stdout, ex.stderr].filter(Boolean).join("\n").trim();
  return out || "(sem saída capturada no chat)";
}

async function renderLogs(session) {
  const el = ctx.logsModalBody;
  if (!el) return;

  const rows = collectSessionExecutionsDetailed(session);
  if (!rows.length) {
    el.innerHTML = `<p class="session-modal-empty">Nenhum comando executado nesta conversa ainda.</p>`;
    return;
  }

  el.innerHTML = `<p class="session-modal-hint">Carregando ${rows.length} execução(ões)…</p>`;

  let serverMeta = new Map();
  try {
    const res = await listDataLogs(session.id, 120);
    if (res.ok) {
      const body = await res.json();
      for (const row of body.logs || []) {
        serverMeta.set(row.id, row);
      }
    }
  } catch {
    /* local only */
  }

  el.innerHTML = rows
    .map((ex, idx) => {
      const logId = ex.log_file_id || "";
      const meta = logId ? serverMeta.get(logId) : null;
      const when = meta?.modified_at || ex.executedAt || session.updatedAt;
      const ok = ex.success ? "OK" : ex.blocked ? "BLOQ" : "FALHA";
      const cls = ex.success ? "log-ok" : ex.blocked ? "log-warn" : "log-fail";
      const key = logId || `local-${idx}`;
      return `
        <article class="session-log-card" data-log-key="${escapeHtml(key)}">
          <header class="session-log-head">
            <time class="session-log-time">${escapeHtml(formatWhen(when))}</time>
            <span class="session-log-badge ${cls}">${ok}</span>
            ${logId ? `<span class="session-log-id">#${escapeHtml(logId)}</span>` : ""}
          </header>
          <p class="session-log-cmd"><code>${escapeHtml(ex.command || "—")}</code></p>
          ${ex.reason ? `<p class="session-log-reason">${escapeHtml(ex.reason)}</p>` : ""}
          <button type="button" class="session-log-toggle" data-toggle="${escapeHtml(key)}">
            ver resultado
          </button>
          <pre class="session-log-output" id="log-out-${escapeHtml(key)}" hidden></pre>
        </article>`;
    })
    .join("");

  const byKey = new Map();
  rows.forEach((ex, idx) => {
    const key = ex.log_file_id || `local-${idx}`;
    byKey.set(key, ex);
  });

  el.querySelectorAll("[data-toggle]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const key = btn.getAttribute("data-toggle");
      const pre = document.getElementById(`log-out-${key}`);
      if (!pre) return;
      if (!pre.hidden) {
        pre.hidden = true;
        btn.textContent = "ver resultado";
        expandedId = "";
        return;
      }
      el.querySelectorAll(".session-log-output").forEach((node) => {
        node.hidden = true;
      });
      el.querySelectorAll(".session-log-toggle").forEach((b) => {
        b.textContent = "ver resultado";
      });
      expandedId = key;
      btn.textContent = "ocultar resultado";
      pre.hidden = false;
      pre.textContent = "carregando…";
      const ex = byKey.get(key);
      const logId = ex?.log_file_id;
      if (logId) {
        try {
          const res = await getLog(logId);
          if (res.ok) {
            pre.textContent = truncate(await res.text());
            return;
          }
        } catch {
          /* fallback */
        }
      }
      pre.textContent = truncate(outputPreview(ex || {}));
    });
  });
}
