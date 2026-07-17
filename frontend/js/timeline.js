/** Timeline de execuções da sessão ativa. */

import { escapeHtml } from "./exec.js";
import { collectSessionExecutions, getActiveSession } from "./sessions.js";

let ctx = {};

export function initTimeline(context) {
  ctx = context;
}

function statusLabel(ex) {
  if (ex.blocked) return "blocked";
  if (ex.success) return "ok";
  return `exit ${ex.exit_code ?? "?"}`;
}

function statusClass(ex) {
  if (ex.blocked) return "timeline-status--blocked";
  if (ex.success) return "timeline-status--ok";
  return "timeline-status--fail";
}

export function renderTimeline() {
  const { timelineEl } = ctx;
  if (!timelineEl) return;

  const session = getActiveSession();
  const execs = collectSessionExecutions(session);

  if (!execs.length) {
    timelineEl.innerHTML = `
      <p class="timeline-empty">Nenhuma execução nesta sessão.</p>
      <p class="timeline-hint">Envie um comando ou inicie o auto-pilot — as tools aparecem aqui em ordem.</p>
    `;
    return;
  }

  timelineEl.innerHTML = "";
  const list = document.createElement("ol");
  list.className = "timeline-list";

  execs.forEach((ex, i) => {
    const item = document.createElement("li");
    item.className = "timeline-item";
    const logId = ex.log_file_id || "";
    const cmd = ex.command || ex.tool || "—";
    item.innerHTML = `
      <div class="timeline-marker" aria-hidden="true"></div>
      <div class="timeline-body">
        <div class="timeline-head">
          <span class="timeline-index">#${i + 1}</span>
          <span class="timeline-status ${statusClass(ex)}">${escapeHtml(statusLabel(ex))}</span>
        </div>
        <code class="timeline-cmd">${escapeHtml(cmd)}</code>
        ${ex.reason ? `<p class="timeline-reason">${escapeHtml(ex.reason)}</p>` : ""}
        <div class="timeline-actions">
          ${logId ? `<a class="timeline-link" href="/api/logs/${encodeURIComponent(logId)}" target="_blank" rel="noopener">abrir log</a>` : ""}
          ${logId ? `<button type="button" class="timeline-link-btn" data-open-logs>gerenciar</button>` : ""}
          <button type="button" class="timeline-link-btn" data-open-files>artefatos</button>
        </div>
      </div>
    `;
    item.querySelector("[data-open-files]")?.addEventListener("click", () => {
      ctx.onOpenFiles?.();
    });
    item.querySelector("[data-open-logs]")?.addEventListener("click", () => {
      ctx.onOpenLogs?.();
    });
    list.appendChild(item);
  });

  timelineEl.appendChild(list);
}
