/** Ações de linha reutilizáveis — excluir com confirmação inline. */

import { escapeHtml } from "./exec.js";

/**
 * Anexa fluxo de exclusão em duas etapas (excluir → confirmar).
 * @param {object} opts
 * @param {boolean|null} [opts.removeOnSuccess] — remove o scope após sucesso (default: true se houver scope)
 * @returns {() => void} cleanup
 */
export function attachDeleteAction(btn, { label, onDelete, toast, removeOnSuccess = null }) {
  if (!btn) return () => {};

  const handler = (e) => {
    e.preventDefault();
    e.stopPropagation();
    const scope = btn.closest("[data-row-id], [data-delete-scope]");
    const shouldRemove = removeOnSuccess ?? Boolean(scope);

    if (scope?.classList.contains("is-deleting")) return;
    if (!scope && btn.disabled) return;

    if (!btn.classList.contains("is-armed")) {
      const disarmRoot = scope?.parentElement || btn.closest(".data-cards, .record-list, .panel-body") || btn.parentElement;
      disarmRoot?.querySelectorAll(".row-action.is-armed").forEach((b) => {
        b.classList.remove("is-armed");
        b.textContent = b.dataset.defaultLabel || "excluir";
      });
      btn.classList.add("is-armed");
      btn.textContent = btn.dataset.confirmLabel || "confirmar?";
      return;
    }

    scope?.classList.add("is-deleting");
    btn.disabled = true;
    onDelete()
      .then(() => {
        if (shouldRemove && scope) {
          scope.classList.add("row-removing");
          setTimeout(() => scope.remove(), 180);
        }
        toast?.(`${label} excluído`, "success");
      })
      .catch((err) => {
        scope?.classList.remove("is-deleting");
        btn.disabled = false;
        btn.classList.remove("is-armed");
        btn.textContent = btn.dataset.defaultLabel || "excluir";
        toast?.(err?.message || "Falha ao excluir", "error");
      });
  };

  btn.dataset.defaultLabel = btn.textContent.trim();
  btn.addEventListener("click", handler);
  return () => btn.removeEventListener("click", handler);
}

export function renderLogRow(log, { showCommand = false } = {}) {
  const id = log.id || "";
  const cmd = log.command || log.tool || "";
  const hasFile = log.has_file !== false;
  return `
    <article class="record-row" data-row-id="${escapeHtml(id)}" role="row">
      <div class="record-row-main">
        <code class="record-id" title="${escapeHtml(id)}">${escapeHtml(id)}</code>
        ${!hasFile ? `<span class="record-tag">só auditoria</span>` : ""}
        ${showCommand && cmd ? `<span class="record-sub">${escapeHtml(cmd.slice(0, 64))}${cmd.length > 64 ? "…" : ""}</span>` : ""}
        ${!showCommand && cmd && !hasFile ? `<span class="record-sub">${escapeHtml(cmd.slice(0, 64))}${cmd.length > 64 ? "…" : ""}</span>` : ""}
        <span class="record-meta">
          <span>${escapeHtml(formatBytes(log.size))}</span>
          <span>${escapeHtml(formatDate(log.modified_at))}</span>
        </span>
      </div>
      <div class="record-row-actions">
        ${hasFile ? `<a class="row-action row-action--ghost" href="/api/logs/${encodeURIComponent(id)}" target="_blank" rel="noopener">abrir</a>` : ""}
        <button type="button" class="row-action row-action--danger" data-delete-log="${escapeHtml(id)}">excluir</button>
      </div>
    </article>`;
}

export function formatBytes(bytes) {
  if (!bytes || bytes < 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function formatDate(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" });
  } catch {
    return iso;
  }
}

export function bindLogDeleteButtons(root, { deleteFn, toast, onDeleted }) {
  const cleanups = [];
  root?.querySelectorAll("[data-delete-log]").forEach((btn) => {
    const id = btn.getAttribute("data-delete-log");
    if (!id) return;
    cleanups.push(
      attachDeleteAction(btn, {
        label: `log ${id.slice(0, 8)}`,
        toast,
        onDelete: async () => {
          await deleteFn(id);
          onDeleted?.();
        },
      })
    );
  });
  return () => cleanups.forEach((fn) => fn());
}
