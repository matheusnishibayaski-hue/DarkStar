/** Modal Files — lista simples de artefatos em /tools/output. */

import { listFiles } from "./api/routes.js";
import { fileOpenUrl } from "./api.js";
import { deleteFile } from "./data-admin.js";
import { attachDeleteAction, formatBytes, formatDate } from "./row-actions.js";
import { escapeHtml } from "./exec.js";
import { openOverlay } from "./ui.js";

let ctx = {};
let filesCache = [];
let filter = "";

export function initFilesPanel(context) {
  ctx = context;
  ctx.filesRefreshBtn?.addEventListener("click", () => loadFiles(true));
  ctx.filesSearch?.addEventListener("input", () => {
    filter = (ctx.filesSearch.value || "").trim().toLowerCase();
    render();
  });
}

function basename(path) {
  return (path || "").split("/").pop() || path;
}

function folderOf(path) {
  const parts = (path || "").split("/");
  return parts.length > 1 ? parts.slice(0, -1).join("/") : "";
}

function render() {
  const { filesListEl, filesMetaEl } = ctx;
  if (!filesListEl) return;

  let list = filesCache;
  if (filter) {
    list = list.filter((f) => f.name.toLowerCase().includes(filter));
  }

  if (filesMetaEl) {
    filesMetaEl.textContent = list.length
      ? `${list.length} arquivo${list.length === 1 ? "" : "s"}`
      : "nenhum arquivo";
  }

  if (!list.length) {
    filesListEl.innerHTML = `
      <div class="files-simple-empty">
        <p>${filter ? "Nada corresponde à busca." : "Pasta vazia."}</p>
        <p class="files-simple-hint">No chat, peça para salvar assim:<br>
          <code>nmap -oN /tools/output/scan.txt alvo.com</code>
        </p>
      </div>`;
    return;
  }

  // agrupa por pasta
  const groups = new Map();
  for (const f of list) {
    const folder = folderOf(f.name) || "raiz";
    if (!groups.has(folder)) groups.set(folder, []);
    groups.get(folder).push(f);
  }

  filesListEl.innerHTML = [...groups.entries()]
    .map(([folder, items]) => {
      const rows = items
        .map((f) => {
          const name = f.name;
          return `
          <div class="files-simple-row" data-row-id="${escapeHtml(name)}">
            <div class="files-simple-info">
              <span class="files-simple-name">${escapeHtml(basename(name))}</span>
              <span class="files-simple-meta">${escapeHtml(formatBytes(f.size))} · ${escapeHtml(formatDate(f.modified_at))}</span>
            </div>
            <div class="files-simple-actions">
              <a class="files-simple-btn" href="${escapeHtml(fileOpenUrl(name))}" target="_blank" rel="noopener">Abrir</a>
              <button type="button" class="files-simple-btn files-simple-btn--danger files-del-btn">Excluir</button>
            </div>
          </div>`;
        })
        .join("");
      return `
        <section class="files-simple-group">
          <h3 class="files-simple-folder">${escapeHtml(folder)}</h3>
          ${rows}
        </section>`;
    })
    .join("");

  filesListEl.querySelectorAll(".files-del-btn").forEach((btn) => {
    const row = btn.closest("[data-row-id]");
    const name = row?.dataset.rowId;
    if (!name) return;
    attachDeleteAction(btn, {
      label: basename(name),
      toast: ctx.toast,
      onDelete: async () => {
        await deleteFile(name);
        await loadFiles(true);
      },
    });
  });
}

async function loadFiles(force = false) {
  const { filesListEl } = ctx;
  if (!force && filesCache.length) {
    render();
    return;
  }
  if (filesListEl) filesListEl.innerHTML = `<p class="files-simple-empty">carregando…</p>`;
  try {
    const res = await listFiles();
    if (!res.ok) throw new Error("Não foi possível listar os arquivos");
    const data = await res.json();
    filesCache = data.files || [];
    render();
  } catch (e) {
    if (filesListEl) {
      filesListEl.innerHTML = `<p class="files-simple-empty">${escapeHtml(e.message)}</p>`;
    }
  }
}

export async function openFilesPanel(nameFilter = "") {
  if (!ctx.overlayFiles) return;
  filter = (nameFilter || "").trim().toLowerCase();
  if (ctx.filesSearch) ctx.filesSearch.value = filter;
  openOverlay(ctx.overlayFiles);
  await loadFiles(true);
}

/** Compat: chamado pelo hub antigo */
export async function loadFilesInto() {
  await loadFiles(true);
}
