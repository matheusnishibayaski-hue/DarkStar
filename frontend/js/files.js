/** Painel de artefatos — /tools/output (volume compartilhado com o Kali). */

import { listFiles } from "./api/routes.js";
import { apiFetch } from "./api.js";
import { escapeHtml } from "./exec.js";
import { openOverlay } from "./ui.js";

const ICONS = {
  pcap: "◎",
  html: "◇",
  json: "{ }",
  markdown: "md",
  archive: "▣",
  image: "▦",
  scan: "⌗",
  text: "▤",
  file: "▤",
};

let ctx = {};
let nameFilter = "";

export function initFilesPanel(context) {
  ctx = context;
  ctx.filesRefreshBtn?.addEventListener("click", () => loadFiles());
}

function formatSize(bytes) {
  if (!bytes || bytes < 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDate(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" });
  } catch {
    return iso;
  }
}

function fileIcon(kind) {
  return ICONS[kind] || ICONS.file;
}

function fileUrl(name) {
  const encoded = name.split("/").map(encodeURIComponent).join("/");
  return `/api/files/${encoded}`;
}

async function downloadFile(name) {
  try {
    const res = await apiFetch(fileUrl(name));
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Falha no download");
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name.split("/").pop() || "download";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    ctx.toast?.(`download: ${name.split("/").pop()}`, "success");
  } catch (e) {
    ctx.toast?.(e.message || "Erro ao baixar", "error");
  }
}

function renderFiles(files, root) {
  const { filesListEl, filesMetaEl } = ctx;
  if (!filesListEl) return;

  let visible = files;
  if (nameFilter) {
    const q = nameFilter.toLowerCase();
    visible = files.filter((f) => f.name.toLowerCase().includes(q));
  }

  if (filesMetaEl) {
    const suffix = nameFilter ? ` · filtro: ${nameFilter}` : "";
    filesMetaEl.textContent = `${visible.length} arquivo(s) · ${root || "/tools/output"}${suffix}`;
  }

  if (!visible.length) {
    const exampleTarget = nameFilter || "scanme.nmap.org";
    filesListEl.innerHTML = `
      <p class="files-empty">Nenhum artefato${nameFilter ? " para este filtro" : " ainda"}.</p>
      <p class="files-hint">Peça à IA salvar saídas em <code>/tools/output/</code>:</p>
      <pre class="files-example">nmap -oA /tools/output/scan ${escapeHtml(exampleTarget)}</pre>
      ${nameFilter ? '<button type="button" class="files-clear-filter" id="files-clear-filter">limpar filtro</button>' : ""}
    `;
    document.getElementById("files-clear-filter")?.addEventListener("click", () => {
      nameFilter = "";
      loadFiles();
    });
    return;
  }

  filesListEl.innerHTML = "";
  const table = document.createElement("div");
  table.className = "files-table";
  table.setAttribute("role", "table");

  const head = document.createElement("div");
  head.className = "files-row files-row-head";
  head.setAttribute("role", "row");
  head.innerHTML = `
    <span class="files-col files-col-icon" role="columnheader"></span>
    <span class="files-col files-col-name" role="columnheader">nome</span>
    <span class="files-col files-col-size" role="columnheader">tam</span>
    <span class="files-col files-col-date" role="columnheader">mod</span>
    <span class="files-col files-col-action" role="columnheader"></span>
  `;
  table.appendChild(head);

  for (const f of visible) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "files-row files-row-item";
    row.setAttribute("role", "row");
    row.title = `Baixar ${f.name}`;
    row.innerHTML = `
      <span class="files-col files-col-icon" aria-hidden="true">${fileIcon(f.kind)}</span>
      <span class="files-col files-col-name">
        <span class="files-name">${escapeHtml(f.name)}</span>
        ${f.extension ? `<span class="files-ext">.${escapeHtml(f.extension)}</span>` : ""}
      </span>
      <span class="files-col files-col-size">${formatSize(f.size)}</span>
      <span class="files-col files-col-date">${formatDate(f.modified_at)}</span>
      <span class="files-col files-col-action" aria-hidden="true">↓</span>
    `;
    row.addEventListener("click", () => downloadFile(f.name));
    table.appendChild(row);
  }

  filesListEl.appendChild(table);
}

async function loadFiles() {
  const { filesListEl } = ctx;
  if (filesListEl) {
    filesListEl.innerHTML = '<p class="files-empty">listando /tools/output …</p>';
  }

  try {
    const res = await listFiles();
    if (!res.ok) throw new Error("Falha ao listar arquivos");
    const data = await res.json();
    renderFiles(data.files || [], data.root);
  } catch (e) {
    if (filesListEl) {
      filesListEl.innerHTML = `<p class="files-empty">${escapeHtml(e.message)}</p>`;
    }
  }
}

export async function openFilesPanel(filter = "") {
  if (!ctx.overlayFiles) return;
  nameFilter = (filter || "").trim().toLowerCase();
  openOverlay(ctx.overlayFiles);
  await loadFiles();
}
