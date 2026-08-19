/** Modo do composer (Agent/Plan/Ask/Review) e anexos. */

import {
  PROJECT_MAP_NAME,
  collectDroppedProjectFiles,
  ingestProjectFiles,
} from "./project-ingest.js";
import { toast } from "./ui.js";
import {
  appendFolderIngestResult,
  showFolderIngestProgress,
  updateFolderIngestProgress,
} from "./chat-view.js";
import {
  ensureSession,
  getActiveSession,
  saveStore,
  saveStoreNow,
} from "./sessions.js";

export const CHAT_MODE_KEY = "darkstar-chat-mode";
export const CHAT_MODES = ["agent", "plan", "ask", "review"];

/** @type {{name: string, content: string}[]} */
let attachments = [];

export function getChatMode() {
  try {
    const v = localStorage.getItem(CHAT_MODE_KEY) || "agent";
    return CHAT_MODES.includes(v) ? v : "agent";
  } catch {
    return "agent";
  }
}

export function setChatMode(mode) {
  const next = CHAT_MODES.includes(mode) ? mode : "agent";
  try {
    localStorage.setItem(CHAT_MODE_KEY, next);
  } catch { /* ignore */ }
  document.querySelectorAll("[data-chat-mode]").forEach((btn) => {
    btn.classList.toggle("active", btn.getAttribute("data-chat-mode") === next);
  });
  return next;
}

export function getAttachments() {
  return attachments.slice();
}

export function clearAttachments({ persist = true } = {}) {
  attachments = [];
  renderAttachmentChips();
  if (persist) persistPendingAttachments();
}

export function addAttachment(name, content) {
  attachments.push({ name: String(name).slice(0, 256), content: String(content).slice(0, 200000) });
  renderAttachmentChips();
  persistPendingAttachments();
}

export function removeAttachment(index) {
  attachments.splice(index, 1);
  renderAttachmentChips();
  persistPendingAttachments();
}

export function setAttachments(list, { persist = false } = {}) {
  attachments = Array.isArray(list)
    ? list.map((a) => ({
        name: String(a?.name || "").slice(0, 256),
        content: String(a?.content || "").slice(0, 200000),
      }))
    : [];
  renderAttachmentChips();
  if (persist) persistPendingAttachments();
}

/** Grava anexos pendentes na conversa ativa (sobrevive a F5). */
export function persistPendingAttachments() {
  const session = getActiveSession();
  if (!session) return;
  session.pendingAttachments = attachments.slice();
  saveStore();
}

/** Restaura chips a partir da conversa ativa. */
export function restoreAttachmentsFromSession(session = getActiveSession()) {
  setAttachments(session?.pendingAttachments || [], { persist: false });
}

/**
 * Empurra card de pasta como mensagem da conversa + mantém anexos.
 * @param {object} summary
 */
export function commitFolderIngestToSession(summary) {
  ensureSession();
  const session = getActiveSession();
  if (!session) return;
  if (summary?.error) {
    appendFolderIngestResult(summary);
    return;
  }
  session.messages.push({
    role: "assistant",
    kind: "folder-ingest",
    content: summary.folderName
      ? `Pasta anexada: ${summary.folderName}`
      : "Pasta anexada",
    folderSummary: {
      folderName: summary.folderName || "projeto",
      totalSeen: summary.totalSeen ?? 0,
      keptCount: summary.keptCount ?? 0,
      ignoredCount: summary.ignoredCount ?? 0,
      attached: summary.attached ?? 0,
      files: Array.isArray(summary.files) ? summary.files.slice(0, 40) : [],
    },
    at: Date.now(),
    toolExecutions: [],
  });
  session.pendingAttachments = attachments.slice();
  session.updatedAt = Date.now();
  appendFolderIngestResult(summary);
  saveStoreNow(session).catch((err) => console.warn("folder_persist_failed", err));
  // Pentest white-box automático — dynamic import evita ciclo com chat.js
  import("./chat.js")
    .then((m) => m.startFolderPentest(summary))
    .catch((err) => console.warn("folder_auto_pentest_failed", err));
}

function renderAttachmentChips() {
  const wrap = document.getElementById("composer-attach-chips");
  if (!wrap) return;
  wrap.hidden = attachments.length === 0;
  wrap.innerHTML = attachments
    .map((a, i) => {
      let label = a.name;
      if (a.name === PROJECT_MAP_NAME) {
        const m = a.content.match(/\((\d+) arquivos após filtros/);
        label = m ? `mapa (${m[1]} arq.)` : "mapa do repo";
      } else {
        const parts = a.name.split("/");
        label = parts.length > 2 ? `…/${parts.slice(-2).join("/")}` : a.name;
      }
      return `<button type="button" class="attach-chip" data-attach-i="${i}" title="${escapeText(a.name)}">${escapeText(label)}</button>`;
    })
    .join("");
  wrap.querySelectorAll("[data-attach-i]").forEach((btn) => {
    btn.addEventListener("click", () => removeAttachment(Number(btn.getAttribute("data-attach-i"))));
  });
}

function escapeText(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

/** @deprecated use ingestProjectFiles */
export async function ingestFiles(fileList) {
  return runFolderIngest(fileList);
}

async function runFolderIngest(fileList, { collectingLabel } = {}) {
  showFolderIngestProgress(collectingLabel || "Preparando pasta…");
  try {
    const result = await ingestProjectFiles(fileList, {
      addAttachment: (name, content) => {
        attachments.push({
          name: String(name).slice(0, 256),
          content: String(content).slice(0, 200000),
        });
        renderAttachmentChips();
      },
      clearAttachments: () => {
        attachments = [];
        renderAttachmentChips();
      },
      toast,
      onProgress: (label) => updateFolderIngestProgress(label),
    });
    if (!result?.map && !(fileList && fileList.length)) {
      commitFolderIngestToSession({ error: "Nenhuma pasta selecionada." });
      return result;
    }
    if (!result?.map) {
      commitFolderIngestToSession({ error: "Nenhuma pasta selecionada." });
      return result;
    }
    commitFolderIngestToSession({
      folderName: result.folderName,
      totalSeen: result.totalSeen,
      keptCount: result.keptCount,
      ignoredCount: result.ignoredCount,
      attached: result.attached,
      files: result.files,
    });
    return result;
  } catch (err) {
    commitFolderIngestToSession({ error: `Falha ao anexar pasta: ${err?.message || err}` });
    return null;
  }
}

export function initComposerExtras() {
  setChatMode(getChatMode());
  document.getElementById("composer-modes")?.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-chat-mode]");
    if (btn) setChatMode(btn.getAttribute("data-chat-mode"));
  });

  const plus = document.getElementById("composer-plus");
  const menu = document.getElementById("composer-plus-menu");
  plus?.addEventListener("click", (e) => {
    e.stopPropagation();
    if (menu) menu.hidden = !menu.hidden;
  });
  document.addEventListener("click", () => {
    if (menu) menu.hidden = true;
  });
  menu?.addEventListener("click", (e) => e.stopPropagation());

  document.getElementById("composer-attach-folder")?.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (menu) menu.hidden = true;
    const input = document.getElementById("composer-folder-input");
    setTimeout(() => input?.click(), 0);
  });
  document.getElementById("composer-attach-github")?.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (menu) menu.hidden = true;
    const ov = document.getElementById("overlay-github-tree");
    if (ov) {
      ov.hidden = false;
      requestAnimationFrame(() => ov.classList.add("overlay-visible"));
    }
  });

  document.getElementById("composer-folder-input")?.addEventListener("change", async (e) => {
    const input = e.target;
    const files = input.files;
    try {
      await runFolderIngest(files);
    } catch {
      /* resultado já no chat */
    } finally {
      input.value = "";
    }
  });

  initChatFolderDrop();
  initGithubOverlay();
}

function initChatFolderDrop() {
  const zone =
    document.querySelector(".ide-editor-body") ||
    document.getElementById("terminal") ||
    document.getElementById("chat");
  if (!zone) return;

  let depth = 0;
  let dropping = false;

  const setActive = (on) => {
    zone.classList.toggle("chat-drop-active", on);
  };

  const isFileDrag = (e) => {
    const types = e.dataTransfer?.types;
    if (!types) return false;
    return [...types].includes("Files");
  };

  zone.addEventListener("dragenter", (e) => {
    if (!isFileDrag(e)) return;
    e.preventDefault();
    depth += 1;
    setActive(true);
  });
  zone.addEventListener("dragover", (e) => {
    if (!isFileDrag(e)) return;
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = "copy";
  });
  zone.addEventListener("dragleave", (e) => {
    if (!isFileDrag(e)) return;
    depth = Math.max(0, depth - 1);
    if (depth === 0) setActive(false);
  });
  zone.addEventListener("drop", async (e) => {
    if (!isFileDrag(e)) return;
    e.preventDefault();
    e.stopPropagation();
    depth = 0;
    setActive(false);
    if (dropping) return;
    dropping = true;
    try {
      showFolderIngestProgress("Coletando arquivos da pasta…");
      const files = await collectDroppedProjectFiles(e.dataTransfer);
      if (!files.length) {
        commitFolderIngestToSession({ error: "Nenhum arquivo encontrado no drop." });
        return;
      }
      updateFolderIngestProgress(`Coletados ${files.length} itens — indexando…`);
      await runFolderIngest(files, { collectingLabel: `Indexando ${files.length} itens…` });
    } catch (err) {
      commitFolderIngestToSession({ error: `Falha no drop: ${err?.message || err}` });
    } finally {
      dropping = false;
    }
  });
}

async function initGithubOverlay() {
  const overlay = document.getElementById("overlay-github-tree");
  const close = document.getElementById("github-tree-close");
  const loadBtn = document.getElementById("github-tree-load");
  const attachBtn = document.getElementById("github-tree-attach-project");
  const input = document.getElementById("github-tree-repo");
  const list = document.getElementById("github-tree-list");
  const meta = document.getElementById("github-tree-meta");
  close?.addEventListener("click", () => {
    overlay?.classList.remove("overlay-visible");
    if (overlay) overlay.hidden = true;
  });
  overlay?.addEventListener("click", (e) => {
    if (e.target === overlay) close?.click();
  });

  let currentRepo = "";
  let currentPath = "";

  async function loadTree(repo, path) {
    if (!list) return;
    currentRepo = repo;
    currentPath = path || "";
    list.innerHTML = "<p class='panel-callout'>carregando…</p>";
    if (meta) meta.textContent = `${repo} · /${currentPath}`;
    try {
      const { apiFetch } = await import("./api.js");
      const q = new URLSearchParams({ repo, path: currentPath });
      const res = await apiFetch(`/api/github/tree?${q.toString()}`);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || "falha ao listar");
      const items = data.items || [];
      const up = currentPath
        ? `<button type="button" class="github-tree-item" data-gh-up="1">.. (voltar)</button>`
        : "";
      list.innerHTML =
        up +
        items
          .map((it) => {
            const kind = it.type === "dir" ? "dir" : "file";
            return `<button type="button" class="github-tree-item" data-gh-kind="${kind}" data-gh-path="${escapeText(it.path)}">${kind === "dir" ? "[dir]" : "[file]"} ${escapeText(it.name)}</button>`;
          })
          .join("") || "<p class='panel-callout'>vazio</p>";
    } catch (err) {
      list.innerHTML = `<p class="panel-callout">${escapeText(err.message || "erro")}</p>`;
    }
  }

  async function attachWholeProject(repo) {
    if (!repo) {
      toast?.("Informe owner/repo", "error");
      return;
    }
    if (meta) meta.textContent = `${repo} · anexando projeto…`;
    if (attachBtn) attachBtn.disabled = true;
    try {
      const { apiFetch } = await import("./api.js");
      const q = new URLSearchParams({ repo });
      const res = await apiFetch(`/api/github/project?${q.toString()}`);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || "falha ao anexar projeto");
      attachments = [];
      const mapName = data.map_name || PROJECT_MAP_NAME;
      if (data.map_text) {
        attachments.push({ name: mapName, content: String(data.map_text).slice(0, 200000) });
      }
      const fileNames = [];
      for (const f of data.files || []) {
        if (f?.path && f?.content) {
          attachments.push({
            name: String(f.path).slice(0, 256),
            content: String(f.content).slice(0, 200000),
          });
          fileNames.push(f.path);
        }
      }
      renderAttachmentChips();
      const st = data.stats || {};
      commitFolderIngestToSession({
        folderName: repo,
        totalSeen: st.total_seen ?? fileNames.length,
        keptCount: st.kept ?? st.total_seen ?? fileNames.length,
        ignoredCount: st.ignored ?? 0,
        attached: st.attached ?? fileNames.length,
        files: fileNames,
      });
      toast?.(
        `GitHub: ${st.total_seen ?? "?"} vistos · mapa + ${st.attached ?? 0} arquivos (${st.ignored ?? 0} ignorados)`,
        "info"
      );
      close?.click();
    } catch (err) {
      const msg = err.message || "erro";
      if (meta) meta.textContent = msg;
      toast?.(msg, "error");
    } finally {
      if (attachBtn) attachBtn.disabled = false;
    }
  }

  loadBtn?.addEventListener("click", () => {
    const repo = (input?.value || "").trim();
    if (repo) loadTree(repo, "");
  });
  attachBtn?.addEventListener("click", () => {
    const repo = (input?.value || currentRepo || "").trim();
    attachWholeProject(repo);
  });
  input?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      loadBtn?.click();
    }
  });
  list?.addEventListener("click", async (e) => {
    const btn = e.target.closest(".github-tree-item");
    if (!btn) return;
    if (btn.hasAttribute("data-gh-up")) {
      const parts = currentPath.split("/").filter(Boolean);
      parts.pop();
      loadTree(currentRepo, parts.join("/"));
      return;
    }
    const kind = btn.getAttribute("data-gh-kind");
    const path = btn.getAttribute("data-gh-path") || "";
    if (kind === "dir") {
      loadTree(currentRepo, path);
      return;
    }
    try {
      const { apiFetch } = await import("./api.js");
      const q = new URLSearchParams({ repo: currentRepo, path });
      const res = await apiFetch(`/api/github/file?${q.toString()}`);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || "falha ao ler arquivo");
      addAttachment(data.path || path, data.content || "");
      close?.click();
    } catch (err) {
      if (meta) meta.textContent = err.message || "erro";
    }
  });
}
