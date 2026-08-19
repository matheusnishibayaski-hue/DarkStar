/** Renderização do terminal de chat. */

import { escapeHtml, buildExecBlock } from "./exec.js";
import { renderMarkdown } from "./markdown.js";
import { getActiveSession } from "./sessions.js";
import { renderWelcome } from "./ui.js";
import { getRun } from "./session-runs.js";
import { restoreLiveBlocks } from "./stream.js";

let ctx = {};

export function initChatView(context) {
  ctx = context;
}

function line(className, html) {
  const el = document.createElement("div");
  el.className = `term-line ${className || ""}`.trim();
  el.innerHTML = html;
  return el;
}

function userMessage(text) {
  const block = document.createElement("div");
  block.className = "cmd-line cmd-line--user";
  block.innerHTML = `<span class="cmd-echo">${escapeHtml(text)}</span>`;
  return block;
}

function assistantMessage(content) {
  const block = document.createElement("div");
  block.className = "cmd-line cmd-line--out";
  const body = document.createElement("span");
  body.className = "md-body";
  body.innerHTML = renderMarkdown(content);
  block.appendChild(body);
  return block;
}

function isNearBottom() {
  const { chatEl } = ctx;
  if (!chatEl) return true;
  return chatEl.scrollHeight - chatEl.scrollTop - chatEl.clientHeight < 80;
}

export function scrollChatToBottom(smooth = true, force = false) {
  const { chatEl, btnScrollBottom } = ctx;
  if (!chatEl) return;
  if (!force && !isNearBottom()) {
    onChatScroll();
    return;
  }
  chatEl.scrollTo({ top: chatEl.scrollHeight, behavior: smooth ? "smooth" : "auto" });
  if (btnScrollBottom) btnScrollBottom.hidden = true;
}

export function onChatScroll() {
  const { chatEl, btnScrollBottom } = ctx;
  if (!chatEl || !btnScrollBottom) return;
  const nearBottom = chatEl.scrollHeight - chatEl.scrollTop - chatEl.clientHeight < 80;
  btnScrollBottom.hidden = nearBottom || chatEl.scrollHeight <= chatEl.clientHeight;
}

export function renderChat() {
  const { chatEl } = ctx;
  if (!chatEl) return;

  const session = getActiveSession();
  chatEl.innerHTML = "";

  if (!session || session.messages.length === 0) {
    chatEl.appendChild(renderWelcome());
    scrollChatToBottom(false, true);
    return;
  }

  for (const msg of session.messages) {
    if (msg.kind === "pending-attachments") continue;
    if (msg.kind === "folder-ingest") {
      appendFolderIngestResult(msg.folderSummary || { folderName: msg.content });
      continue;
    }
    if (msg.role === "user") {
      chatEl.appendChild(userMessage(msg.display || msg.content));
    } else if (msg.role === "system") {
      continue;
    } else {
      chatEl.appendChild(assistantMessage(msg.content));
      for (const t of msg.toolExecutions || []) {
        chatEl.appendChild(buildExecBlock(t));
      }
    }
  }
  const run = getRun(session.id);
  if (run) {
    restoreLiveBlocks(chatEl, session.id, scrollChatToBottom);
    if (run.typing) showTyping(run.typing);
  }
  scrollChatToBottom(false, true);
}

export function appendUserLine(text) {
  ctx.chatEl?.appendChild(userMessage(text));
  scrollChatToBottom(true, true);
}

export function appendAssistantLine(content) {
  ctx.chatEl?.appendChild(assistantMessage(content));
  scrollChatToBottom();
}

export function appendLine(className, content) {
  ctx.chatEl?.appendChild(line(className, escapeHtml(content)));
  scrollChatToBottom();
}

export function showTyping(label = "processando") {
  hideTyping();
  const el = line("typing-line dim", `<span class="cmd-prompt-inline"><span class="argus-avatar" style="display:inline-block;vertical-align:middle;margin-right:0.35rem"></span><span class="cmd-user" style="color:var(--argus)">Argus</span></span> <span class="typing-dots">${escapeHtml(label)}</span>`);
  el.id = "typing";
  ctx.chatEl?.appendChild(el);
  scrollChatToBottom();
  ctx.updateStatusBar?.();
}

export function hideTyping() {
  document.getElementById("typing")?.remove();
  ctx.updateStatusBar?.();
}

function dismissWelcomeIfEmpty() {
  const chatEl = ctx.chatEl;
  if (!chatEl) return;
  const welcome = chatEl.querySelector(".welcome");
  if (welcome && chatEl.children.length === 1) welcome.remove();
}

/** Card de progresso ao anexar pasta (drop / seletor). */
export function showFolderIngestProgress(label = "Lendo pasta…") {
  dismissWelcomeIfEmpty();
  hideFolderIngestProgress();
  const el = document.createElement("div");
  el.id = "folder-ingest-progress";
  el.className = "cmd-line folder-ingest-card folder-ingest-card--loading";
  el.setAttribute("role", "status");
  el.innerHTML =
    `<div class="folder-ingest-head">` +
    `<span class="folder-ingest-spinner" aria-hidden="true"></span>` +
    `<strong>Pasta</strong>` +
    `</div>` +
    `<p class="folder-ingest-status">${escapeHtml(label)}</p>`;
  ctx.chatEl?.appendChild(el);
  scrollChatToBottom(true, true);
}

export function updateFolderIngestProgress(label) {
  const el = document.getElementById("folder-ingest-progress");
  const status = el?.querySelector(".folder-ingest-status");
  if (status) status.textContent = label;
  scrollChatToBottom(false, true);
}

export function hideFolderIngestProgress() {
  document.getElementById("folder-ingest-progress")?.remove();
}

export function appendFolderIngestResult(summary) {
  hideFolderIngestProgress();
  dismissWelcomeIfEmpty();
  const el = document.createElement("div");
  el.className = "cmd-line folder-ingest-card";
  el.setAttribute("role", "status");

  if (summary?.error) {
    el.classList.add("folder-ingest-card--error");
    el.innerHTML =
      `<div class="folder-ingest-head"><strong>Pasta</strong></div>` +
      `<p class="folder-ingest-status">${escapeHtml(summary.error)}</p>`;
    ctx.chatEl?.appendChild(el);
    scrollChatToBottom(true, true);
    return;
  }

  const name = summary.folderName || "projeto";
  const files = summary.files || [];
  const fileList =
    files.length === 0
      ? "<li class='dim'>Nenhum arquivo de conteúdo anexado (só o mapa).</li>"
      : files
          .map((f) => `<li><code>${escapeHtml(f)}</code></li>`)
          .join("");

  el.innerHTML =
    `<div class="folder-ingest-head"><strong>Pasta anexada</strong> · ${escapeHtml(name)}</div>` +
    `<ul class="folder-ingest-stats">` +
    `<li><span>Itens vistos</span><b>${escapeHtml(String(summary.totalSeen ?? 0))}</b></li>` +
    `<li><span>No mapa</span><b>${escapeHtml(String(summary.keptCount ?? 0))}</b></li>` +
    `<li><span>Ignorados</span><b>${escapeHtml(String(summary.ignoredCount ?? 0))}</b></li>` +
    `<li><span>Lidos (conteúdo)</span><b>${escapeHtml(String(summary.attached ?? 0))}</b></li>` +
    `</ul>` +
    `<p class="folder-ingest-label">Arquivos com conteúdo anexado</p>` +
    `<ul class="folder-ingest-files">${fileList}</ul>` +
    `<p class="folder-ingest-hint">O mapa completo da pasta também foi anexado — envie uma mensagem para a Argus analisar.</p>`;

  ctx.chatEl?.appendChild(el);
  scrollChatToBottom(true, true);
}

export function showAutopilotProgress(text) {
  showTyping(text);
}

export { line };
