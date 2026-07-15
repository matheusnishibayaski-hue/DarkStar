/** Renderização do terminal de chat. */

import { escapeHtml, buildExecBlock } from "./exec.js";
import { renderMarkdown } from "./markdown.js";
import { getActiveSession } from "./sessions.js";
import { renderWelcome } from "./ui.js";

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
  block.innerHTML = `<span class="cmd-prompt-inline"><span class="cmd-user">kali@pentest</span><span class="cmd-at">:</span><span class="cmd-path">~</span><span class="cmd-sym">$</span></span> <span class="cmd-echo">${escapeHtml(text)}</span>`;
  return block;
}

function assistantMessage(content) {
  const block = document.createElement("div");
  block.className = "cmd-line cmd-line--out";
  const prefix = document.createElement("span");
  prefix.className = "out-prefix";
  prefix.textContent = "# ";
  const body = document.createElement("span");
  body.className = "md-body";
  body.innerHTML = renderMarkdown(content);
  block.appendChild(prefix);
  block.appendChild(body);
  return block;
}

export function scrollChatToBottom(smooth = true) {
  const { chatEl, btnScrollBottom } = ctx;
  chatEl?.scrollTo({ top: chatEl.scrollHeight, behavior: smooth ? "smooth" : "auto" });
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
    scrollChatToBottom(false);
    return;
  }

  for (const msg of session.messages) {
    if (msg.role === "user") {
      chatEl.appendChild(userMessage(msg.content));
    } else {
      chatEl.appendChild(assistantMessage(msg.content));
      for (const t of msg.toolExecutions || []) {
        chatEl.appendChild(buildExecBlock(t));
      }
    }
  }
  scrollChatToBottom(false);
}

export function appendUserLine(text) {
  ctx.chatEl?.appendChild(userMessage(text));
  scrollChatToBottom();
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
  const el = line("typing-line dim", `<span class="cmd-prompt-inline"><span class="cmd-user">kali@pentest</span><span class="cmd-at">:</span><span class="cmd-path">~</span><span class="cmd-sym">$</span></span> <span class="typing-dots">${escapeHtml(label)}</span>`);
  el.id = "typing";
  ctx.chatEl?.appendChild(el);
  scrollChatToBottom();
  ctx.updateStatusBar?.();
}

export function hideTyping() {
  document.getElementById("typing")?.remove();
  ctx.updateStatusBar?.();
}

export function showAutopilotProgress(text) {
  showTyping(text);
}

export { line };
