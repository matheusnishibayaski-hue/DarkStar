/** Renderização do terminal de chat. */

import { escapeHtml, buildExecBlock } from "./exec.js";
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
      chatEl.appendChild(line("prompt-line", `<span class="cmd">${escapeHtml(msg.content)}</span>`));
    } else {
      chatEl.appendChild(line("assistant", escapeHtml(msg.content)));
      for (const t of msg.toolExecutions || []) {
        chatEl.appendChild(buildExecBlock(t));
      }
    }
  }
  scrollChatToBottom(false);
}

export function appendUserLine(text) {
  ctx.chatEl?.appendChild(line("prompt-line", `<span class="cmd">${escapeHtml(text)}</span>`));
  scrollChatToBottom();
}

export function appendAssistantLine(content) {
  ctx.chatEl?.appendChild(line("assistant", escapeHtml(content)));
  scrollChatToBottom();
}

export function appendLine(className, content) {
  ctx.chatEl?.appendChild(line(className, escapeHtml(content)));
  scrollChatToBottom();
}

export function showTyping(label = "processando") {
  hideTyping();
  const el = line("typing-line dim", label);
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
