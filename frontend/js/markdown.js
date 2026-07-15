/** Renderização segura de Markdown (subset) para respostas da IA. */

import { escapeHtml } from "./exec.js";

const SAFE_URL = /^https?:\/\/[^\s<>"']+$/i;

function inlineMarkdown(text) {
  let s = escapeHtml(text);
  s = s.replace(/`([^`\n]+)`/g, "<code>$1</code>");
  s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  s = s.replace(/\*([^*\n]+)\*/g, "<em>$1</em>");
  s = s.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, label, url) => {
    const u = url.trim();
    if (!SAFE_URL.test(u)) return label;
    return `<a href="${escapeHtml(u)}" target="_blank" rel="noopener noreferrer">${label}</a>`;
  });
  return s;
}

function flushParagraph(lines, out) {
  const text = lines.join(" ").trim();
  if (text) out.push(`<p>${inlineMarkdown(text)}</p>`);
  lines.length = 0;
}

function flushList(items, tag, out) {
  if (!items.length) return;
  out.push(`<${tag}>` + items.map((i) => `<li>${inlineMarkdown(i)}</li>`).join("") + `</${tag}>`);
  items.length = 0;
}

/**
 * Converte Markdown básico em HTML sanitizado (sem tags arbitrárias).
 * Suporta: parágrafos, #–###, listas, **negrito**, *itálico*, `code`, ```blocos```, links http(s).
 */
export function renderMarkdown(source) {
  if (!source) return "";

  const parts = String(source).split(/(```[\s\S]*?```)/g);
  const out = [];

  for (const part of parts) {
    if (part.startsWith("```") && part.endsWith("```")) {
      const inner = part.slice(3, -3);
      const nl = inner.indexOf("\n");
      const code = (nl >= 0 ? inner.slice(nl + 1) : inner).replace(/^\n|\n$/g, "");
      out.push(`<pre class="md-pre"><code>${escapeHtml(code)}</code></pre>`);
      continue;
    }

    const lines = part.replace(/\r\n/g, "\n").split("\n");
    const paraBuf = [];
    const ulBuf = [];
    const olBuf = [];

    for (const raw of lines) {
      const line = raw.trimEnd();
      const trimmed = line.trim();

      if (!trimmed) {
        flushParagraph(paraBuf, out);
        flushList(ulBuf, "ul", out);
        flushList(olBuf, "ol", out);
        continue;
      }

      const h = trimmed.match(/^(#{1,3})\s+(.+)$/);
      if (h) {
        flushParagraph(paraBuf, out);
        flushList(ulBuf, "ul", out);
        flushList(olBuf, "ol", out);
        const level = h[1].length;
        out.push(`<h${level} class="md-h${level}">${inlineMarkdown(h[2])}</h${level}>`);
        continue;
      }

      const ul = trimmed.match(/^[-*]\s+(.+)$/);
      if (ul) {
        flushParagraph(paraBuf, out);
        flushList(olBuf, "ol", out);
        ulBuf.push(ul[1]);
        continue;
      }

      const ol = trimmed.match(/^\d+\.\s+(.+)$/);
      if (ol) {
        flushParagraph(paraBuf, out);
        flushList(ulBuf, "ul", out);
        olBuf.push(ol[1]);
        continue;
      }

      flushList(ulBuf, "ul", out);
      flushList(olBuf, "ol", out);
      paraBuf.push(trimmed);
    }

    flushParagraph(paraBuf, out);
    flushList(ulBuf, "ul", out);
    flushList(olBuf, "ol", out);
  }

  return out.join("");
}
