/** Painel de triagem — Attack Surface / findings assertivos. */

import { openOverlay, closeOverlay, toast } from "./ui.js";
import { escapeHtml } from "./exec.js";
import { deleteEngagement } from "./data-admin.js";
import { attachDeleteAction } from "./row-actions.js";
import {
  listSurface,
  getEngagementTriage,
  patchFindingStatus,
  verifyEngagement,
  getEngagementReportUrl,
  patchEngagement,
} from "./api/routes.js";

let ctx = {};
let currentTarget = "";

export function initTriagePanel(context) {
  ctx = context;
  ctx.triageRefresh?.addEventListener("click", () => loadTriageTab());
  ctx.triageVerify?.addEventListener("click", () => runVerify());
  ctx.triageExportMd?.addEventListener("click", () => exportReport("md"));
  ctx.triageExportHtml?.addEventListener("click", () => exportReport("html"));
  ctx.triageExportZip?.addEventListener("click", () => exportReport("zip"));
  ctx.triageTargetSelect?.addEventListener("change", () => {
    currentTarget = ctx.triageTargetSelect.value || "";
    if (currentTarget) loadTriageDetail(currentTarget);
  });
  if (ctx.triageDelete) {
    attachDeleteAction(ctx.triageDelete, {
      label: "engajamento",
      toast,
      onDelete: async () => {
        if (!currentTarget) throw new Error("selecione um alvo");
        await deleteEngagement(currentTarget);
        currentTarget = "";
        ctx.onEngagementDeleted?.();
        await loadTriageTab();
      },
    });
  }
}

export async function loadTriageTab() {
  const wrap = ctx.triageBodyEl;
  const meta = ctx.triageMetaEl;
  if (!wrap) return;
  wrap.innerHTML = `<p class="recon-empty">carregando surface…</p>`;
  try {
    const res = await listSurface();
    if (!res.ok) throw new Error("Falha ao listar surface");
    const data = await res.json();
    const targets = data.targets || [];
    if (meta) meta.textContent = `${targets.length} alvo(s)`;

    if (ctx.triageTargetSelect) {
      const prev = currentTarget;
      ctx.triageTargetSelect.innerHTML =
        `<option value="">— alvo —</option>` +
        targets
          .map(
            (t) =>
              `<option value="${escapeHtml(t.target)}">${escapeHtml(t.target)} · C${t.findings_confirmed || 0}/H${(t.findings_candidates || 0) + (t.findings_inconclusive || 0)}</option>`
          )
          .join("");
      if (prev && targets.some((t) => t.target === prev)) {
        ctx.triageTargetSelect.value = prev;
        currentTarget = prev;
      } else if (targets[0]) {
        ctx.triageTargetSelect.value = targets[0].target;
        currentTarget = targets[0].target;
      } else {
        currentTarget = "";
      }
    }

    if (!currentTarget) {
      wrap.innerHTML = `<div class="recon-empty-state">
        <p class="recon-empty">Nenhum alvo com Attack Surface.</p>
        <p class="recon-hint">Rode o chat/Auto-Pilot em um alvo autorizado. Achados de nmap (HttpOnly), nikto e nuclei aparecem aqui para verificar e gerar o relatório.</p>
      </div>`;
      return;
    }
    await loadTriageDetail(currentTarget);
  } catch (e) {
    wrap.innerHTML = `<p class="recon-card-error">${escapeHtml(e.message || "erro")}</p>`;
  }
}

async function loadTriageDetail(target) {
  const wrap = ctx.triageBodyEl;
  if (!wrap) return;
  wrap.innerHTML = `<p class="recon-empty">triagem ${escapeHtml(target)}…</p>`;
  try {
    const res = await getEngagementTriage(target);
    if (!res.ok) throw new Error("Falha ao carregar triagem");
    const data = await res.json();
    const sum = data.summary || {};
    const exec = data.executive || [];
    const human = data.human_queue || [];
    const archive = data.archive || [];
    const risk = data.risk || {};
    const chains = data.chains || [];

    const candidates = (sum.findings_candidates || 0) + (sum.findings_inconclusive || 0);
    const total = sum.findings_total || exec.length + human.length + archive.length;
    wrap.innerHTML = `
      <div class="triage-summary">
        <span class="triage-risk">risco:<b>${escapeHtml(String(risk.score ?? "—"))}/100 ${escapeHtml(risk.label || "")}</b></span>
        <span>fase:<b>${escapeHtml(sum.phase || "?")}</b></span>
        <span>achados:<b>${total}</b></span>
        <span class="triage-ok">no relatório:<b>${exec.length}</b></span>
        <span class="triage-warn">revisar:<b>${human.length || candidates}</b></span>
      </div>
      ${
        total > 0 && exec.length === 0
          ? `<p class="recon-hint recon-hint--warn">Há ${total} achado(s) candidato(s). Clique em <strong>verificar</strong> para validar e depois exporte o relatório.</p>`
          : ""
      }
      ${
        chains.length
          ? `<div class="triage-chains">${chains
              .slice(0, 4)
              .map(
                (c) =>
                  `<span class="triage-chain">⛓ ${escapeHtml(c.title || "")}</span>`
              )
              .join("")}</div>`
          : ""
      }
      <div class="triage-client-row">
        <input type="text" class="panel-field triage-client-input" id="triage-client"
          placeholder="cliente / empresa" value="" spellcheck="false" />
        <button type="button" class="intel-refresh-btn" id="triage-save-client">salvar engajamento</button>
      </div>
      ${section("Confirmados (executivo)", exec, "confirmed", true)}
      ${section("Fila humana (revisar)", human, "human", true)}
      ${section("Arquivo (FP / descartados)", archive, "archive", false)}
    `;

    wrap.querySelector("#triage-save-client")?.addEventListener("click", async () => {
      const client = wrap.querySelector("#triage-client")?.value?.trim() || "";
      try {
        await patchEngagement(target, { client });
        toast("engajamento atualizado", "success");
      } catch (e) {
        toast(e.message || "falha ao salvar", "error");
      }
    });

    wrap.querySelectorAll("[data-action]").forEach((btn) => {
      btn.addEventListener("click", () => onFindingAction(btn));
    });
  } catch (e) {
    wrap.innerHTML = `<p class="recon-card-error">${escapeHtml(e.message || "erro")}</p>`;
  }
}

function section(title, items, kind, showActions) {
  if (!items.length) {
    return `<div class="triage-section"><h4 class="triage-h">${escapeHtml(title)}</h4><p class="recon-empty">— vazio —</p></div>`;
  }
  const rows = items
    .slice(0, 40)
    .map((f) => {
      const id = escapeHtml(f.id || "");
      const actions = showActions
        ? `<div class="triage-actions">
            <button type="button" data-action="confirmed" data-id="${id}">✓</button>
            <button type="button" data-action="false_positive" data-id="${id}">FP</button>
            <button type="button" data-action="discarded" data-id="${id}">✕</button>
          </div>`
        : `<span class="triage-st">${escapeHtml(f.status || "")}</span>`;
      return `<div class="triage-row triage-row--${escapeHtml(kind)}">
        <span class="triage-sev triage-sev--${escapeHtml(String(f.severity || "info").toLowerCase())}">${escapeHtml(String(f.severity || "?").toUpperCase())}</span>
        <span class="triage-title" title="${escapeHtml(f.title || "")}">${escapeHtml(f.title || "")}</span>
        <span class="triage-conf">${escapeHtml(f.confidence || "—")}</span>
        ${actions}
      </div>`;
    })
    .join("");
  return `<div class="triage-section"><h4 class="triage-h">${escapeHtml(title)} <em>${items.length}</em></h4>${rows}</div>`;
}

async function onFindingAction(btn) {
  const status = btn.getAttribute("data-action");
  const fid = btn.getAttribute("data-id");
  if (!currentTarget || !fid || !status) return;
  try {
    await patchFindingStatus(currentTarget, fid, { status, evidence: `manual:${status}` });
    toast(`finding → ${status}`, "success");
    await loadTriageDetail(currentTarget);
  } catch (e) {
    toast(e.message || "falha", "error");
  }
}

async function runVerify() {
  if (!currentTarget) {
    toast("selecione um alvo", "warn");
    return;
  }
  toast("pipeline PoC…", "info");
  try {
    const res = await verifyEngagement(currentTarget);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.detail || "verify falhou");
    toast(
      `verify: ${body.confirmed || 0} OK · ${body.false_positive || 0} FP · ${body.discarded || 0} descart.`,
      "success",
      5000
    );
    await loadTriageDetail(currentTarget);
  } catch (e) {
    toast(e.message || "verify falhou", "error");
  }
}

function exportReport(fmt) {
  if (!currentTarget) {
    toast("selecione um alvo", "warn");
    return;
  }
  const url = getEngagementReportUrl(currentTarget, fmt);
  window.open(url, "_blank", "noopener");
}

export function openTriageFromIntel() {
  if (ctx.overlayIntel) openOverlay(ctx.overlayIntel);
}
