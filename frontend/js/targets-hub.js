/**
 * Hub principal do Intel — um alvo por vez, ações claras.
 * Substitui a confusão recon/triage/abas.
 */

import { listRecon, getReconDetail } from "./api/routes.js";
import {
  getEngagementTriage,
  verifyEngagement,
  getEngagementReportUrl,
  patchFindingStatus,
} from "./api/routes.js";
import { deleteReconTarget, deleteEngagement } from "./data-admin.js";
import { attachDeleteAction } from "./row-actions.js";
import { escapeHtml } from "./exec.js";

let ctx = {};
let targets = [];
let selected = "";
let detail = null;
let triage = null;
let loading = false;

export function initTargetsHub(context) {
  ctx = context;
  ctx.hubSearch?.addEventListener("input", () => renderList());
  ctx.hubRefresh?.addEventListener("click", () => loadHub(true));
  ctx.hubVerify?.addEventListener("click", () => runVerify());
  ctx.hubReportMd?.addEventListener("click", () => exportReport("md"));
  ctx.hubReportHtml?.addEventListener("click", () => exportReport("html"));
  ctx.hubReportZip?.addEventListener("click", () => exportReport("zip"));
  ctx.hubFiles?.addEventListener("click", () => {
    if (selected) ctx.onOpenFiles?.(selected);
  });
  ctx.hubChat?.addEventListener("click", () => {
    if (!selected || !ctx.input) return;
    ctx.input.value = `Continue a análise de ${selected} com base nos achados já salvos`;
    ctx.input.focus();
    ctx.onClose?.();
  });
}

function formatDate(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" });
  } catch {
    return iso;
  }
}

function filteredTargets() {
  const q = (ctx.hubSearch?.value || "").trim().toLowerCase();
  if (!q) return targets;
  return targets.filter((t) => t.target.toLowerCase().includes(q));
}

function renderList() {
  const el = ctx.hubListEl;
  if (!el) return;
  const list = filteredTargets();

  if (!list.length) {
    el.innerHTML = targets.length
      ? `<p class="hub-empty">Nenhum alvo com esse nome.</p>`
      : `<div class="hub-empty-box">
           <p class="hub-empty">Nenhum alvo ainda</p>
           <p class="hub-hint">Rode um scan no chat ou no piloto automático. Os resultados aparecem aqui.</p>
         </div>`;
    return;
  }

  el.innerHTML = list
    .map((t) => {
      const n = t.vulnerabilities_count || 0;
      const active = t.target === selected ? " is-active" : "";
      return `
      <button type="button" class="hub-target${active}" data-target="${escapeHtml(t.target)}">
        <span class="hub-target-name">${escapeHtml(t.target)}</span>
        <span class="hub-target-meta">
          <span class="${n ? "hub-badge hub-badge--warn" : "hub-badge"}">${n} achado${n === 1 ? "" : "s"}</span>
          <span class="hub-badge">${t.open_ports_count || 0} porta${(t.open_ports_count || 0) === 1 ? "" : "s"}</span>
        </span>
      </button>`;
    })
    .join("");

  el.querySelectorAll("[data-target]").forEach((btn) => {
    btn.addEventListener("click", () => selectTarget(btn.dataset.target));
  });
}

function setActionsEnabled(on) {
  [ctx.hubVerify, ctx.hubReportMd, ctx.hubReportHtml, ctx.hubReportZip, ctx.hubFiles, ctx.hubChat, ctx.hubDelete].forEach(
    (b) => {
      if (b) b.disabled = !on;
    }
  );
}

function sevClass(sev) {
  const s = (sev || "").toLowerCase();
  if (s === "critical" || s === "high") return "hub-sev--high";
  if (s === "medium") return "hub-sev--med";
  return "hub-sev--low";
}

function renderDetail() {
  const el = ctx.hubDetailEl;
  if (!el) return;

  if (!selected) {
    el.innerHTML = `<div class="hub-empty-box hub-empty-box--detail">
      <p class="hub-empty">Selecione um alvo à esquerda</p>
      <p class="hub-hint">Depois você pode verificar achados e baixar o relatório.</p>
    </div>`;
    setActionsEnabled(false);
    if (ctx.hubMetaEl) ctx.hubMetaEl.textContent = `${targets.length} alvo(s)`;
    return;
  }

  if (loading) {
    el.innerHTML = `<p class="hub-empty">carregando ${escapeHtml(selected)}…</p>`;
    return;
  }

  setActionsEnabled(true);
  const findings = detail?.findings || [];
  const ports = detail?.open_ports || [];
  const tools = detail?.tools_run || [];
  const exec = triage?.executive || [];
  const human = triage?.human_queue || [];
  const risk = triage?.risk || {};
  const allFindings =
    findings.length > 0
      ? findings
      : [...exec, ...human].map((f) => f);

  if (ctx.hubMetaEl) {
    ctx.hubMetaEl.textContent = `${selected} · ${allFindings.length} achado(s)`;
  }

  const findingsHtml = allFindings.length
    ? allFindings
        .slice(0, 50)
        .map((f) => {
          const id = f.id || "";
          const sev = f.severity || "info";
          const status = f.status || "candidate";
          return `<li class="hub-finding" data-fid="${escapeHtml(id)}">
            <span class="hub-sev ${sevClass(sev)}">${escapeHtml(sev)}</span>
            <div class="hub-finding-body">
              <strong>${escapeHtml(f.title || "—")}</strong>
              <span class="hub-finding-sub">${escapeHtml(status)}${f.tool ? ` · ${escapeHtml(f.tool)}` : ""}</span>
            </div>
            ${
              id
                ? `<div class="hub-finding-actions">
                    <button type="button" class="hub-mini" data-faction="confirmed" data-id="${escapeHtml(id)}" title="Confirmar no relatório">ok</button>
                    <button type="button" class="hub-mini hub-mini--mute" data-faction="false_positive" data-id="${escapeHtml(id)}" title="Falso positivo">fp</button>
                  </div>`
                : ""
            }
          </li>`;
        })
        .join("")
    : `<p class="hub-hint">Nenhum achado estruturado ainda. Rode scan com nmap/nikto/nuclei neste alvo.</p>`;

  el.innerHTML = `
    <header class="hub-detail-head">
      <div>
        <h3 class="hub-detail-title">${escapeHtml(selected)}</h3>
        <p class="hub-detail-sub">
          atualizado ${formatDate(detail?.updated_at)}
          ${detail?.commands_run ? ` · ${detail.commands_run} comandos` : ""}
          ${tools.length ? ` · ${escapeHtml(tools.slice(-5).join(", "))}` : ""}
        </p>
      </div>
      <div class="hub-risk">
        risco <b>${escapeHtml(String(risk.score ?? "—"))}</b>
        <span>${escapeHtml(risk.label || "")}</span>
      </div>
    </header>

    <div class="hub-steps">
      <span class="hub-step"><b>1</b> Verifique</span>
      <span class="hub-step"><b>2</b> Marque ok / fp</span>
      <span class="hub-step"><b>3</b> Baixe o relatório</span>
    </div>

    ${
      allFindings.length && exec.length === 0
        ? `<p class="hub-callout">Há achados, mas ainda não entram no relatório executivo. Clique em <strong>Verificar</strong> ou marque <strong>ok</strong> nos itens.</p>`
        : ""
    }

    <section class="hub-section">
      <h4>Achados <em>${allFindings.length}</em>
        ${exec.length ? `<span class="hub-pill hub-pill--ok">${exec.length} no relatório</span>` : ""}
        ${human.length ? `<span class="hub-pill hub-pill--warn">${human.length} revisar</span>` : ""}
      </h4>
      <ul class="hub-findings">${findingsHtml}</ul>
    </section>

    ${
      ports.length
        ? `<section class="hub-section">
            <h4>Portas <em>${ports.length}</em></h4>
            <ul class="hub-ports">${ports
              .slice(0, 20)
              .map((p) => `<li>${escapeHtml(typeof p === "string" ? p : JSON.stringify(p))}</li>`)
              .join("")}</ul>
          </section>`
        : ""
    }
  `;

  el.querySelectorAll("[data-faction]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const status = btn.getAttribute("data-faction");
      const fid = btn.getAttribute("data-id");
      try {
        await patchFindingStatus(selected, fid, { status, evidence: `manual:${status}` });
        ctx.toast?.(`marcado como ${status === "confirmed" ? "ok" : "fp"}`, "success");
        await selectTarget(selected, true);
      } catch (e) {
        ctx.toast?.(e.message || "falha", "error");
      }
    });
  });

  // bind delete once per selection
  if (ctx.hubDelete) {
    const fresh = ctx.hubDelete.cloneNode(true);
    ctx.hubDelete.replaceWith(fresh);
    ctx.hubDelete = fresh;
    ctx.hubDelete.disabled = false;
    attachDeleteAction(ctx.hubDelete, {
      label: selected,
      toast: ctx.toast,
      removeOnSuccess: false,
      onDelete: async () => {
        await deleteReconTarget(selected).catch(() => {});
        await deleteEngagement(selected).catch(() => {});
        selected = "";
        detail = null;
        triage = null;
        ctx.onDeleted?.();
        await loadHub(true);
      },
    });
  }
}

async function selectTarget(target, force = false) {
  if (!target) return;
  if (!force && selected === target && detail) {
    renderList();
    return;
  }
  selected = target;
  loading = true;
  renderList();
  renderDetail();
  try {
    const [reconRes, triageRes] = await Promise.all([
      getReconDetail(target),
      getEngagementTriage(target).catch(() => null),
    ]);
    detail = reconRes.ok ? await reconRes.json() : { target, findings: [], open_ports: [] };
    if (triageRes?.ok) {
      triage = await triageRes.json();
    } else {
      triage = { executive: [], human_queue: [], risk: {}, summary: {} };
    }
  } catch (e) {
    detail = { target, findings: [], open_ports: [] };
    triage = null;
    ctx.toast?.(e.message || "erro ao carregar", "error");
  }
  loading = false;
  renderList();
  renderDetail();
}

async function runVerify() {
  if (!selected) return;
  ctx.toast?.("Verificando achados…", "info");
  try {
    const res = await verifyEngagement(selected);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.detail || "Falha na verificação");
    ctx.toast?.(
      `Pronto: ${body.confirmed || 0} confirmado(s) · ${body.false_positive || 0} FP`,
      "success",
      4500
    );
    await selectTarget(selected, true);
  } catch (e) {
    ctx.toast?.(e.message || "Falha na verificação", "error");
  }
}

function exportReport(fmt) {
  if (!selected) {
    ctx.toast?.("Selecione um alvo primeiro", "warn");
    return;
  }
  window.open(getEngagementReportUrl(selected, fmt), "_blank", "noopener");
}

export async function loadHub(force = false) {
  if (!force && targets.length) {
    renderList();
    renderDetail();
    return;
  }
  if (ctx.hubListEl) ctx.hubListEl.innerHTML = `<p class="hub-empty">carregando…</p>`;
  try {
    const res = await listRecon();
    if (!res.ok) throw new Error("Falha ao listar alvos");
    targets = (await res.json()).targets || [];
    if (selected && !targets.some((t) => t.target === selected)) {
      selected = "";
      detail = null;
      triage = null;
    }
    if (!selected && targets[0]) {
      await selectTarget(targets[0].target);
    } else {
      renderList();
      if (selected) await selectTarget(selected, true);
      else renderDetail();
    }
  } catch (e) {
    if (ctx.hubListEl) {
      ctx.hubListEl.innerHTML = `<p class="hub-empty">${escapeHtml(e.message)}</p>`;
    }
  }
}

export function openTargetInHub(target) {
  if (target) selectTarget(target);
}
