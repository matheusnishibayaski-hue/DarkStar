/** Alvos — vision unificada: portas + achados do Attack Surface + ações. */

import { listRecon, getReconDetail } from "./api/routes.js";
import { deleteReconTarget, deleteEngagement } from "./data-admin.js";
import { attachDeleteAction } from "./row-actions.js";
import { escapeHtml } from "./exec.js";

let ctx = {};
let cachedList = null;
let detailCache = new Map();
let expandedTarget = null;
let searchQuery = "";
let sortBy = "date";

export function initReconIntel(context) {
  ctx = context;
  ctx.reconSearch?.addEventListener("input", () => {
    searchQuery = ctx.reconSearch.value.trim();
    if (cachedList) renderTable(cachedList);
  });
  ctx.reconSort?.addEventListener("change", () => {
    sortBy = ctx.reconSort.value || "date";
    if (cachedList) renderTable(cachedList);
  });
  ctx.reconRefresh?.addEventListener("click", () => loadReconTab(true));
}

function formatDate(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" });
  } catch {
    return iso;
  }
}

function filterAndSort(targets) {
  let list = [...targets];
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    list = list.filter((t) => t.target.toLowerCase().includes(q));
  }
  list.sort((a, b) => {
    if (sortBy === "target") return a.target.localeCompare(b.target);
    if (sortBy === "ports") return (b.open_ports_count || 0) - (a.open_ports_count || 0);
    if (sortBy === "cves") return (b.cves_count || 0) - (a.cves_count || 0);
    if (sortBy === "vulns") return (b.vulnerabilities_count || 0) - (a.vulnerabilities_count || 0);
    return String(b.updated_at || "").localeCompare(String(a.updated_at || ""));
  });
  return list;
}

function sevClass(sev) {
  const s = (sev || "").toLowerCase();
  if (s === "critical" || s === "high") return "finding-sev--high";
  if (s === "medium") return "finding-sev--med";
  return "finding-sev--low";
}

function renderFindingsList(findings) {
  if (!findings?.length) return "";
  return `
    <section class="recon-card-section recon-card-section--full">
      <h4>achados <span class="recon-count">${findings.length}</span></h4>
      <ul class="recon-findings-list">
        ${findings
          .slice(0, 40)
          .map((f) => {
            const sev = f.severity || "info";
            const status = f.status || "candidate";
            return `<li class="recon-finding-item">
              <span class="finding-sev ${sevClass(sev)}">${escapeHtml(sev)}</span>
              <span class="finding-title">${escapeHtml(f.title || "")}</span>
              <span class="finding-status">${escapeHtml(status)}</span>
              ${f.tool ? `<span class="finding-tool">${escapeHtml(f.tool)}</span>` : ""}
            </li>`;
          })
          .join("")}
      </ul>
      ${findings.length > 40 ? `<p class="recon-more">+${findings.length - 40} …</p>` : ""}
    </section>`;
}

function renderExpandCard(target, data, loading, error) {
  if (loading) return '<p class="recon-card-loading">carregando…</p>';
  if (error) return `<p class="recon-card-error">${escapeHtml(error)}</p>`;
  if (!data) return "";

  const ports = data.open_ports || [];
  const findings = data.findings || [];
  const vulnsText = data.vulnerabilities || [];
  const tools = data.tools_run || [];
  const summary = data.findings_summary || {};
  const totalFindings = summary.total ?? findings.length ?? vulnsText.length;

  return `
    <div class="recon-card-inner">
      <div class="recon-card-head">
        <span class="recon-card-file">${escapeHtml(target)}</span>
        <span class="recon-card-meta">
          atualizado ${formatDate(data.updated_at)}
          ${data.commands_run ? ` · ${data.commands_run} cmd(s)` : ""}
          ${tools.length ? ` · ${escapeHtml(tools.slice(-4).join(", "))}` : ""}
        </span>
      </div>

      <div class="recon-stat-pills">
        <span class="recon-pill">portas <b>${ports.length}</b></span>
        <span class="recon-pill recon-pill--warn">achados <b>${totalFindings}</b></span>
        <span class="recon-pill recon-pill--ok">confirmados <b>${summary.confirmed || 0}</b></span>
        <span class="recon-pill">candidatos <b>${summary.candidates || 0}</b></span>
      </div>

      ${
        totalFindings === 0 && (data.commands_run || 0) > 0
          ? `<p class="recon-hint recon-hint--warn">
              ${data.commands_run} comando(s) rodaram, mas nenhum achado estruturado foi gravado.
              Use <em>triagem → verify</em> ou rode nuclei/nikto de novo — o parser agora extrai cookies, banners e paths.
            </p>`
          : ""
      }

      <div class="recon-card-grid">
        ${
          ports.length
            ? `<section class="recon-card-section">
                <h4>portas</h4>
                <ul class="recon-tags">${ports
                  .slice(0, 24)
                  .map((p) => `<li>${escapeHtml(typeof p === "string" ? p : JSON.stringify(p))}</li>`)
                  .join("")}</ul>
              </section>`
            : ""
        }
        ${renderFindingsList(findings)}
        ${
          !findings.length && vulnsText.length
            ? `<section class="recon-card-section recon-card-section--full">
                <h4>achados (texto)</h4>
                <ul class="recon-findings">${vulnsText
                  .slice(0, 30)
                  .map((v) => `<li>${escapeHtml(v)}</li>`)
                  .join("")}</ul>
              </section>`
            : ""
        }
        ${
          !ports.length && !findings.length && !vulnsText.length
            ? '<p class="recon-empty">Sem dados estruturados para este alvo.</p>'
            : ""
        }
      </div>

      <div class="recon-card-actions">
        <button type="button" class="recon-action-btn recon-action-btn--primary" data-action="triage" data-target="${escapeHtml(target)}">ver triagem / relatório</button>
        <button type="button" class="recon-action-btn" data-action="prompt" data-target="${escapeHtml(target)}">usar no chat</button>
        <button type="button" class="recon-action-btn recon-action-btn--scan" data-action="scan" data-target="${escapeHtml(target)}">re-scan</button>
        <button type="button" class="recon-action-btn recon-action-btn--files" data-action="files" data-target="${escapeHtml(target)}">artefatos</button>
        <button type="button" class="recon-action-btn recon-action-btn--danger" data-delete-recon data-target="${escapeHtml(target)}">excluir</button>
      </div>
    </div>
  `;
}

function bindCardActions(container) {
  container.querySelectorAll("[data-action]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const target = btn.dataset.target;
      const action = btn.dataset.action;
      if (!target) return;
      if (action === "triage") {
        ctx.onOpenTriage?.(target);
        return;
      }
      if (action === "files") {
        ctx.onOpenFiles?.(target);
        return;
      }
      if (!ctx.input) return;
      if (action === "prompt") {
        ctx.input.value = `Continue a análise de ${target} com base nos achados já salvos`;
      } else if (action === "scan") {
        ctx.input.value = `Atualize o recon de ${target}: portas, headers, diretórios e vulnerabilidades (nuclei -jsonl se possível)`;
      }
      ctx.input.focus();
      ctx.onClose?.();
    });
  });
  container.querySelectorAll("[data-delete-recon]").forEach((btn) => {
    const target = btn.dataset.target;
    if (!target) return;
    attachDeleteAction(btn, {
      label: `alvo ${target}`,
      toast: ctx.toast,
      onDelete: async () => {
        await deleteReconTarget(target).catch(() => {});
        await deleteEngagement(target).catch(() => {});
        detailCache.delete(target);
        if (expandedTarget === target) expandedTarget = null;
        cachedList = (cachedList || []).filter((t) => t.target !== target);
        ctx.onReconDeleted?.();
        renderTable(cachedList || []);
      },
    });
  });
}

function renderTable(targets) {
  const { reconTableEl, reconMetaEl } = ctx;
  if (!reconTableEl) return;

  const filtered = filterAndSort(targets);
  if (reconMetaEl) {
    const withFindings = filtered.filter((t) => (t.vulnerabilities_count || 0) > 0).length;
    reconMetaEl.textContent = `${filtered.length} alvo(s) · ${withFindings} com achados`;
  }

  if (!filtered.length) {
    reconTableEl.innerHTML = searchQuery
      ? '<p class="recon-empty">Nenhum alvo corresponde à busca.</p>'
      : `<div class="recon-empty-state">
           <p class="recon-empty">Nenhum alvo ainda.</p>
           <p class="recon-hint">Rode um scan no chat ou Auto-Pilot. Achados de nmap/nikto/nuclei aparecem aqui e no relatório.</p>
           <button type="button" class="recon-action-btn recon-action-btn--primary" id="recon-first-scan">exemplo: scanme.nmap.org</button>
         </div>`;
    document.getElementById("recon-first-scan")?.addEventListener("click", () => {
      if (ctx.input) {
        ctx.input.value =
          "Faça um scan básico em scanme.nmap.org e salve saídas em /tools/output/";
        ctx.input.focus();
        ctx.onClose?.();
      }
    });
    return;
  }

  reconTableEl.innerHTML = "";
  const table = document.createElement("div");
  table.className = "recon-table";
  table.setAttribute("role", "table");

  const head = document.createElement("div");
  head.className = "recon-row recon-row-head";
  head.setAttribute("role", "row");
  head.innerHTML = `
    <span class="recon-col recon-col-caret" role="columnheader"></span>
    <span class="recon-col recon-col-target" role="columnheader">alvo</span>
    <span class="recon-col recon-col-stat" role="columnheader">portas</span>
    <span class="recon-col recon-col-stat" role="columnheader">achados</span>
    <span class="recon-col recon-col-stat" role="columnheader">ok</span>
    <span class="recon-col recon-col-date" role="columnheader">mod</span>
  `;
  table.appendChild(head);

  for (const t of filtered) {
    const isExpanded = expandedTarget === t.target;
    const cached = detailCache.get(t.target);
    const entry = document.createElement("div");
    entry.className = `recon-entry${isExpanded ? " expanded" : ""}`;

    const vulns = t.vulnerabilities_count || 0;
    const confirmed = t.findings_confirmed || 0;

    const row = document.createElement("button");
    row.type = "button";
    row.className = "recon-row recon-row-toggle";
    row.setAttribute("aria-expanded", isExpanded ? "true" : "false");
    row.innerHTML = `
      <span class="recon-col recon-col-caret" aria-hidden="true">${isExpanded ? "▾" : "▸"}</span>
      <span class="recon-col recon-col-target">
        <span class="recon-target-name">${escapeHtml(t.target)}</span>
        <span class="recon-target-file">${t.commands_run ? `${t.commands_run} cmds` : t.last_tool || "—"} · ${t.has_surface ? "surface" : "só cache"}</span>
      </span>
      <span class="recon-col recon-col-stat">${t.open_ports_count || 0}</span>
      <span class="recon-col recon-col-stat ${vulns ? "recon-col-warn" : ""}">${vulns}</span>
      <span class="recon-col recon-col-stat ${confirmed ? "recon-col-ok" : ""}">${confirmed}</span>
      <span class="recon-col recon-col-date">${formatDate(t.updated_at)}</span>
    `;
    row.addEventListener("click", () => toggleTarget(t.target));

    const card = document.createElement("div");
    card.className = "recon-card";
    if (!isExpanded) card.hidden = true;
    card.innerHTML = renderExpandCard(
      t.target,
      cached?.data,
      cached?.loading,
      cached?.error
    );
    bindCardActions(card);

    entry.appendChild(row);
    entry.appendChild(card);
    table.appendChild(entry);
  }

  reconTableEl.appendChild(table);
}

async function fetchDetail(target) {
  detailCache.set(target, { loading: true });
  renderTable(cachedList || []);

  try {
    const res = await getReconDetail(target);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      detailCache.set(target, { error: err.detail || "Erro ao carregar" });
    } else {
      detailCache.set(target, { data: await res.json() });
    }
  } catch (e) {
    detailCache.set(target, { error: e.message });
  }
  renderTable(cachedList || []);
}

async function toggleTarget(target) {
  if (expandedTarget === target) {
    expandedTarget = null;
    renderTable(cachedList || []);
    return;
  }
  expandedTarget = target;
  if (!detailCache.has(target) || detailCache.get(target)?.error) {
    await fetchDetail(target);
  } else {
    renderTable(cachedList || []);
  }
}

export async function loadReconTab(force = false) {
  const { reconTableEl } = ctx;
  if (!reconTableEl) return;

  if (!force && cachedList) {
    renderTable(cachedList);
    return;
  }

  reconTableEl.innerHTML = '<p class="recon-empty">carregando alvos…</p>';

  try {
    const res = await listRecon();
    if (!res.ok) throw new Error("Falha ao listar alvos");
    cachedList = (await res.json()).targets || [];
    renderTable(cachedList);
  } catch (e) {
    reconTableEl.innerHTML = `<p class="recon-empty">${escapeHtml(e.message)}</p>`;
  }
}
