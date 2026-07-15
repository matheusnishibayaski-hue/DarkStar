/** Recon — tabela retro com linhas expansíveis (cache /var/recon). */

import { listRecon, getReconDetail } from "./api/routes.js";
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

function renderExpandCard(target, data, loading, error) {
  if (loading) return '<p class="recon-card-loading">carregando detalhe…</p>';
  if (error) return `<p class="recon-card-error">${escapeHtml(error)}</p>`;
  if (!data) return "";

  const ports = data.open_ports || [];
  const cves = data.cves || [];
  const vulns = data.vulnerabilities || [];

  return `
    <div class="recon-card-inner">
      <div class="recon-card-head">
        <span class="recon-card-file">${escapeHtml(target)}.json</span>
        <span class="recon-card-meta">atualizado ${formatDate(data.updated_at)}${data.last_tool ? ` · ${escapeHtml(data.last_tool)}` : ""}</span>
      </div>
      <div class="recon-card-grid">
        ${ports.length ? `
          <section class="recon-card-section">
            <h4># portas abertas <span class="recon-count">${ports.length}</span></h4>
            <ul class="recon-tags">${ports.slice(0, 48).map((p) => `<li>${escapeHtml(p)}</li>`).join("")}</ul>
            ${ports.length > 48 ? `<p class="recon-more">+${ports.length - 48} …</p>` : ""}
          </section>` : ""}
        ${cves.length ? `
          <section class="recon-card-section">
            <h4># CVEs <span class="recon-count">${cves.length}</span></h4>
            <ul class="recon-tags recon-tags--cve">${cves.map((c) => `<li>${escapeHtml(c)}</li>`).join("")}</ul>
          </section>` : ""}
        ${vulns.length ? `
          <section class="recon-card-section recon-card-section--full">
            <h4># achados <span class="recon-count">${vulns.length}</span></h4>
            <ul class="recon-findings">${vulns.slice(0, 30).map((v) => `<li>${escapeHtml(v)}</li>`).join("")}</ul>
            ${vulns.length > 30 ? `<p class="recon-more">+${vulns.length - 30} …</p>` : ""}
          </section>` : ""}
        ${!ports.length && !cves.length && !vulns.length ? '<p class="recon-empty">Sem dados extraídos para este alvo.</p>' : ""}
      </div>
      <div class="recon-card-actions">
        <button type="button" class="recon-action-btn" data-action="prompt" data-target="${escapeHtml(target)}">usar no prompt</button>
        <button type="button" class="recon-action-btn recon-action-btn--scan" data-action="scan" data-target="${escapeHtml(target)}">re-scan</button>
        <button type="button" class="recon-action-btn recon-action-btn--files" data-action="files" data-target="${escapeHtml(target)}">artefatos</button>
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
      if (!target || !ctx.input) return;
      if (action === "prompt") {
        ctx.input.value = `Recon e análise de ${target}`;
      } else if (action === "scan") {
        ctx.input.value = `Atualize o recon de ${target}: portas, serviços e vulnerabilidades`;
      } else if (action === "files") {
        ctx.onOpenFiles?.(target);
        ctx.onClose?.();
        return;
      }
      ctx.input.focus();
      ctx.onClose?.();
    });
  });
}

function renderTable(targets) {
  const { reconTableEl, reconMetaEl } = ctx;
  if (!reconTableEl) return;

  const filtered = filterAndSort(targets);
  if (reconMetaEl) {
    reconMetaEl.textContent = `${filtered.length} alvo(s) · /var/recon`;
  }

  if (!filtered.length) {
    reconTableEl.innerHTML = searchQuery
      ? '<p class="recon-empty">Nenhum alvo corresponde à busca.</p>'
      : `<p class="recon-empty">Nenhum alvo em cache.</p>
         <p class="recon-hint">Execute scans em alvos autorizados — a IA persiste portas, CVEs e achados automaticamente.</p>
         <button type="button" class="recon-action-btn recon-first-scan" id="recon-first-scan">rodar primeiro scan</button>`;
    document.getElementById("recon-first-scan")?.addEventListener("click", () => {
      if (ctx.input) {
        ctx.input.value = "Faça um scan básico em scanme.nmap.org e salve em /tools/output/";
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
    <span class="recon-col recon-col-stat" role="columnheader">cve</span>
    <span class="recon-col recon-col-stat" role="columnheader">achados</span>
    <span class="recon-col recon-col-date" role="columnheader">mod</span>
  `;
  table.appendChild(head);

  for (const t of filtered) {
    const isExpanded = expandedTarget === t.target;
    const cached = detailCache.get(t.target);
    const entry = document.createElement("div");
    entry.className = `recon-entry${isExpanded ? " expanded" : ""}`;

    const row = document.createElement("button");
    row.type = "button";
    row.className = "recon-row recon-row-toggle";
    row.setAttribute("aria-expanded", isExpanded ? "true" : "false");
    row.innerHTML = `
      <span class="recon-col recon-col-caret" aria-hidden="true">${isExpanded ? "▾" : "▸"}</span>
      <span class="recon-col recon-col-target">
        <span class="recon-target-name">${escapeHtml(t.target)}</span>
        <span class="recon-target-file">${escapeHtml(t.target)}.json</span>
      </span>
      <span class="recon-col recon-col-stat">${t.open_ports_count || 0}</span>
      <span class="recon-col recon-col-stat">${t.cves_count || 0}</span>
      <span class="recon-col recon-col-stat recon-col-warn">${t.vulnerabilities_count || 0}</span>
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
      cached?.error,
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

  reconTableEl.innerHTML = '<p class="recon-empty">listando /var/recon …</p>';

  try {
    const res = await listRecon();
    if (!res.ok) throw new Error("Falha ao listar recon");
    cachedList = (await res.json()).targets || [];
    renderTable(cachedList);
  } catch (e) {
    reconTableEl.innerHTML = `<p class="recon-empty">${escapeHtml(e.message)}</p>`;
  }
}
