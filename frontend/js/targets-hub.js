/**
 * Intel simplificado — conversas (chat), achados agregados, triagem e PDF único.
 */

import {
  listIntelSessions,
  getIntelSession,
  patchIntelSession,
  patchSessionFinding,
  deleteIntelSession,
} from "./api/routes.js";
import { apiFetch } from "./api.js";
import {
  store,
  sessionTitle,
  getActiveSession,
  collectSessionExecutions,
  collectSessionHistory,
} from "./sessions.js";
import { escapeHtml } from "./exec.js";

let ctx = {};
let sessions = [];
let selected = "";
let detail = null;
let loading = false;

const SEV_ORDER = [
  { key: "alto", label: "Alto", class: "intel-sev--high" },
  { key: "medio", label: "Médio", class: "intel-sev--med" },
  { key: "baixo", label: "Baixo", class: "intel-sev--low" },
];

const STATUS_LABEL = {
  confirmed: "Positivo",
  false_positive: "Falso positivo",
  discarded: "Descartado",
  candidate: "Pendente",
  inconclusive: "Pendente",
};

function sevBucket(sev) {
  const s = (sev || "").toLowerCase();
  if (s === "critical" || s === "high") return "alto";
  if (s === "medium") return "medio";
  return "baixo";
}

function groupFindings(findings) {
  const g = { alto: [], medio: [], baixo: [] };
  for (const f of findings || []) {
    g[sevBucket(f.severity)].push(f);
  }
  return g;
}

function displayName(item) {
  const label = (item?.label || "").trim();
  if (label) return label;
  return item?.title || "Conversa";
}

function mergeSessions(backendRows) {
  const byId = new Map((backendRows || []).map((s) => [s.session_id, s]));
  return [...store.sessions]
    .map((s) => {
      const row = byId.get(s.id) || {};
      return {
        session_id: s.id,
        title: sessionTitle(s),
        label: row.label || "",
        targets: row.targets || [],
        findings_total: row.findings_total || 0,
        findings_confirmed: row.findings_confirmed || 0,
        updatedAt: s.updatedAt || 0,
      };
    })
    .sort((a, b) => b.updatedAt - a.updatedAt);
}

export function initTargetsHub(context) {
  ctx = context;
  ctx.hubSearch?.addEventListener("input", () => renderList());
  ctx.hubRefresh?.addEventListener("click", () => loadHub(true));
  ctx.hubReportPdf?.addEventListener("click", () => downloadPdf());
  ctx.hubDelete?.addEventListener("click", () => confirmDelete());
}

function filteredSessions() {
  const q = (ctx.hubSearch?.value || "").trim().toLowerCase();
  if (!q) return sessions;
  return sessions.filter((s) => {
    const name = displayName(s).toLowerCase();
    const title = String(s.title || "").toLowerCase();
    const targets = (s.targets || []).join(" ").toLowerCase();
    return name.includes(q) || title.includes(q) || targets.includes(q);
  });
}

function renderList() {
  const el = ctx.hubListEl;
  if (!el) return;
  const list = filteredSessions();

  if (!list.length) {
    el.innerHTML = sessions.length
      ? `<p class="intel-empty">Nenhuma conversa encontrada.</p>`
      : `<div class="intel-empty-box">
           <p class="intel-empty">Nenhuma conversa ainda</p>
           <p class="intel-hint">Inicie um chat e execute ferramentas em alvos autorizados.</p>
         </div>`;
    return;
  }

  el.innerHTML = list
    .map((s) => {
      const n = s.findings_total || 0;
      const pos = s.findings_confirmed || 0;
      const active = s.session_id === selected ? " is-active" : "";
      const name = displayName(s);
      const targets = (s.targets || []).slice(0, 2).join(", ");
      const sub = targets
        ? `<span class="intel-target-host">${escapeHtml(targets)}${s.targets.length > 2 ? "…" : ""}</span>`
        : "";
      return `
      <button type="button" class="intel-target${active}" data-session="${escapeHtml(s.session_id)}">
        <span class="intel-target-name">${escapeHtml(name)}</span>
        ${sub}
        <span class="intel-target-meta">${n} achado(s) · ${pos} positivo(s)</span>
      </button>`;
    })
    .join("");

  el.querySelectorAll("[data-session]").forEach((btn) => {
    btn.addEventListener("click", () => selectSession(btn.dataset.session));
  });
}

function setActionsEnabled(on) {
  if (ctx.hubReportPdf) ctx.hubReportPdf.disabled = !on;
  if (ctx.hubDelete) ctx.hubDelete.disabled = !on;
}

async function setFindingStatus(fid, surfaceTarget, status) {
  if (!selected || !fid || !surfaceTarget) return;
  try {
    await patchSessionFinding(selected, fid, {
      surface_target: surfaceTarget,
      status,
      evidence: `manual:${status}`,
    });
    ctx.toast?.(`Marcado como ${STATUS_LABEL[status] || status}`, "success");
    await selectSession(selected, true);
  } catch (e) {
    ctx.toast?.(e.message || "Falha ao salvar", "error");
  }
}

function renderFindingRow(f) {
  const id = f.id || "";
  const surfaceTarget = f.surface_target || f.host || "";
  const status = f.status || "candidate";
  const statusLabel = STATUS_LABEL[status] || status;
  const host = surfaceTarget ? ` · ${surfaceTarget}` : "";
  return `
    <li class="intel-finding" data-fid="${escapeHtml(id)}">
      <div class="intel-finding-main">
        <p class="intel-finding-title">${escapeHtml(f.title || "—")}</p>
        <p class="intel-finding-meta">${escapeHtml(statusLabel)}${f.tool ? ` · ${escapeHtml(f.tool)}` : ""}${escapeHtml(host)}</p>
      </div>
      ${
        id && surfaceTarget
          ? `<div class="intel-finding-btns">
              <button type="button" class="intel-triage-btn intel-triage-btn--ok${status === "confirmed" ? " is-on" : ""}" data-status="confirmed" data-id="${escapeHtml(id)}" data-target="${escapeHtml(surfaceTarget)}">Positivo</button>
              <button type="button" class="intel-triage-btn intel-triage-btn--fp${status === "false_positive" ? " is-on" : ""}" data-status="false_positive" data-id="${escapeHtml(id)}" data-target="${escapeHtml(surfaceTarget)}">Falso positivo</button>
              <button type="button" class="intel-triage-btn intel-triage-btn--drop${status === "discarded" ? " is-on" : ""}" data-status="discarded" data-id="${escapeHtml(id)}" data-target="${escapeHtml(surfaceTarget)}">Descartar</button>
            </div>`
          : ""
      }
    </li>`;
}

async function saveLabel() {
  if (!selected) return;
  const input = document.getElementById("hub-label-input");
  const label = (input?.value || "").trim();
  try {
    const res = await patchIntelSession(selected, { label });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Falha ao salvar nome");
    }
    const row = sessions.find((s) => s.session_id === selected);
    if (row) row.label = label;
    if (detail) detail.label = label;
    ctx.toast?.("Nome atualizado", "success");
    renderList();
    renderDetail();
  } catch (e) {
    ctx.toast?.(e.message || "Falha ao salvar", "error");
  }
}

function renderDetail() {
  const el = ctx.hubDetailEl;
  if (!el) return;

  if (!selected) {
    el.innerHTML = `<div class="intel-empty-box">
      <p class="intel-empty">Selecione uma conversa</p>
      <p class="intel-hint">Todos os testes desta conversa entram em um único PDF.</p>
    </div>`;
    setActionsEnabled(false);
    if (ctx.hubMetaEl) ctx.hubMetaEl.textContent = `${sessions.length} conversa(s)`;
    return;
  }

  if (loading) {
    el.innerHTML = `<p class="intel-empty">Carregando…</p>`;
    return;
  }

  setActionsEnabled(true);
  const row = sessions.find((s) => s.session_id === selected);
  const findings = detail?.findings || [];
  const groups = groupFindings(findings);
  const confirmed = findings.filter((f) => f.status === "confirmed").length;
  const name = displayName({ ...row, label: detail?.label });
  const labelVal = (detail?.label || row?.label || "").trim();
  const targets = detail?.targets || row?.targets || [];

  if (ctx.hubMetaEl) {
    ctx.hubMetaEl.textContent = `${name} · ${findings.length} achado(s) · ${confirmed} no PDF`;
  }

  let sections = "";
  for (const { key, label, class: cls } of SEV_ORDER) {
    const items = groups[key];
    sections += `
      <section class="intel-sev-block ${cls}">
        <h3 class="intel-sev-title">${label} <em>${items.length}</em></h3>
        ${
          items.length
            ? `<ul class="intel-findings">${items.map(renderFindingRow).join("")}</ul>`
            : `<p class="intel-hint">Nenhum achado nesta faixa.</p>`
        }
      </section>`;
  }

  el.innerHTML = `
    <header class="intel-detail-head">
      <div class="intel-rename">
        <label class="intel-rename-label" for="hub-label-input">Nome no relatório (PDF)</label>
        <div class="intel-rename-row">
          <input type="text" class="intel-rename-input" id="hub-label-input"
            value="${escapeHtml(labelVal || name)}"
            placeholder="ex: Pentest Cliente XYZ — Mar/2026"
            maxlength="120" spellcheck="false" />
          <button type="button" class="hub-btn" id="hub-label-save">Salvar</button>
        </div>
        <p class="intel-hint">Alvos nesta conversa: ${
          targets.length
            ? targets.map((t) => `<code>${escapeHtml(t)}</code>`).join(", ")
            : "<em>nenhum ainda</em>"
        }</p>
      </div>
    </header>
    ${sections}
  `;

  document.getElementById("hub-label-save")?.addEventListener("click", () => saveLabel());
  document.getElementById("hub-label-input")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      saveLabel();
    }
  });

  el.querySelectorAll("[data-status]").forEach((btn) => {
    btn.addEventListener("click", () => {
      setFindingStatus(
        btn.getAttribute("data-id"),
        btn.getAttribute("data-target"),
        btn.getAttribute("data-status")
      );
    });
  });
}

async function selectSession(sessionId, force = false) {
  if (!sessionId) return;
  if (!force && selected === sessionId && detail) {
    renderList();
    return;
  }
  selected = sessionId;
  loading = true;
  renderList();
  renderDetail();
  try {
    const res = await getIntelSession(sessionId);
    if (res.ok) {
      detail = await res.json();
    } else {
      const row = sessions.find((s) => s.session_id === sessionId);
      detail = {
        session_id: sessionId,
        label: row?.label || "",
        targets: row?.targets || [],
        findings: [],
      };
    }
  } catch (e) {
    detail = { session_id: sessionId, findings: [], targets: [], label: "" };
    ctx.toast?.(e.message || "Erro ao carregar", "error");
  }
  loading = false;
  renderList();
  renderDetail();
}

async function downloadPdf() {
  if (!selected) {
    ctx.toast?.("Selecione uma conversa", "warn");
    return;
  }
  const session = store.sessions.find((s) => s.id === selected);
  if (!session) {
    ctx.toast?.("Conversa não encontrada", "warn");
    return;
  }
  const toolExecutions = collectSessionExecutions(session);
  if (!toolExecutions.length) {
    ctx.toast?.("Nenhuma ferramenta executada nesta conversa", "warn");
    return;
  }

  const btn = ctx.hubReportPdf;
  if (btn) btn.disabled = true;
  try {
    const label = (detail?.label || sessions.find((s) => s.session_id === selected)?.label || "").trim();
    const title = label ? `Relatório — ${label}` : `Relatório — ${sessionTitle(session)}`;
    const res = await apiFetch("/api/generate-report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        history: collectSessionHistory(session),
        tool_executions: toolExecutions,
        title,
        chat_session_id: selected,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || res.statusText || "Falha ao gerar PDF");
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "relatorio-pentest.pdf";
    a.click();
    URL.revokeObjectURL(url);
    ctx.toast?.("PDF baixado", "success");
  } catch (e) {
    ctx.toast?.(e.message || "Erro ao gerar PDF", "error");
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function confirmDelete() {
  if (!selected) return;
  const row = sessions.find((s) => s.session_id === selected);
  const name = displayName({ ...row, label: detail?.label });
  const ok = window.confirm(
    `Limpar achados e dados de pentest de "${name}"?\n\nA conversa no chat será mantida.`
  );
  if (!ok) return;
  try {
    await deleteIntelSession(selected);
    detail = { session_id: selected, findings: [], targets: [], label: "" };
    const row2 = sessions.find((s) => s.session_id === selected);
    if (row2) {
      row2.findings_total = 0;
      row2.findings_confirmed = 0;
      row2.targets = [];
    }
    ctx.toast?.("Dados de pentest removidos", "success");
    renderList();
    renderDetail();
  } catch (e) {
    ctx.toast?.(e.message || "Falha ao limpar", "error");
  }
}

export async function loadHub(force = false) {
  if (!force && sessions.length) {
    renderList();
    renderDetail();
    return;
  }
  if (ctx.hubListEl) ctx.hubListEl.innerHTML = `<p class="intel-empty">Carregando…</p>`;
  try {
    const res = await listIntelSessions();
    const body = res.ok ? await res.json() : { sessions: [] };
    sessions = mergeSessions(body.sessions || []);
    if (selected && !sessions.some((s) => s.session_id === selected)) {
      selected = "";
      detail = null;
    }
    if (!selected) {
      const active = getActiveSession();
      if (active) await selectSession(active.id);
      else if (sessions[0]) await selectSession(sessions[0].session_id);
      else renderDetail();
    } else {
      renderList();
      await selectSession(selected, true);
    }
  } catch (e) {
    if (ctx.hubListEl) {
      ctx.hubListEl.innerHTML = `<p class="intel-empty">${escapeHtml(e.message)}</p>`;
    }
  }
}

export function openSessionInHub(sessionId) {
  if (sessionId) selectSession(sessionId);
}

/** @deprecated use openSessionInHub */
export function openTargetInHub(sessionId) {
  openSessionInHub(sessionId);
}
