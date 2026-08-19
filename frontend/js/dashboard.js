/**
 * Dashboard — visão por conversa, linguagem para envio ao cliente.
 */

import { apiFetch } from "./api.js";
import { toast } from "./ui.js";
import { getActiveSession } from "./sessions.js";

let currentDays = 30;
let trendChart = null;
let severityChart = null;
let loadAbort = null;
let loadGen = 0;

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function sessionQuery() {
  const session = getActiveSession();
  if (!session?.id) return null;
  return `session_id=${encodeURIComponent(session.id)}`;
}

function sessionSlug() {
  const session = getActiveSession();
  return String(session?.id || "sessao").slice(0, 8);
}

function todayStamp() {
  return new Date().toISOString().slice(0, 10).replace(/-/g, "");
}

export async function refreshDashboard() {
  return loadDashboard();
}

function setLoadingSkeleton() {
  const metricsEl = document.getElementById("dashboard-metrics");
  const topBody = document.querySelector("#dashboard-top-issues tbody");
  const histBody = document.querySelector("#dashboard-recent-scans tbody");
  if (metricsEl) metricsEl.innerHTML = "<p class='panel-callout'>carregando…</p>";
  if (topBody) topBody.innerHTML = `<tr><td colspan="4">carregando…</td></tr>`;
  if (histBody) histBody.innerHTML = `<tr><td colspan="5">carregando…</td></tr>`;
}

async function loadDashboard() {
  const metricsEl = document.getElementById("dashboard-metrics");
  const leadEl = document.getElementById("dashboard-exec-lead");
  const q = sessionQuery();
  if (!q) {
    if (metricsEl) {
      metricsEl.innerHTML = "<p class='panel-callout'>Nenhuma conversa ativa.</p>";
    }
    if (leadEl) leadEl.textContent = "";
    return;
  }

  if (loadAbort) loadAbort.abort();
  loadAbort = new AbortController();
  const gen = ++loadGen;
  setLoadingSkeleton();

  try {
    const res = await apiFetch(
      `/api/dashboard/bundle?days=${currentDays}&history_limit=20&top_limit=10&${q}`,
      { signal: loadAbort.signal }
    );
    const data = await res.json().catch(() => ({}));
    if (gen !== loadGen) return;
    if (!res.ok) throw new Error(data.detail || "falha ao carregar dashboard");
    renderMetrics(data.metrics || {});
    renderTrend(data.trend || []);
    renderSeverity(data.trend || []);
    renderTopIssues(data.top_issues || []);
    renderRecent(data.history || []);
  } catch (err) {
    if (err?.name === "AbortError") return;
    if (gen !== loadGen) return;
    if (metricsEl) {
      metricsEl.innerHTML = `<p class="panel-callout">Falha ao carregar: ${escapeHtml(err.message || err)}</p>`;
    }
    toast?.("Dashboard: falha ao carregar", "error");
  }
}

function meaningFor(key, value) {
  const n = Number(value) || 0;
  if (key === "scans") {
    if (n === 0) return "Ainda não houve varreduras nesta conversa.";
    return n === 1 ? "Uma varredura registrada no período." : `${n} varreduras no período selecionado.`;
  }
  if (key === "critical") {
    if (n === 0) return "Nenhuma crítica em média — bom sinal.";
    return "Média de achados críticos por varredura — priorize estes.";
  }
  if (key === "high") {
    if (n === 0) return "Sem achados altos em média.";
    return "Média de achados altos — trate após as críticas.";
  }
  if (key === "open") {
    if (n === 0) return "Nada em aberto neste recorte.";
    return "Problemas ainda sem fechamento nesta conversa.";
  }
  return "";
}

function renderMetrics(data) {
  const el = document.getElementById("dashboard-metrics");
  const leadEl = document.getElementById("dashboard-exec-lead");
  if (!el) return;
  const open = data.open_vulnerabilities ?? 0;
  const scans = data.total_scans ?? 0;
  const crit = Math.round(data.avg_critical || 0);
  const high = Math.round(data.avg_high || 0);
  if (leadEl) {
    if (!scans) {
      leadEl.textContent =
        "Resumo executivo: ainda não há varreduras nesta conversa. Rode testes no chat ou no piloto e volte aqui.";
    } else if (open > 0) {
      leadEl.textContent = `Resumo executivo: ${scans} varredura(s) no período · ${open} problema(s) em aberto. Priorize críticas e altas antes de entregar ao cliente.`;
    } else {
      leadEl.textContent = `Resumo executivo: ${scans} varredura(s) no período · nenhum problema em aberto neste recorte.`;
    }
  }
  const cards = [
    { key: "scans", label: "Varreduras", value: scans },
    { key: "critical", label: "Críticas (média)", value: crit },
    { key: "high", label: "Altas (média)", value: high },
    { key: "open", label: "Problemas em aberto", value: open },
  ];
  el.innerHTML = cards
    .map(
      (c) =>
        `<div class="dashboard-metric">` +
        `<span class="dashboard-metric-label">${escapeHtml(c.label)}</span>` +
        `<span class="dashboard-metric-value">${escapeHtml(String(c.value))}</span>` +
        `<span class="dashboard-metric-hint">${escapeHtml(meaningFor(c.key, c.value))}</span>` +
        `</div>`
    )
    .join("");
}

function chartColors() {
  return {
    text: getComputedStyle(document.documentElement).getPropertyValue("--text")?.trim() || "#c9d1d9",
    muted: getComputedStyle(document.documentElement).getPropertyValue("--muted")?.trim() || "#8b949e",
    grid: "rgba(255,255,255,0.08)",
  };
}

function showChartEmpty(canvasId, message) {
  const canvas = document.getElementById(canvasId);
  const box = canvas?.closest(".dashboard-chart-box");
  if (!box) return;
  if (canvasId === "dashboard-trend-chart" && trendChart) {
    trendChart.destroy();
    trendChart = null;
  }
  if (canvasId === "dashboard-severity-chart" && severityChart) {
    severityChart.destroy();
    severityChart = null;
  }
  canvas?.remove();
  let empty = box.querySelector(".dashboard-chart-empty");
  if (!empty) {
    empty = document.createElement("p");
    empty.className = "dashboard-chart-empty";
    box.appendChild(empty);
  }
  empty.textContent = message;
}

function prepareChartCanvas(canvasId) {
  const old = document.getElementById(canvasId);
  const box = old?.closest(".dashboard-chart-box");
  if (!box) return null;
  box.querySelector(".dashboard-chart-empty")?.remove();
  if (!old) {
    const canvas = document.createElement("canvas");
    canvas.id = canvasId;
    canvas.height = 160;
    box.appendChild(canvas);
    return canvas;
  }
  return old;
}

function renderTrend(rows) {
  if (!rows.length) {
    showChartEmpty("dashboard-trend-chart", "Sem dados no período");
    return;
  }
  const canvas = prepareChartCanvas("dashboard-trend-chart");
  if (!canvas || typeof Chart === "undefined") return;
  const colors = chartColors();
  if (trendChart) trendChart.destroy();
  trendChart = new Chart(canvas.getContext("2d"), {
    type: "line",
    data: {
      labels: rows.map((r) => r.date),
      datasets: [
        {
          label: "Críticas",
          data: rows.map((r) => r.critical || 0),
          borderColor: "#e07a6a",
          tension: 0.2,
        },
        {
          label: "Altas",
          data: rows.map((r) => r.high || 0),
          borderColor: "#d4a84a",
          tension: 0.2,
        },
        {
          label: "Total",
          data: rows.map((r) => r.total || 0),
          borderColor: "#6ec6a8",
          tension: 0.2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: { legend: { labels: { color: colors.text } } },
      scales: {
        x: { ticks: { color: colors.muted }, grid: { color: colors.grid } },
        y: { ticks: { color: colors.muted }, grid: { color: colors.grid }, beginAtZero: true },
      },
    },
  });
}

function renderSeverity(rows) {
  const sum = rows.reduce(
    (acc, r) => {
      acc.critical += r.critical || 0;
      acc.high += r.high || 0;
      acc.medium += r.medium || 0;
      acc.low += r.low || 0;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0 }
  );
  const total = sum.critical + sum.high + sum.medium + sum.low;
  if (!rows.length || total === 0) {
    showChartEmpty("dashboard-severity-chart", "Sem dados no período");
    return;
  }
  const canvas = prepareChartCanvas("dashboard-severity-chart");
  if (!canvas || typeof Chart === "undefined") return;
  const colors = chartColors();
  if (severityChart) severityChart.destroy();
  severityChart = new Chart(canvas.getContext("2d"), {
    type: "doughnut",
    data: {
      labels: ["Crítica", "Alta", "Média", "Baixa"],
      datasets: [
        {
          data: [sum.critical, sum.high, sum.medium, sum.low],
          backgroundColor: ["#e07a6a", "#d4a84a", "#6ec6a8", "#8b949e"],
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: { legend: { labels: { color: colors.text } } },
    },
  });
}

function renderTopIssues(rows) {
  const tbody = document.querySelector("#dashboard-top-issues tbody");
  if (!tbody) return;
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="4">Nenhum problema nesta conversa</td></tr>`;
    return;
  }
  tbody.innerHTML = rows
    .map(
      (r) =>
        `<tr><td title="${escapeHtml(r.title || "")}">${escapeHtml(r.title || "")}</td>` +
        `<td>${escapeHtml(r.severity || "")}</td>` +
        `<td title="${escapeHtml(r.target || "")}">${escapeHtml(r.target || "")}</td>` +
        `<td>${escapeHtml(String(r.count ?? ""))}</td></tr>`
    )
    .join("");
}

function renderRecent(rows) {
  const tbody = document.querySelector("#dashboard-recent-scans tbody");
  if (!tbody) return;
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="5">Nenhuma varredura nesta conversa</td></tr>`;
    return;
  }
  tbody.innerHTML = rows
    .map((r) => {
      const when = String(r.timestamp || "").slice(0, 19).replace("T", " ");
      return (
        `<tr><td title="${escapeHtml(r.target || "")}">${escapeHtml(r.target || "")}</td>` +
        `<td>${escapeHtml(String(r.vulnerability_count ?? 0))}</td>` +
        `<td>${escapeHtml(String(r.critical ?? 0))}</td>` +
        `<td>${escapeHtml(String(r.high ?? 0))}</td>` +
        `<td>${escapeHtml(when)}</td></tr>`
      );
    })
    .join("");
}

async function exportReport(format) {
  const q = sessionQuery();
  if (!q) {
    toast?.("Nenhuma conversa ativa", "error");
    return;
  }
  try {
    const res = await apiFetch(
      `/api/dashboard/export?format=${format}&days=${currentDays}&${q}`
    );
    const stamp = todayStamp();
    const slug = sessionSlug();
    if (format === "json") {
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "export failed");
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      downloadBlob(blob, `darkstar-dashboard-${slug}-${stamp}.json`);
      return;
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "export failed");
    }
    const blob = await res.blob();
    const ext = format === "pdf" ? "pdf" : format === "xlsx" ? "xlsx" : "csv";
    downloadBlob(blob, `darkstar-dashboard-${slug}-${stamp}.${ext}`);
    if (format === "xlsx") toast?.("Excel pronto para envio ao cliente", "info");
  } catch (err) {
    toast?.(`Export falhou: ${err.message || err}`, "error");
  }
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function initDashboard() {
  const refresh = document.getElementById("dashboard-refresh");
  refresh?.addEventListener("click", () => loadDashboard());
  document.querySelectorAll(".dashboard-period-btn").forEach((b) => {
    b.addEventListener("click", () => {
      document.querySelectorAll(".dashboard-period-btn").forEach((x) => x.classList.remove("active"));
      b.classList.add("active");
      currentDays = parseInt(b.dataset.days || "30", 10);
      loadDashboard();
    });
  });
  document.querySelectorAll("[data-export]").forEach((b) => {
    b.addEventListener("click", () => exportReport(b.getAttribute("data-export")));
  });
}
