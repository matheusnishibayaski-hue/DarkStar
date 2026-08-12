/**
 * Dashboard — métricas da conversa ativa (session_id obrigatório).
 */

import { apiFetch } from "./api.js";
import { toast } from "./ui.js";
import { getActiveSession } from "./sessions.js";

let currentDays = 30;
let trendChart = null;
let severityChart = null;

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

export async function refreshDashboard() {
  return loadDashboard();
}

async function loadDashboard() {
  const metricsEl = document.getElementById("dashboard-metrics");
  const q = sessionQuery();
  if (!q) {
    if (metricsEl) {
      metricsEl.innerHTML = "<p class='panel-callout'>Nenhuma conversa ativa.</p>";
    }
    return;
  }
  if (metricsEl) metricsEl.innerHTML = "<p class='panel-callout'>carregando…</p>";
  try {
    const [metricsRes, trendRes, topRes, histRes] = await Promise.all([
      apiFetch(`/api/dashboard/metrics?days=${currentDays}&${q}`),
      apiFetch(`/api/dashboard/vulnerability-trend?days=${currentDays}&${q}`),
      apiFetch(`/api/dashboard/top-issues?limit=10&${q}`),
      apiFetch(`/api/dashboard/scan-history?days=${currentDays}&limit=20&${q}`),
    ]);
    const metrics = await metricsRes.json();
    const trend = await trendRes.json();
    const top = await topRes.json();
    const hist = await histRes.json();
    if (!metricsRes.ok) throw new Error(metrics.detail || "métricas");
    renderMetrics(metrics.data || {});
    renderTrend(trend.data || []);
    renderSeverity(trend.data || []);
    renderTopIssues(top.data || []);
    renderRecent(hist.data || []);
  } catch (err) {
    if (metricsEl) {
      metricsEl.innerHTML = `<p class="panel-callout">Falha ao carregar: ${escapeHtml(err.message || err)}</p>`;
    }
    toast?.("Dashboard: falha ao carregar", "error");
  }
}

function renderMetrics(data) {
  const el = document.getElementById("dashboard-metrics");
  if (!el) return;
  const cards = [
    { label: "Scans", value: data.total_scans ?? 0 },
    { label: "Avg critical", value: Math.round(data.avg_critical || 0) },
    { label: "Avg high", value: Math.round(data.avg_high || 0) },
    { label: "Open vulns", value: data.open_vulnerabilities ?? 0 },
  ];
  el.innerHTML = cards
    .map(
      (c) =>
        `<div class="dashboard-metric"><span class="dashboard-metric-label">${escapeHtml(c.label)}</span>` +
        `<span class="dashboard-metric-value">${escapeHtml(String(c.value))}</span></div>`
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

function renderTrend(rows) {
  const canvas = document.getElementById("dashboard-trend-chart");
  if (!canvas || typeof Chart === "undefined") return;
  const colors = chartColors();
  if (trendChart) trendChart.destroy();
  trendChart = new Chart(canvas.getContext("2d"), {
    type: "line",
    data: {
      labels: rows.map((r) => r.date),
      datasets: [
        {
          label: "Critical",
          data: rows.map((r) => r.critical || 0),
          borderColor: "#e07a6a",
          tension: 0.2,
        },
        {
          label: "High",
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
      plugins: { legend: { labels: { color: colors.text } } },
      scales: {
        x: { ticks: { color: colors.muted }, grid: { color: colors.grid } },
        y: { ticks: { color: colors.muted }, grid: { color: colors.grid } },
      },
    },
  });
}

function renderSeverity(rows) {
  const canvas = document.getElementById("dashboard-severity-chart");
  if (!canvas || typeof Chart === "undefined") return;
  const colors = chartColors();
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
  if (severityChart) severityChart.destroy();
  severityChart = new Chart(canvas.getContext("2d"), {
    type: "doughnut",
    data: {
      labels: ["Critical", "High", "Medium", "Low"],
      datasets: [
        {
          data: [sum.critical, sum.high, sum.medium, sum.low],
          backgroundColor: ["#e07a6a", "#d4a84a", "#6ec6a8", "#8b949e"],
        },
      ],
    },
    options: {
      responsive: true,
      plugins: { legend: { labels: { color: colors.text } } },
    },
  });
}

function renderTopIssues(rows) {
  const tbody = document.querySelector("#dashboard-top-issues tbody");
  if (!tbody) return;
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="4">Nenhum issue nesta conversa</td></tr>`;
    return;
  }
  tbody.innerHTML = rows
    .map(
      (r) =>
        `<tr><td>${escapeHtml(r.title || "")}</td><td>${escapeHtml(r.severity || "")}</td>` +
        `<td>${escapeHtml(r.target || "")}</td><td>${escapeHtml(String(r.count ?? ""))}</td></tr>`
    )
    .join("");
}

function renderRecent(rows) {
  const tbody = document.querySelector("#dashboard-recent-scans tbody");
  if (!tbody) return;
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="5">Nenhum scan nesta conversa</td></tr>`;
    return;
  }
  tbody.innerHTML = rows
    .map((r) => {
      const when = String(r.timestamp || "").slice(0, 19).replace("T", " ");
      return (
        `<tr><td>${escapeHtml(r.target || "")}</td>` +
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
    if (format === "json") {
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "export failed");
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      downloadBlob(blob, `darkstar-dashboard-${currentDays}d.json`);
      return;
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "export failed");
    }
    const blob = await res.blob();
    const ext = format === "pdf" ? "pdf" : "csv";
    downloadBlob(blob, `darkstar-dashboard-${currentDays}d.${ext}`);
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
