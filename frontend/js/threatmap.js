/** CiberAmeaças — widget Kaspersky (aba dentro de /sys/intel). */

import { escapeHtml } from "./exec.js";

const WIDGET_URL = "https://cybermap.kaspersky.com/pt/widget/dynamic/dark";
const FULL_MAP_URL = "https://cybermap.kaspersky.com/pt";

const THREAT_TYPES = [
  { code: "OAS", label: "Ataques online", desc: "Ameaças detectadas em tempo real na rede" },
  { code: "ODS", label: "Scanner sob demanda", desc: "Análise manual de objetos suspeitos" },
  { code: "MAV", label: "Antivírus de e-mail", desc: "Malware em anexos e links maliciosos" },
  { code: "WAV", label: "Antivírus web", desc: "URLs e downloads bloqueados" },
  { code: "IDS", label: "IDS / IPS", desc: "Tentativas de intrusão na rede" },
  { code: "VUL", label: "Vulnerabilidades", desc: "Exploração de falhas conhecidas" },
  { code: "KAS", label: "Anti-spam", desc: "Campanhas de spam e phishing" },
  { code: "RMW", label: "Ransomware", desc: "Tentativas de sequestro de dados" },
];

let ctx = {};
let viewMode = "live";
let iframeLoaded = false;
let loadingTimer = null;

export function initThreatIntel(context) {
  ctx = context;
  renderLegend();
  bindControls();
}

function hideLoading() {
  ctx.threatLoadingEl?.classList.add("hidden");
  if (loadingTimer) {
    clearTimeout(loadingTimer);
    loadingTimer = null;
  }
}

function showLoading() {
  ctx.threatLoadingEl?.classList.remove("hidden");
  if (loadingTimer) clearTimeout(loadingTimer);
  loadingTimer = setTimeout(hideLoading, 6000);
}

function renderLegend() {
  const { threatLegendEl } = ctx;
  if (!threatLegendEl) return;

  threatLegendEl.innerHTML = THREAT_TYPES.map((t) => `
    <div class="threat-legend-item" title="${escapeHtml(t.desc)}">
      <span class="threat-code">${t.code}</span>
      <span class="threat-label">${escapeHtml(t.label)}</span>
    </div>
  `).join("");
}

function bindControls() {
  ctx.threatModeLive?.addEventListener("click", () => setViewMode("live"));
  ctx.threatModeGlobe?.addEventListener("click", () => setViewMode("globe"));
  ctx.threatOpenFull?.addEventListener("click", () => {
    window.open(FULL_MAP_URL, "_blank", "noopener,noreferrer");
  });
}

function setViewMode(mode) {
  if (viewMode === mode) return;
  viewMode = mode;
  ctx.intelPanel?.classList.toggle("threatmap-view-globe", mode === "globe");
  ctx.threatModeLive?.classList.toggle("active", mode === "live");
  ctx.threatModeGlobe?.classList.toggle("active", mode === "globe");
}

function loadIframe() {
  const { threatFrame } = ctx;
  if (!threatFrame || iframeLoaded) return;
  iframeLoaded = true;
  showLoading();
  threatFrame.addEventListener("load", hideLoading);
  threatFrame.src = WIDGET_URL;
}

export function activateThreatsTab() {
  setViewMode("live");
  loadIframe();
}
