/** Onboarding de primeiro uso — 3 passos. */

import { ONBOARDING_STORAGE_KEY } from "./constants.js";
import { getHealth } from "./api/routes.js";
import { escapeHtml } from "./exec.js";

let ctx = {};
let step = 0;
let healthData = null;

export function initOnboarding(context) {
  ctx = context;
  ctx.onboardingNext?.addEventListener("click", nextStep);
  ctx.onboardingSkip?.addEventListener("click", finish);
  ctx.onboardingBackdrop?.addEventListener("click", (e) => {
    if (e.target === ctx.onboardingBackdrop) finish();
  });
}

export function maybeShowOnboarding() {
  if (localStorage.getItem(ONBOARDING_STORAGE_KEY)) return;
  step = 0;
  healthData = null;
  showOverlay();
  renderStep();
  refreshHealthForOnboarding();
}

function showOverlay() {
  if (!ctx.onboardingOverlay) return;
  ctx.onboardingOverlay.hidden = false;
  requestAnimationFrame(() => ctx.onboardingOverlay.classList.add("overlay-visible"));
  document.body.classList.add("has-overlay");
  ctx.onboardingNext?.focus();
}

function hideOverlay() {
  if (!ctx.onboardingOverlay) return;
  ctx.onboardingOverlay.classList.remove("overlay-visible");
  ctx.onboardingOverlay.hidden = true;
  if (!document.querySelector(".overlay:not([hidden])")) {
    document.body.classList.remove("has-overlay");
  }
}

function finish() {
  localStorage.setItem(ONBOARDING_STORAGE_KEY, "1");
  hideOverlay();
  ctx.input?.focus();
}

async function refreshHealthForOnboarding() {
  try {
    const res = await getHealth();
    if (res.ok) healthData = await res.json();
  } catch { /* ignore */ }
  if (step === 0) renderStep();
}

function renderStep() {
  const { onboardingBody, onboardingTitle, onboardingNext, onboardingSkip } = ctx;
  if (!onboardingBody) return;

  const steps = [
    {
      title: "1/3 — Ambiente",
      html: renderHealthStep(),
      next: "continuar",
    },
    {
      title: "2/3 — Escopo de alvos",
      html: `
        <p>Defina <code>ALLOWED_TARGETS</code> no arquivo <code>.env</code> para restringir scans a alvos autorizados.</p>
        <pre class="onboarding-code">ALLOWED_TARGETS=scanme.nmap.org,10.0.0.5</pre>
        <p class="onboarding-note">Vazio = sem restrição (modo aviso). Reinicie o servidor após editar o .env.</p>
      `,
      next: "continuar",
    },
    {
      title: "3/3 — Primeiro scan",
      html: `
        <p>Experimente um alvo de laboratório público:</p>
        <pre class="onboarding-code">nmap -sV scanme.nmap.org</pre>
        <p>Ou use o prompt rápido abaixo após fechar este guia.</p>
      `,
      next: "começar",
    },
  ];

  const current = steps[step];
  if (onboardingTitle) onboardingTitle.textContent = current.title;
  onboardingBody.innerHTML = current.html;
  if (onboardingNext) onboardingNext.textContent = current.next;
  if (onboardingSkip) {
    onboardingSkip.textContent = step === 1 ? "continuar sem escopo" : "pular";
  }
}

function renderHealthStep() {
  if (!healthData) {
    return '<p class="onboarding-loading">verificando docker e kali…</p>';
  }
  const docker = healthData.docker ? "ok" : "off";
  const kali = healthData.kali_container ? "ok" : "warn";
  const version = healthData.version || "—";
  return `
    <ul class="onboarding-checklist">
      <li>versão <strong>${escapeHtml(version)}</strong></li>
      <li>docker: <strong class="onboarding-${docker}">${docker}</strong></li>
      <li>kali: <strong class="onboarding-${kali}">${kali}</strong></li>
    </ul>
    ${!healthData.docker || !healthData.kali_container
      ? `<p class="onboarding-warn">${escapeHtml(healthData.kali_error || "Inicie Docker e rode start.bat repair")}</p>`
      : "<p>Ambiente pronto para executar ferramentas.</p>"}
  `;
}

function nextStep() {
  if (step < 2) {
    step += 1;
    renderStep();
    return;
  }
  finish();
  if (ctx.input) {
    ctx.input.value = "Faça um scan básico em scanme.nmap.org e analise os resultados";
    ctx.input.focus();
  }
}
