/**
 * Tour guiado — overlay cinza, destaque no elemento e explicação em linguagem simples.
 */

import { openOverlay, openSidebar } from "./ui.js";

let ctx = {};
let stepIndex = 0;
let active = false;

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

function $(id) {
  return typeof id === "string" ? document.querySelector(id) : id;
}

function visible(el) {
  if (!el) return false;
  if (el.hidden) return false;
  const st = getComputedStyle(el);
  if (st.display === "none" || st.visibility === "hidden") return false;
  const r = el.getBoundingClientRect();
  return r.width > 0 && r.height > 0;
}

/** Elemento real para o spotlight (ex.: label do switch quando o input está oculto). */
function spotlightTarget(step) {
  const primary = step.spotlightSelector ? $(step.spotlightSelector) : $(step.selector);
  if (!primary) return null;
  if (visible(primary)) return primary;
  if (primary instanceof HTMLInputElement) {
    const label =
      primary.closest("label") ||
      (primary.id ? document.querySelector(`label[for="${CSS.escape(primary.id)}"]`) : null);
    if (label && visible(label)) return label;
  }
  return null;
}

function buildSteps() {
  return [
    {
      title: "Bem-vindo",
      text: "DarkStar com Argus: converse e rode ferramentas no Kali — só em alvos autorizados.",
      centered: true,
      before: async () => resetPanels(),
    },
    {
      selector: "#chat",
      title: "Conversa",
      text: "Mensagens e respostas da Argus aparecem aqui.",
      placement: "top",
      before: async () => resetPanels(),
    },
    {
      selector: "#input",
      title: "Mensagem",
      text: "Escreva e pressione Enter. Ex.: scan leve em scanme.nmap.org.",
      placement: "top",
    },
    {
      selector: "#model-trigger",
      title: "Modelo",
      text: "Troque o modelo da IA.",
      placement: "top",
    },
    {
      selector: "#sidebar",
      title: "Barra lateral",
      text: "Conversas, workspace (ferramentas, logs, relatórios, mapa), master key e ajuda — tudo aqui.",
      placement: "right",
      before: async () => {
        resetPanels();
        openSidebar();
        await delay(180);
      },
    },
    {
      selector: "#sidebar-new",
      title: "Nova conversa",
      text: "Começa um chat em branco.",
      placement: "right",
    },
    {
      selector: "#btn-workspace",
      title: "Workspace",
      text: "Página da conversa: ferramentas, logs, relatórios (prévia, carteira e PDF), mapa e dashboard — só deste chat.",
      placement: "right",
    },
    {
      selector: "#btn-session-logs",
      title: "Logs",
      text: "Comandos executados nesta conversa.",
      placement: "right",
    },
    {
      selector: "#btn-session-report",
      title: "Relatório",
      text: "Pré-visualização ao vivo do PDF, carteira dos alvos e download.",
      placement: "right",
    },
    {
      selector: "#btn-master-key",
      title: "Master key",
      text: "Desbloqueia o perfil full e o modo offensive.",
      placement: "right",
    },
    {
      selector: "#offensive-mode-control",
      title: "Offensive",
      text: "Ferramentas agressivas — requer master key.",
      placement: "right",
    },
    {
      selector: "#offline-mode-control",
      title: "Offline",
      text: "Troca a Argus para Ollama local (sem OpenRouter). Ideal para lab air-gapped.",
      placement: "right",
    },
    {
      selector: "#btn-help",
      title: "Ajuda",
      text: "Reabre este tour. Atalho F1.",
      placement: "right",
    },
    {
      selector: "#btn-menu",
      title: "Menu",
      text: "Abre ou recolhe a barra lateral. Atalho M.",
      placement: "bottom",
      before: async () => resetPanels(),
    },
    {
      selector: "#btn-autopilot",
      title: "Piloto",
      text: "Missão automática: alvo + tipo de scan → PDF.",
      placement: "bottom",
    },
    {
      selector: "#btn-cancel-mission",
      title: "Parar",
      text: "Interrompe a missão em andamento.",
      placement: "bottom",
      when: () => visible($("#btn-cancel-mission")),
    },
    {
      selector: "#autopilot-target",
      title: "Alvo",
      text: "Domínio, IP ou URL autorizado.",
      placement: "bottom",
      before: async () => {
        resetPanels();
        openOverlay(ctx.overlayAutopilot);
        await delay(220);
      },
    },
    {
      selector: "#autopilot-start",
      title: "Iniciar",
      text: "A IA executa o perfil escolhido.",
      placement: "top",
    },
    {
      selector: "#status-bar",
      title: "Status",
      text: "Docker, Kali e privilégio (B ou full). Clique em priv para a master key.",
      placement: "top",
      before: async () => resetPanels(),
    },
    {
      title: "Pronto!",
      text: "Use só alvos autorizados. F1 reabre este guia.",
      centered: true,
      before: async () => resetPanels(),
    },
  ];
}

let steps = [];

function resetPanels() {
  ctx.closeAllOverlays?.();
}

function getActiveSteps() {
  return steps.filter((s) => (typeof s.when === "function" ? s.when() : true));
}

function els() {
  return {
    root: $("#guided-tour"),
    backdrop: $("#guided-tour-backdrop"),
    spotlight: $("#guided-tour-spotlight"),
    card: $("#guided-tour-card"),
    title: $("#guided-tour-title"),
    text: $("#guided-tour-text"),
    progress: $("#guided-tour-progress"),
    prev: $("#guided-tour-prev"),
    next: $("#guided-tour-next"),
    skip: $("#guided-tour-skip"),
    advanced: $("#guided-tour-advanced"),
  };
}

function positionCard(rect, placement, centered) {
  const { card } = els();
  if (!card) return;

  const margin = 14;
  const cardRect = card.getBoundingClientRect();
  let top;
  let left;

  if (centered || !rect) {
    top = Math.max(margin, (window.innerHeight - cardRect.height) / 2);
    left = Math.max(margin, (window.innerWidth - cardRect.width) / 2);
    card.style.top = `${top}px`;
    card.style.left = `${left}px`;
    card.dataset.place = "center";
    return;
  }

  left = rect.left + rect.width / 2 - cardRect.width / 2;
  left = Math.max(margin, Math.min(left, window.innerWidth - cardRect.width - margin));

  if (placement === "top" || (placement !== "bottom" && rect.top > window.innerHeight / 2)) {
    top = rect.top - cardRect.height - margin;
    card.dataset.place = "top";
  } else if (placement === "right") {
    top = rect.top;
    left = rect.right + margin;
    if (left + cardRect.width > window.innerWidth - margin) {
      left = rect.left - cardRect.width - margin;
      card.dataset.place = "left";
    } else {
      card.dataset.place = "right";
    }
  } else if (placement === "left") {
    top = rect.top;
    left = rect.left - cardRect.width - margin;
    if (left < margin) {
      left = rect.right + margin;
      card.dataset.place = "right";
    } else {
      card.dataset.place = "left";
    }
  } else {
    top = rect.bottom + margin;
    card.dataset.place = "bottom";
  }

  top = Math.max(margin, Math.min(top, window.innerHeight - cardRect.height - margin));
  card.style.top = `${top}px`;
  card.style.left = `${left}px`;
}

function positionSpotlight() {
  const activeSteps = getActiveSteps();
  const step = activeSteps[stepIndex];
  const { backdrop, spotlight } = els();
  if (!step || !backdrop || !spotlight) return;

  if (step.centered || !step.selector) {
    backdrop.hidden = false;
    spotlight.hidden = true;
    positionCard(null, null, true);
    return;
  }

  const el = spotlightTarget(step);
  if (!el) {
    backdrop.hidden = false;
    spotlight.hidden = true;
    positionCard(null, null, true);
    return;
  }

  el.scrollIntoView({ block: "nearest", behavior: "smooth" });
  const rect = el.getBoundingClientRect();
  const pad = 6;

  backdrop.hidden = true;
  spotlight.hidden = false;
  spotlight.style.top = `${Math.max(0, rect.top - pad)}px`;
  spotlight.style.left = `${Math.max(0, rect.left - pad)}px`;
  spotlight.style.width = `${rect.width + pad * 2}px`;
  spotlight.style.height = `${rect.height + pad * 2}px`;

  requestAnimationFrame(() => positionCard(rect, step.placement, false));
}

async function renderStep() {
  const activeSteps = getActiveSteps();
  const step = activeSteps[stepIndex];
  const { title, text, progress, prev, next, skip, advanced, root } = els();
  if (!step || !root) return;

  if (step.before) await step.before();

  if (title) title.textContent = step.title || "";
  if (text) text.textContent = step.text || "";
  if (progress) {
    progress.textContent = `${stepIndex + 1} / ${activeSteps.length}`;
  }
  if (prev) prev.disabled = stepIndex === 0;
  if (next) next.textContent = stepIndex === activeSteps.length - 1 ? "concluir" : "próximo";
  if (advanced) advanced.hidden = stepIndex !== activeSteps.length - 1;

  root.hidden = false;
  root.setAttribute("aria-hidden", "false");
  document.body.classList.add("guided-tour-active");

  requestAnimationFrame(() => {
    positionSpotlight();
    requestAnimationFrame(() => positionSpotlight());
  });
}

async function leaveStep() {
  const activeSteps = getActiveSteps();
  const step = activeSteps[stepIndex];
  if (step?.after) await step.after();
}

export function initGuidedTour(context) {
  ctx = context;
  steps = buildSteps();

  const { prev, next, skip, advanced, root } = els();

  prev?.addEventListener("click", async () => {
    if (stepIndex > 0) {
      await leaveStep();
      stepIndex -= 1;
      await renderStep();
    }
  });

  next?.addEventListener("click", async () => {
    const activeSteps = getActiveSteps();
    if (stepIndex < activeSteps.length - 1) {
      await leaveStep();
      stepIndex += 1;
      await renderStep();
    } else {
      stopGuidedTour();
    }
  });

  skip?.addEventListener("click", () => stopGuidedTour());

  advanced?.addEventListener("click", () => {
    stopGuidedTour();
    if (ctx.overlayHelp) openOverlay(ctx.overlayHelp);
  });

  window.addEventListener("resize", () => {
    if (active) positionSpotlight();
  });

  window.addEventListener(
    "scroll",
    () => {
      if (active) positionSpotlight();
    },
    true,
  );
}

export async function startGuidedTour() {
  if (active) return;
  active = true;
  stepIndex = 0;
  steps = buildSteps();
  document.body.classList.add("has-overlay");
  openSidebar();
  await renderStep();
}

export function stopGuidedTour() {
  if (!active) return;
  active = false;
  const { root } = els();
  leaveStep();
  resetPanels();
  if (root) {
    root.hidden = true;
    root.setAttribute("aria-hidden", "true");
  }
  document.body.classList.remove("guided-tour-active");
  if (!document.querySelector(".overlay:not([hidden])")) {
    document.body.classList.remove("has-overlay");
  }
  ctx.input?.focus();
}

export function isGuidedTourActive() {
  return active;
}
