/**
 * Tour guiado — overlay cinza, destaque no elemento e explicação em linguagem simples.
 */

import { isMobile, openOverlay, closeOverlay, openSidebar } from "./ui.js";

let ctx = {};
let stepIndex = 0;
let active = false;
let resizeObserver = null;

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

function buildSteps() {
  return [
    {
      title: "Bem-vindo ao assistente",
      text:
        "Este programa conversa com você e executa testes de segurança em sites e redes — " +
        "somente em alvos que você tem permissão para testar. " +
        "Neste tour vamos passar por cada botão e explicar, em linguagem simples, para que serve.",
      centered: true,
      before: async () => resetPanels(),
    },
    {
      selector: "#chat",
      title: "Área da conversa",
      text:
        "Aqui aparecem suas mensagens e as respostas da inteligência artificial. " +
        "Quando uma ferramenta de segurança roda, o resultado também é mostrado nesta área.",
      placement: "top",
      before: async () => resetPanels(),
    },
    {
      selector: "#input",
      title: "Campo de mensagem",
      text:
        "Digite aqui o que você quer fazer, como se estivesse conversando no WhatsApp. " +
        "Exemplo: “verifique as portas abertas em scanme.nmap.org”. Pressione Enter para enviar.",
      placement: "top",
    },
    {
      selector: "#model-trigger",
      title: "Escolha da inteligência artificial",
      text:
        "Clique aqui para trocar o “cérebro” da IA. Opções mais rápidas gastam menos; " +
        "opções mais inteligentes analisam com mais cuidado, mas demoram um pouco mais.",
      placement: "top",
    },
    {
      selector: "#sidebar",
      title: "Menu lateral — suas conversas",
      text:
        "À esquerda ficam todas as conversas salvas no navegador. " +
        "Clique em uma conversa antiga para voltar a ela; cada conversa guarda seu próprio histórico.",
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
      text:
        "Começa um chat em branco. Use quando quiser testar outro alvo ou assunto " +
        "sem misturar com a conversa anterior.",
      placement: "right",
    },
    {
      selector: "#sidebar-sessions",
      title: "Lista de conversas",
      text:
        "Cada linha é uma conversa. A conversa ativa fica destacada. " +
        "Passe o mouse (ou toque no X) para apagar uma conversa que não precisa mais.",
      placement: "right",
    },
    {
      selector: "#sidebar-help",
      title: "Ajuda no menu lateral",
      text:
        "Abre o mesmo tour guiado que você está vendo agora. Também funciona com a tecla F1 no teclado.",
      placement: "right",
    },
    {
      selector: "#btn-menu",
      title: "Menu (celular)",
      text:
        "Em telas pequenas, este botão abre e fecha o menu lateral com suas conversas.",
      placement: "bottom",
      when: () => isMobile(),
    },
    {
      selector: "#btn-tools",
      title: "Ferramentas",
      text:
        "Abre a lista de programas de segurança disponíveis (como nmap, nuclei, etc.). " +
        "Você pode deixar em automático e a IA escolhe, ou fixar uma ferramenta específica.",
      placement: "bottom",
      before: async () => resetPanels(),
    },
    {
      selector: "#tool-search",
      title: "Buscar ferramenta",
      text: "Digite o nome de uma ferramenta para filtrar a lista grande. Útil quando você já sabe o que quer usar.",
      placement: "bottom",
      before: async () => {
        await ctx.openToolsPanel?.();
        await delay(220);
      },
    },
    {
      selector: "#tool-categories",
      title: "Categorias",
      text:
        "Filtros por tipo: rede, web, enumeração, etc. Clique em uma categoria para ver só ferramentas daquele grupo.",
      placement: "bottom",
    },
    {
      selector: "#tool-list",
      title: "Lista de ferramentas",
      text:
        "Cada cartão é um programa. “auto” significa que a IA decide. “usar” coloca um exemplo no campo de mensagem " +
        "para você enviar ou editar.",
      placement: "top",
    },
    {
      selector: "#btn-autopilot",
      title: "Piloto automático",
      text:
        "Modo “faça tudo sozinho”: você informa o site/alvo e o objetivo, e o sistema executa várias etapas " +
        "sem precisar digitar cada comando. Ideal para varreduras completas.",
      placement: "bottom",
      before: async () => resetPanels(),
    },
    {
      selector: "#btn-cancel-mission",
      title: "Parar missão",
      text:
        "Quando uma missão automática está rodando, este botão vermelho “stop” aparece aqui. " +
        "Use para interromper se algo demorar demais ou você quiser cancelar.",
      placement: "bottom",
      when: () => visible($("#btn-cancel-mission")),
    },
    {
      selector: "#autopilot-target",
      title: "Alvo da missão",
      text:
        "Site ou servidor que você tem autorização para testar. " +
        "Nunca use alvos de terceiros sem permissão.",
      placement: "bottom",
      before: async () => {
        resetPanels();
        openOverlay(ctx.overlayAutopilot);
        await delay(220);
      },
    },
    {
      selector: "#autopilot-objective",
      title: "O que fazer",
      text:
        "Descreva em português o objetivo — por exemplo: “mapear portas e falhas no site”. " +
        "Ou clique numa sugestão abaixo do campo.",
      placement: "top",
    },
    {
      selector: "#autopilot-start",
      title: "Iniciar missão com IA",
      text:
        "Único botão principal: a IA planeja, executa ferramentas e gera relatório. " +
        "Roteiros fixos (sem IA) ficam opcionais em “Roteiros fixos”, se você quiser.",
      placement: "top",
    },
    {
      selector: "#btn-toolbar-more",
      title: "Mais opções (celular)",
      text:
        "Em telas pequenas, alguns botões ficam escondidos aqui. Toque para ver Intel, Arquivos e Relatório.",
      placement: "bottom",
      when: () => isMobile(),
      before: async () => resetPanels(),
    },
    {
      selector: "#btn-intel",
      title: "Intel — seus alvos e relatórios",
      text:
        "Aqui ficam os alvos testados. Você escolhe um, vê os achados, clica em Verificar e baixa o relatório.",
      placement: "bottom",
      before: async () => {
        resetPanels();
        if (isMobile()) $("#term-toolbar-extra")?.classList.add("open");
        await delay(120);
      },
    },
    {
      selector: "#hub-list",
      title: "Lista de alvos",
      text: "Clique no site/IP que você testou. Os detalhes abrem à direita.",
      placement: "right",
      before: async () => {
        await ctx.openIntelPanel?.("hub");
        await delay(280);
      },
    },
    {
      selector: "#hub-actions",
      title: "Ações do alvo",
      text:
        "Verificar = validar achados. Depois baixe Relatório .md / .html / .zip para o cliente. " +
        "Arquivos abre as saídas salvas desse alvo.",
      placement: "bottom",
    },
    {
      selector: "#btn-files",
      title: "Arquivos",
      text: "Pasta com tudo que as ferramentas salvaram em /tools/output. Separado do Intel.",
      placement: "bottom",
      before: async () => {
        resetPanels();
        if (isMobile()) $("#term-toolbar-extra")?.classList.add("open");
        await delay(120);
      },
    },
    {
      selector: "#files-list",
      title: "Lista de arquivos",
      text: "Use Abrir para ver/baixar e Excluir (duas vezes) para apagar.",
      placement: "top",
      before: async () => {
        await ctx.openFilesPanel?.();
        await delay(220);
      },
    },
    {
      selector: "#btn-threats",
      title: "Mapa mundial",
      text:
        "Mapa ao vivo de ataques no mundo (Kaspersky). É só contexto geral — não mistura com seus alvos.",
      placement: "bottom",
      before: async () => {
        resetPanels();
        if (isMobile()) $("#term-toolbar-extra")?.classList.add("open");
        await delay(100);
        await ctx.openThreatsPanel?.();
        await delay(220);
      },
    },
    {
      selector: "#btn-report",
      title: "Relatório da conversa",
      text:
        "Baixa um relatório em texto (Markdown) com o resumo desta conversa — " +
        "útil para documentar o que foi feito na sessão atual.",
      placement: "bottom",
      before: async () => {
        resetPanels();
        if (isMobile()) $("#term-toolbar-extra")?.classList.add("open");
        await delay(120);
      },
    },
    {
      selector: "#btn-new",
      title: "Novo chat (+)",
      text: "Atalho rápido para começar uma conversa nova sem abrir o menu lateral.",
      placement: "bottom",
      before: async () => resetPanels(),
    },
    {
      selector: "#btn-help",
      title: "Ajuda (este tour)",
      text:
        "O botão com “?” abre este tour guiado de novo, sempre que precisar relembrar o que cada coisa faz.",
      placement: "bottom",
      before: async () => {
        resetPanels();
        await delay(80);
      },
    },
    {
      selector: "#status-bar",
      title: "Barra de status",
      text:
        "Mostra se o Docker e o ambiente Kali estão funcionando, quantas mensagens há na conversa " +
        "e outras informações rápidas do sistema.",
      placement: "top",
      before: async () => {
        resetPanels();
        await delay(80);
      },
    },
    {
      selector: "#btn-sound",
      title: "Sons",
      text:
        "Liga ou desliga os bipes do terminal retrô. Algumas pessoas preferem silencioso em ambiente de escritório.",
      placement: "top",
    },
    {
      selector: "#btn-scroll-bottom",
      title: "Ir ao final",
      text:
        "Aparece quando você rola a conversa para cima. Clique para voltar rapidamente à mensagem mais recente.",
      placement: "top",
      when: () => {
        const el = $("#btn-scroll-bottom");
        if (visible(el)) return true;
        el?.removeAttribute("hidden");
        return true;
      },
      after: () => {
        const el = $("#btn-scroll-bottom");
        if (el && $("#chat")) {
          const nearBottom =
            $("#chat").scrollHeight - $("#chat").scrollTop - $("#chat").clientHeight < 80;
          if (nearBottom) el.hidden = true;
        }
      },
    },
    {
      title: "Pronto!",
      text:
        "Você viu os principais botões e funções. Lembre-se: use apenas em alvos autorizados. " +
        "Para uma lista técnica de atalhos de teclado, clique em “Atalhos avançados” abaixo.",
      centered: true,
      before: async () => resetPanels(),
    },
  ];
}

let steps = [];

function resetPanels() {
  ctx.closeAllOverlays?.();
  if (isMobile()) {
    $("#term-toolbar-extra")?.classList.remove("open");
  }
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

  const el = $(step.selector);
  if (!el || !visible(el)) {
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
