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
      title: "Bem-vindo ao assistente",
      text:
        "Você está no Chat IA Kali: a assistente Kali conversa com você e roda ferramentas reais no Docker — " +
        "sempre só em alvos que você tem permissão para testar. " +
        "Este tour mostra cada área da interface em linguagem simples.",
      centered: true,
      before: async () => resetPanels(),
    },
    {
      selector: "#chat",
      title: "Área da conversa",
      text:
        "Suas mensagens e as respostas da Kali aparecem aqui. Ela age como assistente de pentest (não só lista de comandos): " +
        "explica, sugere próximos passos e mostra o resultado quando uma ferramenta roda.",
      placement: "top",
      before: async () => resetPanels(),
    },
    {
      selector: "#input",
      title: "Campo de mensagem",
      text:
        "Converse em português, como no WhatsApp. Ex.: “faça um scan leve em scanme.nmap.org e resuma”. " +
        "Enter envia · ↑/↓ recupera mensagens anteriores desta conversa.",
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
      title: "Guia no menu lateral",
      text:
        "Reabre este tour guiado. Atalhos: F1, Alt+H ou o botão ? na barra superior (fora de campos de texto).",
      placement: "right",
    },
    {
      selector: "#sidebar-collapse",
      title: "Recolher conversas",
      text:
        "No desktop, deixa a barra lateral estreita (só ícones) para ganhar espaço no chat. Atalho M.",
      placement: "right",
      when: () => !isMobile() && visible($("#sidebar-collapse")),
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
      selector: "#offensive-mode-control",
      title: "Modo offensive",
      text:
        "Switch na barra superior: interface fica vermelha e o Piloto automático pode usar perfil de risco completo " +
        "(ferramentas agressivas no scan completo/personalizado). Use só em alvos autorizados.",
      placement: "bottom",
      before: async () => {
        resetPanels();
        if (isMobile()) $("#term-toolbar-extra")?.classList.remove("open");
        await delay(80);
      },
    },
    {
      selector: "#btn-autopilot",
      title: "Piloto automático",
      text:
        "Missão em várias etapas sem digitar cada comando: você informa o alvo e o tipo de scan; a IA executa e, ao terminar, gera PDF.",
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
        "Domínio, IP ou URL que você tem autorização para testar. O objetivo técnico é definido automaticamente conforme o tipo de scan.",
      placement: "bottom",
      before: async () => {
        resetPanels();
        openOverlay(ctx.overlayAutopilot);
        await delay(220);
      },
    },
    {
      selector: "#pilot-scan-options",
      title: "Tipo de scan",
      text:
        "Básico · Intermediário · Completo · Personalizado. Em Personalizado, marque as ferramentas na grade abaixo. " +
        "Com offensive ligado, o scan Completo usa o catálogo ampliado.",
      placement: "top",
    },
    {
      selector: "#autopilot-start",
      title: "Iniciar missão",
      text:
        "A IA planeja e executa as ferramentas do perfil. Ao concluir, o PDF é salvo em Relatórios (Alt+F) e você pode triar achados no ícone de relatório ao lado do prompt.",
      placement: "top",
      before: async () => {
        if (ctx.overlayAutopilot?.hidden) {
          resetPanels();
          openOverlay(ctx.overlayAutopilot);
          await delay(180);
        }
      },
    },
    {
      selector: "#btn-toolbar-more",
      title: "Mais opções (celular)",
      text: "Em telas pequenas, abre Relatórios (PDFs baixados) e Mapa mundial.",
      placement: "bottom",
      when: () => isMobile(),
      before: async () => resetPanels(),
    },
    {
      selector: ".chat-conversation-actions",
      title: "Logs e relatório",
      text:
        "Ícones ao lado do prompt: Logs listam cada execução desta conversa; Relatório abre a triagem de achados (vulnerabilidade, falso positivo, descartar).",
      placement: "top",
      before: async () => {
        resetPanels();
        await delay(80);
      },
    },
    {
      selector: "#btn-session-logs",
      title: "Logs da conversa",
      text: "Detalhe de cada comando: horário, status e saída completa quando precisar auditar o que rodou.",
      placement: "top",
    },
    {
      selector: "#btn-session-report",
      title: "Relatório e triagem",
      text:
        "Modal largo com resumo por severidade. Classifique cada achado; nada é baixado até você clicar em Baixar PDF no rodapé. Alt+R.",
      placement: "top",
    },
    {
      selector: "#btn-files",
      title: "Biblioteca de PDFs",
      text: "Relatórios PDF que você baixou pelo chat ou pelo Piloto — salvos neste navegador (Alt+F).",
      placement: "bottom",
      before: async () => {
        resetPanels();
        if (isMobile()) $("#term-toolbar-extra")?.classList.add("open");
        await delay(120);
      },
    },
    {
      selector: "#files-list",
      title: "Seus relatórios",
      text: "Abra de novo, baixe outra cópia ou exclua entradas da biblioteca local.",
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
        "Você viu chat, ferramentas, Piloto, modo offensive, logs, triagem e PDFs. " +
        "Use só alvos autorizados. Para atalhos de teclado, clique em “Atalhos avançados” abaixo ou F1 de novo.",
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
