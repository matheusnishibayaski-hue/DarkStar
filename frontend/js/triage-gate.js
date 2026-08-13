/** Modal de triagem antes do PDF — um achado por vez, linguagem simples. */

import { patchSessionFinding, fetchIntelTriageQueue, fetchFindingAiReview } from "./api/routes.js";
import { escapeHtml } from "./exec.js";
import { openOverlay, closeOverlay } from "./ui.js";

let toastFn = () => {};
let queue = [];
let index = 0;
let sessionId = "";
let resolveGate = null;
let busy = false;
let summaryData = {};
let abortCtl = null;
let loadGen = 0;
let reviewGen = 0;

export function initTriageGate({ toast } = {}) {
  toastFn = toast || toastFn;
  document.getElementById("triage-gate-cancel")?.addEventListener("click", () => closeGate(false));
  document.getElementById("triage-gate-skip-all")?.addEventListener("click", () => closeGate(true));
  document.getElementById("overlay-triage-gate")?.addEventListener("click", (e) => {
    if (e.target?.id === "overlay-triage-gate") closeGate(false);
  });
  document.getElementById("triage-gate-card")?.addEventListener("click", (e) => {
    const gen = e.target.closest("[data-triage-generate]");
    if (gen) {
      closeGate(true);
      return;
    }
    const btn = e.target.closest("[data-triage-status]");
    if (!btn || busy) return;
    applyStatus(btn.getAttribute("data-triage-status"));
  });
}

function slimExecutions(executions) {
  return (executions || []).slice(0, 40).map((e) => ({
    command: String(e.command || "").slice(0, 800),
    success: Boolean(e.success),
    stdout: String(e.stdout || "").slice(0, 2500),
    stderr: String(e.stderr || "").slice(0, 400),
    tool: String(e.tool || "").slice(0, 80),
    log_file_id: String(e.log_file_id || e.execution_id || "").slice(0, 120),
  }));
}

function setSkipVisible(on) {
  const btn = document.getElementById("triage-gate-skip-all");
  const foot = document.getElementById("triage-gate-foot") || btn?.closest(".triage-gate-foot");
  if (btn) {
    btn.hidden = !on;
    btn.disabled = !on;
  }
  if (foot) foot.hidden = !on;
}

function renderLoading() {
  const summary = document.getElementById("triage-gate-summary");
  const body = document.getElementById("triage-gate-body");
  const progress = document.getElementById("triage-gate-progress");
  const bar = document.getElementById("triage-gate-bar");
  if (summary) {
    summary.hidden = true;
    summary.innerHTML = "";
  }
  if (progress) progress.textContent = "…";
  if (bar) bar.style.width = "12%";
  if (body) {
    body.innerHTML = `
      <div class="triage-gate-loading" role="status">
        <p>Montando a leitura dos achados…</p>
        <p class="triage-gate-loading-hint">Isso costuma levar um instante. Você já pode cancelar.</p>
      </div>`;
  }
  setSkipVisible(false);
}

export async function runTriageGate(sid, executions = []) {
  sessionId = sid;
  const overlay = document.getElementById("overlay-triage-gate");
  if (!overlay) throw new Error("Modal de triagem não encontrado");

  abortCtl?.abort();
  abortCtl = new AbortController();
  const gen = ++loadGen;
  queue = [];
  index = 0;
  summaryData = {};
  renderLoading();
  openOverlay(overlay);

  const done = new Promise((resolve) => {
    resolveGate = resolve;
  });

  try {
    const res = await fetchIntelTriageQueue(sid, slimExecutions(executions), abortCtl.signal);
    if (gen !== loadGen) return done;
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Falha ao carregar triagem");
    }
    const data = await res.json();
    if (gen !== loadGen) return done;
    summaryData = data;
    queue = data.queue || [];
    index = 0;
    renderSummary();
    renderCard();
  } catch (e) {
    if (e?.name === "AbortError" || gen !== loadGen) return done;
    const body = document.getElementById("triage-gate-body");
    if (body) {
      body.innerHTML = `
        <div class="triage-gate-done-box">
          <p class="triage-gate-done">Não deu para montar a triagem.</p>
          <p class="triage-gate-done-hint">${escapeHtml(e.message || "Tente de novo.")}</p>
          <div class="triage-gate-actions">
            <button type="button" class="triage-choice triage-choice--maybe" data-triage-generate="1">
              <strong>Gerar o PDF mesmo assim</strong>
              <span>Sem classificar os itens desta vez</span>
            </button>
          </div>
        </div>`;
    }
    setSkipVisible(false);
  }
  return done;
}

function closeGate(proceed) {
  abortCtl?.abort();
  abortCtl = null;
  loadGen += 1;
  reviewGen += 1;
  setSkipVisible(false);
  closeOverlay(document.getElementById("overlay-triage-gate"));
  const fn = resolveGate;
  resolveGate = null;
  fn?.(Boolean(proceed));
}

function itemsHtml(arr) {
  return (arr || []).map((x) => `<li>${escapeHtml(String(x))}</li>`).join("");
}

function verdictLabel(verdict) {
  const v = String(verdict || "unsure");
  if (v === "confirmed") return "Parece um problema real";
  if (v === "false_positive") return "Parece alarme falso";
  return "Ainda incerto";
}

function renderOpinionBlock(t) {
  const sug = t.suggestion || "unsure";
  const fp = Math.max(0, Math.min(100, Number(t.likely_fp) || 0));
  const pro = itemsHtml(t.why_vulnerability);
  const contra = itemsHtml([...(t.why_false_positive || []), ...(t.reasons || [])].slice(0, 5));
  return `
    <section class="triage-opinion triage-opinion--${escapeHtml(sug)}">
      <h4>Opinião da Argus (automática)</h4>
      <p class="triage-opinion-verdict">${escapeHtml(t.suggestion_label || verdictLabel(sug))}</p>
      <p class="triage-opinion-meta">Chance de alarme falso: <strong>${fp}%</strong> — a decisão final é sua.</p>
      ${pro ? `<p class="triage-block-lead">Por que pode ser real</p><ul>${pro}</ul>` : ""}
      ${contra ? `<p class="triage-block-lead">Por que pode ser alarme falso</p><ul>${contra}</ul>` : ""}
    </section>`;
}

function renderAiReviewHtml(review) {
  if (!review) {
    return `<p class="triage-ai-loading">Segunda leitura da IA…</p>`;
  }
  if (review.source === "unavailable" || review.error) {
    return `<p class="triage-ai-miss">${escapeHtml(
      review.error || "Segunda opinião indisponível. Use a opinião automática acima."
    )}</p>`;
  }
  const reasons = itemsHtml(review.reasons);
  const summary = review.summary ? `<p>${escapeHtml(review.summary)}</p>` : "";
  return `
    <p class="triage-opinion-verdict">${escapeHtml(verdictLabel(review.verdict))}</p>
    <p class="triage-opinion-meta">Confiança da IA: <strong>${Number(review.confidence) || 0}%</strong></p>
    ${summary}
    ${reasons ? `<ul>${reasons}</ul>` : ""}
    <p class="triage-opinion-note">Isto não marca o achado sozinho.</p>`;
}

function fillAiReview(review) {
  const el = document.getElementById("triage-ai-review");
  if (!el) return;
  el.innerHTML = renderAiReviewHtml(review);
}

function requestAiReview(finding) {
  const fid = String(finding?.id || "");
  const cached = finding?.ai_review;
  if (cached && cached.source === "llm") {
    fillAiReview(cached);
    return;
  }
  if (!sessionId || !fid) {
    fillAiReview({ source: "unavailable", error: "Não foi possível pedir a segunda opinião agora." });
    return;
  }
  const gen = ++reviewGen;
  fillAiReview(null);
  fetchFindingAiReview(sessionId, fid, abortCtl?.signal)
    .then(async (res) => {
      if (gen !== reviewGen) return;
      if (!res.ok) throw new Error("falha");
      const data = await res.json();
      const review = data.ai_review || {};
      if (queue[index] && String(queue[index].id) === fid) {
        queue[index].ai_review = review;
      }
      fillAiReview(review);
    })
    .catch((e) => {
      if (e?.name === "AbortError" || gen !== reviewGen) return;
      fillAiReview({
        source: "unavailable",
        error: "Não foi possível pedir a segunda opinião agora.",
      });
    });
}

function sevTone(sev) {
  const s = String(sev || "info").toLowerCase();
  if (s === "critical") return "crit";
  if (s === "high" || s === "alto") return "high";
  if (s === "medium" || s === "medio" || s === "média") return "med";
  if (s === "low" || s === "baixo") return "low";
  return "info";
}

function renderSummary() {
  const el = document.getElementById("triage-gate-summary");
  if (!el) return;
  const sev = summaryData.severity || {};
  const risk = summaryData.risk || {};
  const n = queue.length;
  el.hidden = false;
  el.innerHTML = `
    <p>
      Vamos olhar <strong>${n}</strong> item${n === 1 ? "" : "s"} desta conversa.
      O PDF só coloca no corpo o que você marcar como problema real;
      alarme falso e “não sei” vão para o anexo.
    </p>
    <p class="triage-gate-summary-meta">
      Já confirmados hoje: risco <strong>${escapeHtml(String(risk.label || "ainda nenhum"))}</strong>
      · crítico ${sev.critical || 0}
      · grave ${sev.high || 0}
      · atenção ${sev.medium || 0}
      · leve ${sev.low || 0}
      · só info ${sev.info || 0}
    </p>`;
}

function renderProgress() {
  const progress = document.getElementById("triage-gate-progress");
  const bar = document.getElementById("triage-gate-bar");
  const total = queue.length;
  const current = total ? Math.min(index + 1, total) : 0;
  if (progress) {
    progress.textContent = total ? `${current} de ${total}` : "0 de 0";
  }
  if (bar) {
    const pct = total ? Math.round((index / total) * 100) : 0;
    bar.style.width = `${pct}%`;
  }
}

function renderDone(message) {
  const body = document.getElementById("triage-gate-body");
  if (!body) return;
  body.innerHTML = `
    <div class="triage-gate-done-box">
      <p class="triage-gate-done">${escapeHtml(message)}</p>
      <p class="triage-gate-done-hint">O relatório em PDF usa a sua classificação: problemas reais no corpo; o resto no anexo, com o motivo.</p>
      <div class="triage-gate-actions">
        <button type="button" class="triage-choice triage-choice--yes" data-triage-generate="1">
          <strong>Gerar o PDF agora</strong>
          <span>Baixa o relatório com o que você já decidiu</span>
        </button>
      </div>
    </div>`;
  setSkipVisible(false);
}

function renderCard() {
  renderProgress();
  const body = document.getElementById("triage-gate-body");
  if (!body) return;
  if (!queue.length) {
    renderDone("Nada pendente nesta conversa. Você pode gerar o PDF agora.");
    return;
  }
  if (index >= queue.length) {
    renderDone("Pronto. Você olhou todos os itens desta fila.");
    return;
  }
  const f = queue[index];
  const t = f.triage || {};
  const sev = String(f.severity || "info");
  const tone = sevTone(sev);
  const where = f.surface_target || f.host || "";
  const could = itemsHtml(t.could_happen);
  const whyFp = itemsHtml(t.why_false_positive);
  const steps = itemsHtml(t.how_to_decide);
  const second = f.second_look
    ? `<p class="triage-gate-second">Atenção: isto já tinha sido marcado como vulnerabilidade, mas parece mais alarme falso. Confira de novo antes do PDF.</p>`
    : "";
  const evidence = String(f.evidence || "").trim();
  const command = String(f.command || "").trim();

  body.innerHTML = `
    <p class="triage-gate-kicker triage-gate-kicker--${escapeHtml(t.suggestion || "unsure")}">${escapeHtml(
      t.suggestion_label || "Precisa da sua leitura"
    )}</p>
    ${t.suggestion_hint ? `<p class="triage-gate-hint">${escapeHtml(t.suggestion_hint)}</p>` : ""}
    <h3 class="triage-gate-title">${escapeHtml(t.plain_title || f.title || "Achado")}</h3>
    ${second}
    <p class="triage-gate-meta">
      <span class="triage-sev triage-sev--${tone}">${escapeHtml(t.severity_plain || sev)}</span>
      ${f.tool ? `<span>Encontrado por: ${escapeHtml(f.tool)}</span>` : ""}
      ${where ? `<span>Onde: ${escapeHtml(where)}</span>` : ""}
    </p>
    ${f.title && f.title !== t.plain_title ? `<p class="triage-gate-techname">Nome técnico: ${escapeHtml(f.title)}</p>` : ""}

    <section class="triage-block">
      <h4>O que é isto, em palavras simples</h4>
      <p>${escapeHtml(t.what_it_is || "A ferramenta apontou um sinal. Scanners erram — por isso pedimos a sua leitura.")}</p>
    </section>

    ${
      t.everyday
        ? `<section class="triage-block triage-block--analogy">
      <h4>Uma analogia do dia a dia</h4>
      <p>${escapeHtml(t.everyday)}</p>
    </section>`
        : ""
    }

    <section class="triage-block">
      <h4>Por que isto importa</h4>
      <p>${escapeHtml(t.why_it_matters || "")}</p>
      ${could ? `<p class="triage-block-lead">Se for verdade, o que pode acontecer:</p><ul>${could}</ul>` : ""}
    </section>

    <section class="triage-block triage-block--fp">
      <h4>Por que pode ser só um alarme falso</h4>
      <ul>${whyFp || "<li>Scanners automáticos gritam fácil. Sem prova na evidência, não trate como ataque.</li>"}</ul>
    </section>

    <section class="triage-block">
      <h4>Como decidir (mesmo sem ser técnico)</h4>
      <ol>${steps || "<li>Se a evidência mostra o problema de forma clara no alvo autorizado, é real. Se não completou ou foi bloqueado, escolha incerto.</li>"}</ol>
    </section>

    ${renderOpinionBlock(t)}

    <section class="triage-opinion triage-opinion--ai" id="triage-ai-box">
      <h4>Segunda opinião (IA)</h4>
      <div id="triage-ai-review">${renderAiReviewHtml(f.ai_review && f.ai_review.source === "llm" ? f.ai_review : null)}</div>
    </section>

    ${
      evidence || command
        ? `<details class="triage-evidence">
      <summary>Ver o detalhe técnico (evidência)</summary>
      ${command ? `<p class="triage-gate-cmd">Comando: <code>${escapeHtml(command.slice(0, 400))}</code></p>` : ""}
      ${evidence ? `<pre class="triage-gate-evidence">${escapeHtml(evidence.slice(0, 1400))}</pre>` : ""}
    </details>`
        : ""
    }

    <p class="triage-gate-ask">O que você quer que o PDF diga sobre isto?</p>
    <div class="triage-gate-actions">
      <button type="button" class="triage-choice triage-choice--yes" data-triage-status="confirmed">
        <strong>É um problema real</strong>
        <span>Entra no corpo do relatório como vulnerabilidade</span>
      </button>
      <button type="button" class="triage-choice triage-choice--no" data-triage-status="false_positive">
        <strong>É alarme falso</strong>
        <span>Não assusta o cliente; vai só no anexo</span>
      </button>
      <button type="button" class="triage-choice triage-choice--maybe" data-triage-status="inconclusive">
        <strong>Ainda não sei</strong>
        <span>Fica no anexo como incerto, nada some</span>
      </button>
    </div>`;
  setSkipVisible(true);
  requestAiReview(f);
}

async function applyStatus(status) {
  const f = queue[index];
  if (!f || !sessionId) return;
  busy = true;
  const card = document.getElementById("triage-gate-card");
  card?.querySelectorAll("[data-triage-status]").forEach((b) => {
    b.disabled = true;
  });
  try {
    const res = await patchSessionFinding(sessionId, f.id, {
      surface_target: f.surface_target || f.host || "_session",
      status,
      evidence: `triage-gate:${status}`,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Falha ao salvar");
    }
    index += 1;
    if (index >= queue.length) {
      renderCard();
      toastFn?.("Triagem concluída", "success");
    } else {
      renderCard();
    }
  } catch (e) {
    toastFn?.(e.message || "Erro ao classificar", "error");
    card?.querySelectorAll("[data-triage-status]").forEach((b) => {
      b.disabled = false;
    });
  } finally {
    busy = false;
  }
}
