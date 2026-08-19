/** Modal de triagem antes do PDF — só itens duvidosos, texto curto. */

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
let autoApplied = 0;

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
        <p>Separando o que precisa da sua leitura…</p>
      </div>`;
  }
  setSkipVisible(false);
}

async function applyAutoClassifications(data) {
  if (data?.autos_persisted) {
    const n =
      (data.auto_confirmed?.length || 0) +
      (data.auto_false_positive?.length || 0) +
      (data.auto_discarded?.length || 0);
    return n;
  }
  const confirmed = Array.isArray(data.auto_confirmed) ? data.auto_confirmed : [];
  const fps = Array.isArray(data.auto_false_positive) ? data.auto_false_positive : [];
  const disc = Array.isArray(data.auto_discarded) ? data.auto_discarded : [];
  const jobs = [
    ...confirmed.map((row) => ({ ...row, status: "confirmed" })),
    ...fps.map((row) => ({ ...row, status: "false_positive" })),
    ...disc.map((row) => ({ ...row, status: "discarded" })),
  ].filter((row) => row.id);
  let ok = 0;
  await Promise.all(
    jobs.map(async (row) => {
      try {
        const res = await patchSessionFinding(sessionId, row.id, {
          surface_target: row.surface_target || "_session",
          status: row.status,
          // Não sobrescrever evidência — só status
          evidence: "",
        });
        if (res.ok) ok += 1;
      } catch {
        /* best-effort */
      }
    })
  );
  return ok;
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
  autoApplied = 0;
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
    autoApplied = await applyAutoClassifications(data);
    if (gen !== loadGen) return done;
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
            </button>
          </div>
        </div>`;
    }
    setSkipVisible(false);
  }
  return done;
}

function closeGate(ok) {
  abortCtl?.abort();
  closeOverlay(document.getElementById("overlay-triage-gate"));
  const resolve = resolveGate;
  resolveGate = null;
  resolve?.(Boolean(ok));
}

function itemsHtml(list) {
  if (!Array.isArray(list) || !list.length) return "";
  return list
    .slice(0, 3)
    .map((x) => `<li>${escapeHtml(String(x))}</li>`)
    .join("");
}

function verdictLabel(v) {
  if (v === "confirmed") return "Parece um problema real";
  if (v === "false_positive") return "Parece alarme falso";
  return "Ainda incerto";
}

function reviewFpChance(review) {
  if (review.likely_fp != null && review.likely_fp !== "") {
    return Math.max(0, Math.min(100, Number(review.likely_fp) || 0));
  }
  const conf = Number(review.confidence) || 0;
  if (review.verdict === "confirmed") return Math.max(0, Math.min(100, 100 - conf));
  if (review.verdict === "false_positive") return Math.max(0, Math.min(100, conf));
  return Math.max(0, Math.min(100, conf || 50));
}

function renderAiReviewHtml(review) {
  if (!review) {
    return `<p class="triage-ai-loading">Opinião da IA…</p>`;
  }
  if (review.source === "unavailable" || review.error) {
    return "";
  }
  const summary = review.summary
    ? escapeHtml(String(review.summary).slice(0, 280))
    : escapeHtml(verdictLabel(review.verdict));
  return `<p class="triage-ai-line">${summary}</p>`;
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
    fillAiReview({ source: "unavailable" });
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
      fillAiReview({ source: "unavailable" });
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
  const n = queue.length;
  const auto = Number(summaryData.auto_count ?? autoApplied) || autoApplied;
  el.hidden = false;
  if (!n && !auto) {
    el.innerHTML = `<p class="triage-gate-summary-line">Nada pendente — pode gerar o PDF.</p>`;
    return;
  }
  const parts = [];
  if (n) parts.push(`<strong>${n}</strong> para você decidir`);
  if (auto) parts.push(`<strong>${auto}</strong> já classificados automaticamente`);
  el.innerHTML = `<p class="triage-gate-summary-line">${parts.join(" · ")}</p>`;
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
    const pct = total ? Math.round((index / Math.max(total, 1)) * 100) : 100;
    bar.style.width = `${pct}%`;
  }
}

function renderDone(message) {
  const body = document.getElementById("triage-gate-body");
  if (!body) return;
  body.innerHTML = `
    <div class="triage-gate-done-box">
      <p class="triage-gate-done">${escapeHtml(message)}</p>
      <div class="triage-gate-actions">
        <button type="button" class="triage-choice triage-choice--yes" data-triage-generate="1">
          <strong>Gerar o PDF agora</strong>
        </button>
      </div>
    </div>`;
  setSkipVisible(false);
}

function shortBlurb(t, f) {
  const what = String(t.what_it_is || "").trim();
  if (what) return what.slice(0, 220);
  const hint = String(t.suggestion_hint || "").trim();
  if (hint) return hint;
  return "A ferramenta apontou um sinal e a automação não tem certeza se é falha real.";
}

function renderCard() {
  renderProgress();
  const body = document.getElementById("triage-gate-body");
  if (!body) return;
  if (!queue.length) {
    renderDone(
      autoApplied
        ? "Tudo que era claro já foi classificado. Pode gerar o PDF."
        : "Nada pendente nesta conversa. Pode gerar o PDF."
    );
    return;
  }
  if (index >= queue.length) {
    renderDone("Pronto. Pode gerar o PDF.");
    return;
  }
  const f = queue[index];
  const t = f.triage || {};
  const sev = String(f.severity || "info");
  const tone = sevTone(sev);
  const where = f.surface_target || f.host || "";
  const opinion =
    t.suggestion_hint ||
    t.suggestion_label ||
    "A automação não tem certeza — escolha abaixo.";

  body.innerHTML = `
    <h3 class="triage-gate-title">${escapeHtml(t.plain_title || f.title || "Achado")}</h3>
    <p class="triage-gate-meta">
      <span class="triage-sev triage-sev--${escapeHtml(tone)}">${escapeHtml(t.severity_plain || sev)}</span>
      ${f.tool ? `<span>${escapeHtml(f.tool)}</span>` : ""}
      ${where ? `<span>${escapeHtml(where)}</span>` : ""}
    </p>
    <p class="triage-gate-blurb">${escapeHtml(shortBlurb(t, f))}</p>
    <p class="triage-gate-opinion"><strong>Opinião da IA:</strong> ${escapeHtml(opinion)}</p>
    <div id="triage-ai-review" class="triage-ai-review-slim">${renderAiReviewHtml(
      f.ai_review && f.ai_review.source === "llm" ? f.ai_review : null
    )}</div>
    <div class="triage-gate-actions">
      <button type="button" class="triage-choice triage-choice--yes" data-triage-status="confirmed">
        <strong>Problema real</strong>
      </button>
      <button type="button" class="triage-choice triage-choice--no" data-triage-status="false_positive">
        <strong>Alarme falso</strong>
      </button>
      <button type="button" class="triage-choice triage-choice--maybe" data-triage-status="inconclusive">
        <strong>Não sei</strong>
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
