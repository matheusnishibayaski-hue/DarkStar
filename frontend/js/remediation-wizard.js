/**
 * Wizard de remediação inteligente (overlay no shell).
 */

import { apiFetch } from "./api.js";
import { openOverlay, closeOverlay, toast } from "./ui.js";

let currentPlan = null;
let currentFindingId = "";

function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function updateProgress() {
  const cards = document.querySelectorAll(".remediation-step");
  const done = document.querySelectorAll(".remediation-step.is-done");
  const total = cards.length;
  const n = done.length;
  const fill = document.getElementById("remediation-progress-fill");
  const label = document.getElementById("remediation-progress-label");
  if (fill) fill.style.width = total ? `${(100 * n) / total}%` : "0%";
  if (label) label.textContent = `${n}/${total} passos`;
}

function renderPlan(plan) {
  currentPlan = plan;
  const root = document.getElementById("remediation-root-cause");
  const stepsEl = document.getElementById("remediation-steps");
  const before = document.getElementById("remediation-code-before");
  const after = document.getElementById("remediation-code-after");
  const testCmd = document.getElementById("remediation-test-cmd");
  const deploy = document.getElementById("remediation-deploy");
  const meta = document.getElementById("remediation-meta");
  const refs = document.getElementById("remediation-refs");
  const title = document.getElementById("remediation-title");
  const sev = document.getElementById("remediation-severity");

  if (title) title.textContent = plan.vulnerability_title || "Remediação";
  if (sev) {
    sev.textContent = String(plan.severity || "?").toUpperCase();
    sev.className = `remediation-sev remediation-sev--${String(plan.severity || "info").toLowerCase()}`;
  }
  if (root) root.textContent = plan.root_cause || "—";
  if (before) before.textContent = plan.code_before || "(sem snippet)";
  if (after) after.textContent = plan.code_after || "(sem snippet)";
  if (testCmd) testCmd.textContent = plan.test_command || "(nenhum)";
  if (deploy) deploy.textContent = plan.deployment_notes || "Reteste antes de produção.";
  if (meta) {
    meta.innerHTML = `
      <span>dificuldade: <b>${escapeHtml(plan.difficulty || "—")}</b></span>
      <span>tempo: <b>${escapeHtml(String(plan.estimated_time_minutes ?? "—"))} min</b></span>
      <span>confiança: <b>${escapeHtml(plan.confidence || String(Math.round((plan.confidence_score || 0) * 100) + "%"))}</b></span>
      <span>fonte: <b>${escapeHtml(plan.source || "—")}</b></span>`;
  }
  if (refs) {
    const list = plan.references || [];
    refs.innerHTML = list.length
      ? list.map((u) => `<li><a href="${escapeHtml(u)}" target="_blank" rel="noopener">${escapeHtml(u)}</a></li>`).join("")
      : "<li>—</li>";
  }
  if (stepsEl) {
    const steps = plan.steps || [];
    stepsEl.innerHTML = steps
      .map(
        (s, i) => `
      <div class="remediation-step" data-step-idx="${i}">
        <div class="remediation-step-head">
          <span class="remediation-step-num">${escapeHtml(String(s.step_number ?? i + 1))}</span>
          <strong>${escapeHtml(s.title || "")}</strong>
        </div>
        <p class="remediation-step-desc">${escapeHtml(s.description || "")}</p>
        ${
          s.command
            ? `<pre class="remediation-code"><code>${escapeHtml(s.command)}</code>
               <button type="button" class="term-btn remediation-copy" data-copy>copiar</button></pre>`
            : ""
        }
        ${s.notes ? `<p class="remediation-note">${escapeHtml(s.notes)}</p>` : ""}
        <button type="button" class="term-btn remediation-step-done" data-toggle-step>marcar feito</button>
      </div>`
      )
      .join("");
    stepsEl.querySelectorAll("[data-toggle-step]").forEach((btn) => {
      btn.addEventListener("click", () => {
        btn.closest(".remediation-step")?.classList.toggle("is-done");
        updateProgress();
        syncTrackProgress();
      });
    });
    stepsEl.querySelectorAll("[data-copy]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const code = btn.parentElement?.querySelector("code")?.textContent || "";
        try {
          await navigator.clipboard.writeText(code);
          toast("copiado", "success");
        } catch {
          toast("falha ao copiar", "error");
        }
      });
    });
  }
  updateProgress();
}

async function syncTrackProgress() {
  if (!currentFindingId || !currentPlan) return;
  const done = document.querySelectorAll(".remediation-step.is-done").length;
  const total = document.querySelectorAll(".remediation-step").length;
  const status = total && done >= total ? "completed" : "in_progress";
  try {
    await apiFetch(`/api/remediation/track/${encodeURIComponent(currentFindingId)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status, steps_completed: done }),
    });
  } catch {
    /* ignore */
  }
}

export async function openRemediationWizard(finding) {
  const body = document.getElementById("remediation-body");
  const loading = document.getElementById("remediation-loading");
  openOverlay(document.getElementById("overlay-remediation"));
  currentFindingId = String(finding?.id || finding?.title || "unknown");
  if (loading) loading.hidden = false;
  if (body) body.hidden = true;
  try {
    const res = await apiFetch("/api/remediation/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ finding: finding || {} }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "falha ao gerar plano");
    const plan = data.plan || {};
    renderPlan(plan);
    await apiFetch("/api/remediation/track", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        finding_id: currentFindingId,
        remediation_plan: plan,
        status: "in_progress",
      }),
    });
    if (loading) loading.hidden = true;
    if (body) body.hidden = false;
  } catch (err) {
    if (loading) {
      loading.hidden = false;
      loading.textContent = err.message || "erro";
    }
    toast(err.message || "falha na remediação", "error");
  }
}

export function initRemediationWizard() {
  document.getElementById("remediation-close")?.addEventListener("click", () => {
    closeOverlay(document.getElementById("overlay-remediation"));
  });
  document.getElementById("remediation-mark-resolved")?.addEventListener("click", async () => {
    document.querySelectorAll(".remediation-step").forEach((el) => el.classList.add("is-done"));
    updateProgress();
    if (!currentFindingId) return;
    try {
      await apiFetch(`/api/remediation/track/${encodeURIComponent(currentFindingId)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          status: "completed",
          steps_completed: document.querySelectorAll(".remediation-step").length,
          notes: "marked resolved in wizard",
        }),
      });
      toast("remediação marcada como resolvida", "success");
    } catch (e) {
      toast(e.message || "falha", "error");
    }
  });
}
