/** Master key DarkStar — perfil B (restrito) vs full. */

import { apiFetch } from "./api.js";
import { toast } from "./ui.js";

let elevated = false;
let profileLabel = "B (restrito)";
let onChange = null;

export function isElevated() {
  return elevated;
}

export function getProfileLabel() {
  return profileLabel;
}

export function initMasterKey(handlers = {}) {
  onChange = handlers.onChange || null;
  const overlay = document.getElementById("overlay-master-key");
  const btnOpen = document.getElementById("btn-master-key");
  const btnSubmit = document.getElementById("master-key-submit");
  const btnLock = document.getElementById("master-key-lock");
  const btnCancel = document.getElementById("master-key-cancel");
  const input = document.getElementById("master-key-input");

  btnOpen?.addEventListener("click", () => openMasterKeyModal());
  btnCancel?.addEventListener("click", () => closeMasterKeyModal());
  document.getElementById("status-pill-privilege")?.addEventListener("click", () => openMasterKeyModal());
  overlay?.addEventListener("click", (e) => {
    if (e.target === overlay) closeMasterKeyModal();
  });
  btnSubmit?.addEventListener("click", () => submitMasterKey());
  btnLock?.addEventListener("click", () => lockMasterKey());
  input?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      submitMasterKey();
    }
  });

  refreshPrivilegeStatus();
}

export function openMasterKeyModal() {
  const overlay = document.getElementById("overlay-master-key");
  const input = document.getElementById("master-key-input");
  const status = document.getElementById("master-key-status");
  if (!overlay) return;
  overlay.hidden = false;
  requestAnimationFrame(() => overlay.classList.add("overlay-visible"));
  document.body.classList.add("has-overlay");
  if (status) {
    status.textContent = elevated
      ? `Perfil atual: ${profileLabel}. Informe outra key ou bloqueie abaixo.`
      : "Perfil B (restrito). Digite a master key para liberar permissão total.";
  }
  if (input) {
    input.value = "";
    input.focus();
  }
  const lockBtn = document.getElementById("master-key-lock");
  if (lockBtn) lockBtn.hidden = !elevated;
}

export function closeMasterKeyModal() {
  const overlay = document.getElementById("overlay-master-key");
  if (!overlay) return;
  overlay.classList.remove("overlay-visible");
  overlay.hidden = true;
  if (!document.querySelector(".overlay:not([hidden])")) {
    document.body.classList.remove("has-overlay");
  }
}

async function refreshPrivilegeStatus() {
  try {
    const res = await apiFetch("/api/auth/privilege");
    if (!res.ok) return;
    const data = await res.json();
    applyPrivilege(data);
  } catch { /* ignore */ }
}

function applyPrivilege(data) {
  elevated = Boolean(data?.elevated);
  profileLabel = data?.profile_label || (elevated ? "full (master key)" : "B (restrito)");
  updatePrivilegeUi();
  onChange?.(elevated, profileLabel);
}

function updatePrivilegeUi() {
  const pill = document.getElementById("status-pill-privilege");
  const btn = document.getElementById("btn-master-key");
  if (pill) {
    pill.textContent = elevated ? "priv:full" : "priv:B";
    pill.title = elevated ? `${profileLabel} — clique para gerenciar` : "Perfil B — clique para desbloquear";
    pill.classList.toggle("status-ok", elevated);
    pill.classList.toggle("status-warn", !elevated);
    pill.style.cursor = "pointer";
  }
  if (btn) {
    const label = btn.querySelector("[data-key-label]");
    const text = elevated ? "master key · full" : "master key";
    if (label) label.textContent = text;
    btn.title = elevated
      ? "Master key ativa — clique para gerenciar"
      : "Master key — desbloquear perfil full";
    btn.classList.toggle("term-btn--active", elevated);
  }
  document.documentElement.classList.toggle("mode-elevated", elevated);
}

async function submitMasterKey() {
  const input = document.getElementById("master-key-input");
  const key = (input?.value || "").trim();
  if (!key) {
    toast("Informe a master key");
    input?.focus();
    return;
  }
  try {
    const res = await apiFetch("/api/auth/master-key", {
      method: "POST",
      body: JSON.stringify({ key }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      toast(data.detail || "Master key inválida");
      return;
    }
    applyPrivilege(data);
    toast("Perfil full desbloqueado");
    closeMasterKeyModal();
  } catch {
    toast("Falha ao validar master key");
  }
}

async function lockMasterKey() {
  try {
    const res = await apiFetch("/api/auth/master-key/lock", { method: "POST" });
    const data = await res.json().catch(() => ({}));
    applyPrivilege(data.ok ? data : { elevated: false, profile_label: "B (restrito)" });
    toast("Voltou ao perfil B");
    closeMasterKeyModal();
  } catch {
    toast("Falha ao bloquear");
  }
}

export { refreshPrivilegeStatus };
