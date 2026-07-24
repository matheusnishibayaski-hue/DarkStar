/** Modo ofensivo global — tema vermelho + risk_profile full no Piloto. */

import { PILOT_OFFENSIVE_STORAGE_KEY } from "./constants.js";
import { toast } from "./ui.js";
import { isElevated } from "./master-key.js";

/** @type {HTMLInputElement | null} */
let toggleEl = null;
/** @type {Set<(on: boolean) => void>} */
const listeners = new Set();

export function isOffensiveModeEnabled() {
  if (!isElevated()) return false;
  if (toggleEl) return Boolean(toggleEl.checked);
  return loadOffensivePreference();
}

export function loadOffensivePreference() {
  try {
    return localStorage.getItem(PILOT_OFFENSIVE_STORAGE_KEY) === "1";
  } catch {
    return false;
  }
}

function saveOffensivePreference(on) {
  try {
    localStorage.setItem(PILOT_OFFENSIVE_STORAGE_KEY, on ? "1" : "0");
  } catch {
    /* ignore */
  }
}

export function applyOffensiveTheme(on) {
  document.documentElement.classList.toggle("mode-offensive", on);
}

export function onOffensiveModeChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function notifyListeners(on) {
  for (const fn of listeners) {
    try {
      fn(on);
    } catch {
      /* ignore */
    }
  }
}

function setOffensiveMode(on, { silent = false } = {}) {
  let enabled = Boolean(on);
  if (enabled && !isElevated()) {
    enabled = false;
    if (toggleEl) toggleEl.checked = false;
    if (!silent) {
      toast("Desbloqueie com a master key (barra lateral) para o modo offensive", "warn");
    }
  }
  if (toggleEl) toggleEl.checked = enabled;
  saveOffensivePreference(enabled);
  applyOffensiveTheme(enabled);
  notifyListeners(enabled);
  if (!silent && enabled) {
    toast("Modo ofensivo — só em alvos autorizados", "warn");
  }
}

/**
 * @param {HTMLInputElement | null} input
 */
export function initOffensiveMode(input) {
  toggleEl = input;
  if (!input) {
    applyOffensiveTheme(loadOffensivePreference() && isElevated());
    return;
  }
  const pref = loadOffensivePreference() && isElevated();
  setOffensiveMode(pref, { silent: true });
  input.addEventListener("change", () => {
    setOffensiveMode(input.checked);
  });
}

/** Aplicar tema antes do bundle (script inline no HTML). */
export function bootstrapOffensiveThemeFromStorage() {
  applyOffensiveTheme(loadOffensivePreference());
}
