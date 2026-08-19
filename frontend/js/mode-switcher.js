/**
 * Seletor visual de modos (anjo / diabo / agente) no titlebar do chat.
 */

import { isElevated, openMasterKeyModal } from "./master-key.js";
import {
  isOffensiveModeEnabled,
  setOffensiveMode,
  onOffensiveModeChange,
} from "./offensive-mode.js";
import {
  isOfflineModeEnabled,
  setOfflineMode,
  onOfflineModeChange,
} from "./offline-mode.js";

/** @typedef {"safe" | "offensive" | "offline"} ChatVisualMode */

function currentMode() {
  if (isOfflineModeEnabled()) return "offline";
  if (isOffensiveModeEnabled()) return "offensive";
  return "safe";
}

function syncActiveButtons() {
  const mode = currentMode();
  document.querySelectorAll("[data-chat-visual-mode]").forEach((btn) => {
    const active = btn.getAttribute("data-chat-visual-mode") === mode;
    btn.classList.toggle("is-active", active);
    btn.setAttribute("aria-pressed", active ? "true" : "false");
  });
}

/**
 * @param {ChatVisualMode} mode
 */
async function selectMode(mode) {
  if (mode === "safe") {
    setOffensiveMode(false, { silent: true });
    await setOfflineMode(false, { silent: true });
    syncActiveButtons();
    return;
  }

  if (mode === "offensive") {
    if (!isElevated()) {
      syncActiveButtons();
      openMasterKeyModal();
      return;
    }
    await setOfflineMode(false, { silent: true });
    setOffensiveMode(true);
    syncActiveButtons();
    return;
  }

  if (mode === "offline") {
    setOffensiveMode(false, { silent: true });
    await setOfflineMode(true);
    syncActiveButtons();
  }
}

export function initModeSwitcher() {
  const root = document.getElementById("chat-mode-switcher");
  if (!root) return;

  root.querySelectorAll("[data-chat-visual-mode]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const mode = btn.getAttribute("data-chat-visual-mode");
      if (mode === "safe" || mode === "offensive" || mode === "offline") {
        void selectMode(mode);
      }
    });
  });

  onOffensiveModeChange(() => syncActiveButtons());
  onOfflineModeChange(() => syncActiveButtons());
  syncActiveButtons();
}

export function refreshModeSwitcher() {
  syncActiveButtons();
}
