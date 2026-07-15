/** Atalhos globais — Alt+* evita conflito com Chrome/Edge (Ctrl+T, Ctrl+R, etc.). */

let handlers = {};

export function initShortcuts(h) {
  handlers = h;
}

function run(fn) {
  if (typeof fn === "function") fn();
}

export function handleGlobalKeydown(e) {
  const el = e.target;
  const tag = el?.tagName;
  const inField = tag === "INPUT" || tag === "TEXTAREA" || el?.isContentEditable;
  const mod = e.ctrlKey || e.metaKey;
  const alt = e.altKey;
  const key = e.key.toLowerCase();

  if (e.key === "Escape") {
    run(handlers.onEscape);
    return;
  }

  // Alt+ — funciona mesmo dentro de inputs (exceto password em alguns browsers)
  if (alt && !mod) {
    const altActions = {
      t: handlers.openTools,
      p: handlers.openPilot,
      r: handlers.downloadReport,
      n: handlers.newChat,
      h: handlers.openHelp,
      i: handlers.openIntel,
      c: handlers.openThreats,
      f: handlers.openFiles,
      k: handlers.focusInput,
    };
    if (altActions[key]) {
      e.preventDefault();
      run(altActions[key]);
      return;
    }
  }

  // Ctrl+Shift+ — alternativa documentada
  if (mod && e.shiftKey && !alt) {
    const csActions = {
      t: handlers.openTools,
      p: handlers.openPilot,
      e: handlers.downloadReport,
      n: handlers.newChat,
    };
    if (csActions[key]) {
      e.preventDefault();
      run(csActions[key]);
      return;
    }
  }

  if (mod && !e.shiftKey && !alt) {
    if (key === "k") {
      e.preventDefault();
      run(handlers.focusInput);
      return;
    }
    if (key === "/" || e.key === "?") {
      e.preventDefault();
      run(handlers.openHelp);
      return;
    }
  }

  if (e.key === "F1") {
    e.preventDefault();
    run(handlers.openHelp);
    return;
  }

  if ((key === "m" || key === "?") && !mod && !alt && !inField) {
    if (key === "m") {
      e.preventDefault();
      run(handlers.toggleSidebar);
    } else if (e.key === "?") {
      e.preventDefault();
      run(handlers.openHelp);
    }
  }
}
