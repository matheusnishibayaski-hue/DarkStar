/** Autenticação por sessão HttpOnly (substitui token fixo no localStorage). */

export async function ensureAuth(toast) {
  try {
    const cfgRes = await fetch("/api/client-config", { credentials: "include" });
    if (!cfgRes.ok) return true;
    const cfg = await cfgRes.json();
    if (!cfg.authRequired) return true;

    const sessionRes = await fetch("/api/auth/session", { credentials: "include" });
    if (!sessionRes.ok) return false;
    const session = await sessionRes.json();
    if (session.authenticated) return true;

    return showLoginOverlay(toast);
  } catch {
    return false;
  }
}

function showLoginOverlay(toast) {
  return new Promise((resolve) => {
    const overlay = document.getElementById("overlay-login");
    const input = document.getElementById("login-token");
    const submit = document.getElementById("login-submit");
    const cancel = document.getElementById("login-cancel");

    if (!overlay || !input || !submit) {
      toast?.("API protegida — configure CHAT_API_TOKEN e faça login.", "warn");
      resolve(false);
      return;
    }

    overlay.hidden = false;
    requestAnimationFrame(() => overlay.classList.add("overlay-visible"));
    document.body.classList.add("has-overlay");
    input.value = "";
    input.focus();

    const cleanup = () => {
      overlay.classList.remove("overlay-visible");
      overlay.hidden = true;
      document.body.classList.remove("has-overlay");
      submit.removeEventListener("click", onSubmit);
      cancel?.removeEventListener("click", onCancel);
      input.removeEventListener("keydown", onKey);
    };

    const onCancel = () => {
      cleanup();
      resolve(false);
    };

    const onSubmit = async () => {
      const token = input.value.trim();
      if (!token) {
        toast?.("Informe o token de API.", "warn");
        return;
      }

      submit.disabled = true;
      try {
        const res = await fetch("/api/auth/login", {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token }),
        });
        if (!res.ok) {
          const err = await res.json().catch(() => ({}));
          toast?.(err.detail || "Token inválido.", "error");
          return;
        }
        cleanup();
        toast?.("Sessão iniciada.", "success");
        resolve(true);
      } catch (e) {
        toast?.(`Erro de login: ${e.message}`, "error");
      } finally {
        submit.disabled = false;
      }
    };

    const onKey = (e) => {
      if (e.key === "Enter") onSubmit();
      if (e.key === "Escape") onCancel();
    };

    submit.addEventListener("click", onSubmit);
    cancel?.addEventListener("click", onCancel);
    input.addEventListener("keydown", onKey);
  });
}

export async function cancelMission(missionId) {
  if (!missionId) return;
  await fetch(`/api/missions/${encodeURIComponent(missionId)}/cancel`, {
    method: "POST",
    credentials: "include",
    headers: apiHeaders(),
  });
}

function apiHeaders() {
  const headers = {};
  const legacy = localStorage.getItem("chat-ia-kali-api-token");
  if (legacy) headers["X-Chat-Token"] = legacy;
  return headers;
}
