/**
 * Seletor de workspace multi-cliente (sidebar).
 */

import { apiFetch } from "./api.js";
import { toast } from "./ui.js";

const STORAGE_KEY = "darkstar.active_client_id";

let activeClientId = localStorage.getItem(STORAGE_KEY) || "default";
let clientsCache = [];
let createInFlight = false;

export function getActiveClientId() {
  return activeClientId || "default";
}

async function parseJson(res) {
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = data.detail || data.message || res.statusText;
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return data;
}

function nameToSlug(name) {
  const map = {
    á: "a",
    à: "a",
    â: "a",
    ã: "a",
    ä: "a",
    é: "e",
    ê: "e",
    è: "e",
    í: "i",
    ó: "o",
    ô: "o",
    õ: "o",
    ö: "o",
    ú: "u",
    ü: "u",
    ç: "c",
    ñ: "n",
  };
  let s = (name || "").trim().toLowerCase();
  s = s.replace(/[áàâãäéêèíóôõöúüçñ]/g, (ch) => map[ch] || ch);
  s = s.replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return s.slice(0, 64).replace(/-+$/g, "") || "cliente";
}

function uniqueSlug(base) {
  const taken = new Set(clientsCache.map((c) => c.client_id));
  if (!taken.has(base)) return base;
  for (let i = 2; i < 1000; i += 1) {
    const candidate = `${base.slice(0, 60)}-${i}`;
    if (!taken.has(candidate)) return candidate;
  }
  return `${base.slice(0, 50)}-${Date.now().toString(36)}`;
}

async function loadClients() {
  try {
    const res = await apiFetch("/api/clients");
    const data = await parseJson(res);
    clientsCache = data.clients || [];
    if (data.active_client_id) {
      activeClientId = data.active_client_id;
      localStorage.setItem(STORAGE_KEY, activeClientId);
    }
    renderSelect();
  } catch (err) {
    console.warn("clients_load_failed", err);
  }
}

function renderSelect() {
  const sel = document.getElementById("client-workspace-select");
  const delBtn = document.getElementById("client-workspace-del");
  if (!sel) return;
  const prev = activeClientId;
  sel.innerHTML = "";
  for (const c of clientsCache) {
    const opt = document.createElement("option");
    opt.value = c.client_id;
    const n = c.targets_count ?? (c.targets || []).length;
    opt.textContent = `${c.display_name || c.client_id} (${n})`;
    if (c.client_id === prev) opt.selected = true;
    sel.appendChild(opt);
  }
  if (!sel.options.length) {
    const opt = document.createElement("option");
    opt.value = "default";
    opt.textContent = "Padrão";
    sel.appendChild(opt);
  }
  if (delBtn) {
    delBtn.disabled = (sel.value || "default") === "default";
    delBtn.title =
      sel.value === "default"
        ? "Cliente padrão não pode ser excluído"
        : "Excluir cliente ativo";
  }
}

async function activateClient(clientId) {
  try {
    const res = await apiFetch(`/api/clients/${encodeURIComponent(clientId)}/activate`, {
      method: "POST",
    });
    const data = await parseJson(res);
    activeClientId = data.active_client_id || clientId;
    localStorage.setItem(STORAGE_KEY, activeClientId);
    toast(`Cliente ativo: ${activeClientId}`, "ok");
    renderSelect();
    window.dispatchEvent(
      new CustomEvent("darkstar:client-changed", { detail: { clientId: activeClientId } })
    );
  } catch (err) {
    toast(err.message || "Falha ao ativar cliente", "err");
  }
}

function openCreateModal() {
  const overlay = document.getElementById("overlay-client-new");
  const input = document.getElementById("client-new-name");
  if (!overlay) return;
  overlay.hidden = false;
  if (input) {
    input.value = "";
    requestAnimationFrame(() => input.focus());
  }
}

function closeCreateModal() {
  const overlay = document.getElementById("overlay-client-new");
  if (overlay) overlay.hidden = true;
}

async function submitCreateClient(nameRaw) {
  if (createInFlight) return;
  const name = (nameRaw || "").trim();
  if (!name) {
    toast("Informe o nome do cliente", "err");
    return;
  }
  const id = uniqueSlug(nameToSlug(name));
  createInFlight = true;
  const submitBtn = document.getElementById("client-new-submit");
  if (submitBtn) submitBtn.disabled = true;
  try {
    const res = await apiFetch("/api/clients", {
      method: "POST",
      body: JSON.stringify({
        client_id: id,
        display_name: name.slice(0, 200),
      }),
    });
    if (res.status === 409) {
      toast(`Cliente já existe — ativando`, "ok");
      closeCreateModal();
      await loadClients();
      await activateClient(id);
      return;
    }
    await parseJson(res);
    closeCreateModal();
    toast("Cliente criado", "ok");
    await loadClients();
    await activateClient(id);
  } catch (err) {
    toast(err.message || "Falha ao criar cliente", "err");
  } finally {
    createInFlight = false;
    if (submitBtn) submitBtn.disabled = false;
  }
}

async function deleteClient() {
  const sel = document.getElementById("client-workspace-select");
  const id = (sel?.value || activeClientId || "").trim();
  if (!id || id === "default") {
    toast("Cliente padrão não pode ser excluído", "err");
    return;
  }
  const purge = confirm(
    `Excluir o cliente "${id}"?\n\nOK = apaga workspace e engajamentos\nCancelar = aborta`
  );
  if (!purge) return;
  try {
    const res = await apiFetch(
      `/api/clients/${encodeURIComponent(id)}?purge_surfaces=true`,
      { method: "DELETE" }
    );
    const data = await parseJson(res);
    activeClientId = data.active_client_id || "default";
    localStorage.setItem(STORAGE_KEY, activeClientId);
    toast(`Cliente "${id}" excluído`, "ok");
    await loadClients();
    window.dispatchEvent(
      new CustomEvent("darkstar:client-changed", { detail: { clientId: activeClientId } })
    );
  } catch (err) {
    toast(err.message || "Falha ao excluir cliente", "err");
  }
}

export function initClientWorkspace() {
  const sel = document.getElementById("client-workspace-select");
  const btn = document.getElementById("client-workspace-new");
  const del = document.getElementById("client-workspace-del");
  const overlay = document.getElementById("overlay-client-new");
  const form = document.getElementById("client-new-form");
  const cancel = document.getElementById("client-new-cancel");

  if (sel) {
    sel.addEventListener("change", () => activateClient(sel.value));
  }
  if (btn) {
    btn.addEventListener("click", () => openCreateModal());
  }
  if (del) {
    del.addEventListener("click", () => deleteClient());
  }
  if (form) {
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const input = document.getElementById("client-new-name");
      submitCreateClient(input?.value || "");
    });
  }
  if (cancel) {
    cancel.addEventListener("click", () => closeCreateModal());
  }
  if (overlay) {
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) closeCreateModal();
    });
  }
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && overlay && !overlay.hidden) {
      closeCreateModal();
    }
  });
  loadClients();
}
