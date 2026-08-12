/**
 * Seletor de workspace multi-cliente (sidebar).
 */

import { apiFetch } from "./api.js";
import { toast } from "./ui.js";

const STORAGE_KEY = "darkstar.active_client_id";

let activeClientId = localStorage.getItem(STORAGE_KEY) || "default";
let clientsCache = [];

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

async function createClient() {
  const id = prompt("ID do cliente (slug, ex: empresa-xyz):");
  if (!id) return;
  const name = prompt("Nome de exibição:", id) || id;
  try {
    const res = await apiFetch("/api/clients", {
      method: "POST",
      body: JSON.stringify({
        client_id: id.trim().toLowerCase(),
        display_name: name.trim(),
      }),
    });
    await parseJson(res);
    toast("Cliente criado", "ok");
    await loadClients();
    await activateClient(id.trim().toLowerCase());
  } catch (err) {
    toast(err.message || "Falha ao criar cliente", "err");
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
  if (sel) {
    sel.addEventListener("change", () => activateClient(sel.value));
  }
  if (btn) {
    btn.addEventListener("click", () => createClient());
  }
  if (del) {
    del.addEventListener("click", () => deleteClient());
  }
  loadClients();
}
