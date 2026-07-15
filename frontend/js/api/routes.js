/** Camada centralizada de rotas da API. */

import { apiFetch } from "../api.js";

export function getHealth() {
  return apiFetch("/api/health");
}

export function getClientConfig() {
  return apiFetch("/api/client-config");
}

export function listRecon() {
  return apiFetch("/api/recon");
}

export function getReconDetail(target) {
  return apiFetch(`/api/recon/${encodeURIComponent(target)}`);
}

export function listFiles() {
  return apiFetch("/api/files");
}

export function listAudit(params = {}) {
  const q = new URLSearchParams(params).toString();
  return apiFetch(`/api/audit${q ? `?${q}` : ""}`);
}

export function listPlaybooks() {
  return apiFetch("/api/playbooks");
}

export function runPlaybook(id, body) {
  return apiFetch(`/api/playbooks/${encodeURIComponent(id)}/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export function getLog(logId) {
  return apiFetch(`/api/logs/${logId}`);
}
