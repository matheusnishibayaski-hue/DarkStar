/** Biblioteca de relatórios PDF — persistidos no banco via API. */

import { apiFetch } from "./api.js";

const IDB_NAME = "chat-ia-kali-reports";
const IDB_STORE = "reports";
const MIGRATE_FLAG = "darkstar-reports-migrated-v1";

let listeners = new Set();

function uid() {
  return crypto.randomUUID?.() || `r-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

function safeFileName(title) {
  const base = (title || "relatorio-pentest")
    .replace(/[^\w\s.-áàâãéêíóôõúçÁÀÂÃÉÊÍÓÔÕÚÇ-]/gi, "")
    .trim()
    .replace(/\s+/g, "-")
    .slice(0, 60);
  return `${base || "relatorio-pentest"}.pdf`;
}

export function onReportsChanged(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function emitChange() {
  for (const fn of listeners) fn();
}

async function fetchReportBlob(id) {
  const res = await apiFetch(`/api/reports/${encodeURIComponent(id)}`);
  if (!res.ok) throw new Error("Falha ao carregar PDF.");
  return res.blob();
}

/** Migra IndexedDB legado uma vez para o banco. */
async function migrateIndexedDbOnce() {
  if (localStorage.getItem(MIGRATE_FLAG) === "1") return;
  if (!globalThis.indexedDB) {
    localStorage.setItem(MIGRATE_FLAG, "1");
    return;
  }
  try {
    const db = await new Promise((resolve, reject) => {
      const req = indexedDB.open(IDB_NAME, 1);
      req.onupgradeneeded = () => {
        const d = req.result;
        if (!d.objectStoreNames.contains(IDB_STORE)) {
          d.createObjectStore(IDB_STORE, { keyPath: "id" });
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    const rows = await new Promise((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, "readonly");
      const req = tx.objectStore(IDB_STORE).getAll();
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => reject(req.error);
    });
    for (const row of rows) {
      if (!row?.blob) continue;
      try {
        const fd = new FormData();
        fd.append("file", row.blob, row.fileName || "relatorio.pdf");
        fd.append("session_id", row.sessionId || "");
        fd.append("title", row.title || "Relatório");
        fd.append("file_name", row.fileName || "relatorio.pdf");
        await apiFetch("/api/reports", { method: "POST", body: fd });
      } catch {
        /* best-effort */
      }
    }
    db.close();
    localStorage.setItem(MIGRATE_FLAG, "1");
  } catch {
    localStorage.setItem(MIGRATE_FLAG, "1");
  }
}

export async function saveDownloadedReport({
  blob,
  sessionId = "",
  title = "",
  fileName = "",
} = {}) {
  if (!blob || !(blob instanceof Blob)) {
    throw new Error("Blob de relatório inválido.");
  }
  const name = fileName || safeFileName(title);
  const fd = new FormData();
  fd.append("file", blob, name);
  fd.append("session_id", sessionId || "");
  fd.append("title", (title || "Relatório de pentest").slice(0, 200));
  fd.append("file_name", name);
  const res = await apiFetch("/api/reports", { method: "POST", body: fd });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "Falha ao gravar PDF no banco.");
  }
  const data = await res.json();
  const meta = data.report || {};
  emitChange();
  return {
    id: meta.id || uid(),
    sessionId: meta.sessionId || sessionId || "",
    title: meta.title || title,
    fileName: meta.fileName || name,
    createdAt: meta.createdAt || Date.now(),
    size: meta.size || blob.size,
    blob,
  };
}

export async function listDownloadedReports(sessionId = null) {
  await migrateIndexedDbOnce();
  const q = sessionId
    ? `?session_id=${encodeURIComponent(sessionId)}`
    : "";
  const res = await apiFetch(`/api/reports${q}`);
  if (!res.ok) throw new Error("Falha ao listar PDFs.");
  const data = await res.json();
  const rows = data.reports || [];
  rows.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  return rows;
}

export async function deleteDownloadedReport(id) {
  if (!id) return;
  const res = await apiFetch(`/api/reports/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
  if (!res.ok && res.status !== 404) {
    throw new Error("Falha ao excluir PDF.");
  }
  emitChange();
}

export async function purgeReportsForSession(sessionId) {
  if (!sessionId) return;
  await apiFetch(`/api/reports/session/${encodeURIComponent(sessionId)}`, {
    method: "DELETE",
  }).catch(() => {});
  emitChange();
}

export async function downloadReportRecord(record) {
  if (!record?.id) return;
  const blob = record.blob || (await fetchReportBlob(record.id));
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = record.fileName || "relatorio-pentest.pdf";
  a.click();
  URL.revokeObjectURL(url);
}

export async function openReportRecord(record) {
  if (!record?.id) return;
  const blob = record.blob || (await fetchReportBlob(record.id));
  const url = URL.createObjectURL(blob);
  window.open(url, "_blank", "noopener");
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}
