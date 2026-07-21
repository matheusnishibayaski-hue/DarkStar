/** Biblioteca local de relatórios PDF baixados (IndexedDB). */

const DB_NAME = "chat-ia-kali-reports";
const DB_VERSION = 1;
const STORE = "reports";

let listeners = new Set();

function openDb() {
  return new Promise((resolve, reject) => {
    if (!globalThis.indexedDB) {
      reject(new Error("IndexedDB indisponível neste navegador."));
      return;
    }
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE, { keyPath: "id" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error("Falha ao abrir armazenamento."));
  });
}

function txDone(tx) {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error || new Error("Transação abortada."));
  });
}

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

export async function saveDownloadedReport({
  blob,
  sessionId = "",
  title = "",
  fileName = "",
} = {}) {
  if (!blob || !(blob instanceof Blob)) {
    throw new Error("Blob de relatório inválido.");
  }
  const db = await openDb();
  const id = uid();
  const record = {
    id,
    sessionId: sessionId || "",
    title: (title || "Relatório de pentest").slice(0, 200),
    fileName: fileName || safeFileName(title),
    createdAt: Date.now(),
    size: blob.size,
    blob,
  };
  const tx = db.transaction(STORE, "readwrite");
  tx.objectStore(STORE).put(record);
  await txDone(tx);
  db.close();
  emitChange();
  return record;
}

export async function listDownloadedReports() {
  const db = await openDb();
  const tx = db.transaction(STORE, "readonly");
  const req = tx.objectStore(STORE).getAll();
  const rows = await new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
  await txDone(tx);
  db.close();
  rows.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  return rows;
}

export async function deleteDownloadedReport(id) {
  if (!id) return;
  const db = await openDb();
  const tx = db.transaction(STORE, "readwrite");
  tx.objectStore(STORE).delete(id);
  await txDone(tx);
  db.close();
  emitChange();
}

export function downloadReportRecord(record) {
  if (!record?.blob) return;
  const url = URL.createObjectURL(record.blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = record.fileName || "relatorio-pentest.pdf";
  a.click();
  URL.revokeObjectURL(url);
}

export function openReportRecord(record) {
  if (!record?.blob) return;
  const url = URL.createObjectURL(record.blob);
  window.open(url, "_blank", "noopener");
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}
