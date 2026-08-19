/**
 * Regras compartilhadas de ingest de repositório (Pasta local).
 * Espelho Python: backend/integrations/project_ingest.py
 */

export const PROJECT_MAP_NAME = "__project_map.txt";
export const MAX_CONTENT_FILES = 12;
export const MAX_FILE_BYTES = 200 * 1024;
export const MAX_CONTENT_CHARS = 200000;
export const MAX_MAP_LINES = 4000;
/** 1 mapa + 12 conteúdos */
export const MAX_ATTACHMENTS = MAX_CONTENT_FILES + 1;

export const IGNORE_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "vendor",
  "__pycache__",
  ".next",
  "coverage",
  ".venv",
  "venv",
  "target",
  "out",
  ".turbo",
  ".cache",
  ".idea",
  ".vscode",
  "eggs",
  ".eggs",
  ".tox",
  ".mypy_cache",
  ".ruff_cache",
  ".pytest_cache",
]);

const IGNORE_EXT = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".ico",
  ".svg",
  ".woff",
  ".woff2",
  ".ttf",
  ".eot",
  ".mp3",
  ".mp4",
  ".wav",
  ".zip",
  ".gz",
  ".tar",
  ".7z",
  ".rar",
  ".exe",
  ".dll",
  ".so",
  ".dylib",
  ".bin",
  ".pdf",
  ".pyc",
  ".class",
  ".o",
  ".a",
  ".wasm",
  ".map",
]);

const HIGH_NAMES = new Set([
  "package.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "requirements.txt",
  "requirements-lock.txt",
  "pyproject.toml",
  "poetry.lock",
  "cargo.toml",
  "go.mod",
  "go.sum",
  "pom.xml",
  "composer.json",
  "composer.lock",
  "gemfile",
  "dockerfile",
  "docker-compose.yml",
  "docker-compose.yaml",
  "vercel.json",
  "next.config.js",
  "next.config.mjs",
  "next.config.ts",
  "nuxt.config.ts",
  "nuxt.config.js",
  "vite.config.ts",
  "vite.config.js",
  "tsconfig.json",
  "nginx.conf",
  ".env.example",
  ".env.sample",
  "openapi.yaml",
  "openapi.json",
  "swagger.yaml",
  "swagger.json",
]);

const SOURCE_EXT = new Set([
  ".py",
  ".js",
  ".ts",
  ".tsx",
  ".jsx",
  ".go",
  ".rs",
  ".java",
  ".kt",
  ".rb",
  ".php",
  ".cs",
  ".swift",
  ".c",
  ".cpp",
  ".h",
  ".hpp",
  ".vue",
  ".svelte",
  ".sql",
  ".sh",
  ".ps1",
  ".yml",
  ".yaml",
  ".toml",
  ".ini",
  ".cfg",
  ".conf",
  ".json",
  ".md",
  ".html",
  ".css",
  ".scss",
]);

/**
 * @param {string} path
 */
export function normalizePath(path) {
  return String(path || "")
    .replace(/\\/g, "/")
    .replace(/^\.\//, "")
    .replace(/^\/+/, "");
}

/**
 * @param {string} path
 */
export function pathIgnored(path) {
  const parts = normalizePath(path).split("/").filter(Boolean);
  for (const p of parts.slice(0, -1)) {
    if (IGNORE_DIRS.has(p)) return true;
  }
  const base = parts[parts.length - 1] || "";
  const lower = base.toLowerCase();
  const dot = lower.lastIndexOf(".");
  if (dot >= 0 && IGNORE_EXT.has(lower.slice(dot))) return true;
  if (lower.endsWith(".min.js") || lower.endsWith(".min.css")) return true;
  if (lower === "package-lock.json" && parts.length > 2) return true;
  return false;
}

/**
 * @param {string} path
 * @param {number} [size]
 */
export function scorePath(path, size = 0) {
  const norm = normalizePath(path);
  if (!norm || pathIgnored(norm)) return -1;
  if (size > MAX_FILE_BYTES) return -1;

  const parts = norm.split("/");
  const base = (parts[parts.length - 1] || "").toLowerCase();
  let score = 10;

  if (HIGH_NAMES.has(base)) score += 100;
  if (base.startsWith("dockerfile")) score += 90;
  if (base.startsWith("docker-compose")) score += 90;
  if (base.endsWith(".env.example") || base.endsWith(".env.sample")) score += 85;
  if (base.includes("nginx")) score += 70;

  const joined = norm.toLowerCase();
  if (/(^|\/)(routes|api|auth|middleware|controllers|handlers)(\/|$)/.test(joined)) {
    score += 60;
  }
  if (/(^|\/)(src|app|backend|frontend|server|web)(\/|$)/.test(joined)) {
    score += 25;
  }
  if (parts.length <= 2) score += 20;

  const dot = base.lastIndexOf(".");
  const ext = dot >= 0 ? base.slice(dot) : "";
  if (SOURCE_EXT.has(ext)) score += 15;

  if (/(^|\/)(test|tests|__tests__|spec|docs|doc|examples|fixtures)(\/|$)/.test(joined)) {
    score -= 40;
  }
  if (base.endsWith(".test.js") || base.endsWith(".spec.ts") || base.endsWith("_test.py")) {
    score -= 35;
  }
  if (base.endsWith(".lock") || base === "yarn.lock" || base === "pnpm-lock.yaml") {
    score -= 50;
  }

  return score;
}

/**
 * @param {{ path: string, size?: number }[]} entries
 */
export function buildProjectMap(entries, { maxLines = MAX_MAP_LINES } = {}) {
  const kept = [];
  let ignored = 0;
  for (const e of entries) {
    const path = normalizePath(e.path);
    if (!path || pathIgnored(path)) {
      ignored += 1;
      continue;
    }
    kept.push({ path, size: Number(e.size) || 0 });
  }
  kept.sort((a, b) => a.path.localeCompare(b.path));
  const shown = kept.slice(0, maxLines);
  const omitted = kept.length - shown.length;
  const lines = [
    `# Mapa do repositório (${kept.length} arquivos após filtros; ${ignored} ignorados)`,
    `# Amostra de conteúdo anexada à parte (arquivos prioritários para pentest).`,
    "",
  ];
  for (const row of shown) {
    lines.push(`${row.path}\t${row.size}`);
  }
  if (omitted > 0) {
    lines.push(`… (+${omitted} omitidos do mapa)`);
  }
  return {
    text: lines.join("\n"),
    keptCount: kept.length,
    ignoredCount: ignored,
    totalSeen: entries.length,
  };
}

/**
 * @param {{ path: string, size?: number }[]} entries
 */
export function pickContentPaths(entries, { limit = MAX_CONTENT_FILES } = {}) {
  const scored = [];
  for (const e of entries) {
    const path = normalizePath(e.path);
    const size = Number(e.size) || 0;
    const score = scorePath(path, size);
    if (score < 0) continue;
    scored.push({ path, size, score });
  }
  scored.sort((a, b) => b.score - a.score || a.path.localeCompare(b.path));
  const picked = [];
  const seen = new Set();
  for (const row of scored) {
    if (seen.has(row.path)) continue;
    seen.add(row.path);
    picked.push(row);
    if (picked.length >= limit) break;
  }
  return picked;
}

/**
 * Ingest de FileList do browser (Pasta do projeto).
 * Inventário completo no mapa + leitura só dos arquivos prioritários.
 * @param {FileList|File[]|null} fileList
 * @param {{
 *   addAttachment: (name: string, content: string) => void,
 *   clearAttachments?: () => void,
 *   toast?: (msg: string, type?: string) => void,
 *   onProgress?: (label: string) => void,
 * }} hooks
 */
export async function ingestProjectFiles(fileList, hooks) {
  const list = fileList || [];
  const n = list.length || 0;
  if (!n) {
    hooks.toast?.("Nenhuma pasta selecionada", "error");
    return { map: null, attached: 0, picks: [], folderName: "", files: [] };
  }

  const firstRel = normalizePath(list[0]?.webkitRelativePath || list[0]?.name || "");
  const folderName = firstRel.split("/")[0] || "pasta";

  hooks.onProgress?.(`Indexando “${folderName}” (${n} itens)…`);
  hooks.toast?.(`Indexando pasta (${n} itens)…`, "info");
  hooks.clearAttachments?.();

  /** @type {Map<string, File>} */
  const byPath = new Map();
  for (let i = 0; i < n; i++) {
    const file = list[i];
    if (!file) continue;
    const rel = normalizePath(file.webkitRelativePath || file.name);
    if (!rel) continue;
    byPath.set(rel, file);
    if (i > 0 && i % 400 === 0) {
      hooks.onProgress?.(`Indexando “${folderName}”… ${i}/${n}`);
      await new Promise((r) => setTimeout(r, 0));
    }
  }

  const entries = [];
  for (const [path, file] of byPath) {
    entries.push({ path, size: file.size || 0 });
  }

  hooks.onProgress?.(`Montando mapa de “${folderName}”…`);
  const map = buildProjectMap(entries);
  hooks.addAttachment(PROJECT_MAP_NAME, map.text.slice(0, MAX_CONTENT_CHARS));

  const picks = pickContentPaths(entries);
  const files = [];
  let attached = 0;
  for (const pick of picks) {
    const file = byPath.get(pick.path);
    if (!file) continue;
    if (file.size > MAX_FILE_BYTES) continue;
    hooks.onProgress?.(`Lendo ${pick.path}…`);
    const text = await file.text().catch(() => "");
    if (!text) continue;
    hooks.addAttachment(pick.path, text.slice(0, MAX_CONTENT_CHARS));
    files.push(pick.path);
    attached += 1;
  }

  const msg =
    `Pasta anexada: ${map.keptCount} no mapa · ${attached} arquivos lidos` +
    (map.ignoredCount ? ` · ${map.ignoredCount} ignorados` : "") +
    ` (de ${map.totalSeen})`;
  hooks.toast?.(msg, "info");
  return {
    map,
    attached,
    picks,
    folderName,
    files,
    totalSeen: map.totalSeen,
    keptCount: map.keptCount,
    ignoredCount: map.ignoredCount,
  };
}

function readAllDirectoryEntries(reader) {
  return new Promise((resolve, reject) => {
    const all = [];
    const pump = () => {
      reader.readEntries(
        (batch) => {
          if (!batch.length) {
            resolve(all);
            return;
          }
          all.push(...batch);
          pump();
        },
        reject
      );
    };
    pump();
  });
}

function entryToFile(entry, relativePath) {
  return new Promise((resolve, reject) => {
    entry.file(
      (file) => {
        try {
          Object.defineProperty(file, "webkitRelativePath", {
            value: relativePath,
            configurable: true,
          });
        } catch {
          /* ignore */
        }
        resolve(file);
      },
      reject
    );
  });
}

/**
 * Percorre FileSystemEntry (pasta/arquivo) arrastado do SO — estilo Cursor.
 * @param {FileSystemEntry} entry
 * @param {string} parentPath
 * @param {File[]} out
 */
async function walkDroppedEntry(entry, parentPath, out) {
  if (!entry) return;
  if (entry.isFile) {
    const rel = parentPath ? `${parentPath}/${entry.name}` : entry.name;
    const file = await entryToFile(entry, rel);
    out.push(file);
    if (out.length % 400 === 0) {
      await new Promise((r) => setTimeout(r, 0));
    }
    return;
  }
  if (!entry.isDirectory) return;
  const nextPrefix = parentPath ? `${parentPath}/${entry.name}` : entry.name;
  const reader = entry.createReader();
  const children = await readAllDirectoryEntries(reader);
  for (const child of children) {
    await walkDroppedEntry(child, nextPrefix, out);
  }
}

/**
 * Coleta arquivos/pastas de um DataTransfer (drag-and-drop).
 * Preferência: webkitGetAsEntry (pastas recursivas); fallback: files.
 * @param {DataTransfer|null|undefined} dt
 * @returns {Promise<File[]>}
 */
export async function collectDroppedProjectFiles(dt) {
  if (!dt) return [];
  const out = [];
  const items = dt.items ? [...dt.items] : [];

  if (items.length) {
    const entries = [];
    for (const item of items) {
      if (item.kind !== "file") continue;
      const entry = typeof item.webkitGetAsEntry === "function" ? item.webkitGetAsEntry() : null;
      if (entry) entries.push(entry);
      else {
        const f = item.getAsFile?.();
        if (f) out.push(f);
      }
    }
    for (const entry of entries) {
      await walkDroppedEntry(entry, "", out);
    }
    if (out.length) return out;
  }

  const files = dt.files ? [...dt.files] : [];
  return files;
}
