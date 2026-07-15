import { MODEL_STORAGE_KEY, QUICK_OBJECTIVES } from "./constants.js";
import { apiFetch } from "./api.js";
import { escapeHtml } from "./exec.js";
import { getActiveSession, saveStore } from "./sessions.js";

/** @type {Record<string, unknown>} */
let ctx = {};

export let preferredTool = "auto";
export let toolCategories = [];
export let activeToolCategory = "all";
export let modelCatalog = null;
export let selectedModel = null;

export function initToolsPanel(context) {
  ctx = context;
}

export function getPreferredTool() {
  return preferredTool;
}

export function setPreferredTool(tool) {
  preferredTool = tool;
  const session = getActiveSession();
  if (session) {
    session.preferredTool = tool;
    saveStore();
  }
  const { toolBadge } = ctx;
  if (toolBadge) {
    toolBadge.textContent = tool;
    toolBadge.classList.toggle("fixed", tool !== "auto");
  }
  document.querySelectorAll(".tool-item, .tool-card").forEach((el) => {
    const nameEl = el.querySelector(".tool-item-name");
    if (nameEl) el.classList.toggle("active", nameEl.textContent === tool);
  });
  ctx.updateStatusBar?.();
}

export function syncToolFromSession() {
  const session = getActiveSession();
  setPreferredTool(session?.preferredTool || "auto");
}

function closeModelMenu() {
  const { modelMenu, modelTrigger } = ctx;
  if (modelMenu) modelMenu.hidden = true;
  modelTrigger?.classList.remove("open");
}

export function closeToolsPanelMenus() {
  closeModelMenu();
}

export function toggleModelMenu() {
  const { modelMenu, modelTrigger } = ctx;
  if (!modelMenu || !modelTrigger) return;
  if (modelMenu.hidden) {
    renderModelMenu();
    modelMenu.hidden = false;
    modelTrigger.classList.add("open");
  } else {
    closeModelMenu();
  }
}

function loadSelectedModel() {
  try {
    const raw = localStorage.getItem(MODEL_STORAGE_KEY);
    if (raw) return JSON.parse(raw);
  } catch { /* ignore */ }
  return null;
}

function saveSelectedModel(model) {
  selectedModel = model;
  localStorage.setItem(MODEL_STORAGE_KEY, JSON.stringify(model));
  updateModelLabel();
  ctx.updateStatusBar?.();
}

export function updateModelLabel() {
  const { modelLabel, modelTrigger } = ctx;
  if (!modelLabel || !selectedModel) return;
  modelLabel.textContent = selectedModel.name || "Flash";
  if (modelTrigger) {
    modelTrigger.title = `${selectedModel.name} (${selectedModel.provider || "ia"})`;
    modelTrigger.classList.toggle("model-gemini", selectedModel.provider === "gemini");
    modelTrigger.classList.toggle("model-deepseek", selectedModel.provider === "deepseek");
  }
}

export function getModelPayload() {
  if (!selectedModel) return {};
  return {
    model: selectedModel.id,
    fallback_model: selectedModel.fallback || "",
  };
}

function selectModel(model) {
  saveSelectedModel(model);
  closeModelMenu();
  ctx.toast?.(`${model.name} · ${model.tier_label || "modelo"}`, "success");
}

function renderModelMenu() {
  const { modelMenu } = ctx;
  if (!modelCatalog?.tiers || !modelMenu) return;
  modelMenu.innerHTML = "";

  for (let i = 0; i < modelCatalog.tiers.length; i++) {
    const tier = modelCatalog.tiers[i];
    if (i > 0) {
      const sep = document.createElement("div");
      sep.className = "model-menu-sep";
      modelMenu.appendChild(sep);
    }

    const head = document.createElement("div");
    head.className = "model-tier-head";
    head.innerHTML = `
      <span class="model-tier-label">${escapeHtml(tier.label)}</span>
      <span class="model-tier-desc">${escapeHtml(tier.description || "")}</span>
    `;
    modelMenu.appendChild(head);

    for (const m of tier.models) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = `model-option${selectedModel?.id === m.id ? " active" : ""}`;
      btn.innerHTML = `
        <span class="model-check">${selectedModel?.id === m.id ? "✓" : ""}</span>
        <span class="model-option-body">
          <span class="model-option-name">
            <span class="model-provider model-provider-${m.provider}">${m.provider === "deepseek" ? "DS" : "G"}</span>
            ${escapeHtml(m.name)}
          </span>
          <span class="model-option-desc">${escapeHtml(m.description)}</span>
        </span>
      `;
      btn.addEventListener("click", () => selectModel({
        id: m.id,
        name: m.name,
        fallback: m.fallback,
        provider: m.provider,
        tier_label: tier.label,
      }));
      modelMenu.appendChild(btn);
    }
  }
}

export async function loadModels() {
  try {
    const res = await apiFetch("/api/models");
    if (!res.ok) return false;
    modelCatalog = await res.json();
    const saved = loadSelectedModel();
    if (saved?.id) {
      selectedModel = saved;
    } else {
      const defaultId = modelCatalog.default_model;
      for (const tier of modelCatalog.tiers) {
        const found = tier.models.find((m) => m.id === defaultId);
        if (found) {
          selectedModel = {
            id: found.id,
            name: found.name,
            fallback: found.fallback,
            provider: found.provider,
            tier_label: tier.label,
          };
          break;
        }
      }
    }
    updateModelLabel();
    return true;
  } catch { /* ignore */ }
  return false;
}

export function renderToolCategoryTabs() {
  const { toolCategoriesEl, toolSearch } = ctx;
  if (!toolCategoriesEl) return;
  toolCategoriesEl.innerHTML = "";

  const allBtn = document.createElement("button");
  allBtn.type = "button";
  allBtn.className = `tool-cat-tab${activeToolCategory === "all" ? " active" : ""}`;
  allBtn.textContent = "todas";
  allBtn.addEventListener("click", () => {
    activeToolCategory = "all";
    renderToolCategoryTabs();
    renderToolList(toolSearch?.value || "");
  });
  toolCategoriesEl.appendChild(allBtn);

  for (const cat of toolCategories) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = `tool-cat-tab${activeToolCategory === cat.id ? " active" : ""}`;
    btn.textContent = cat.name;
    btn.addEventListener("click", () => {
      activeToolCategory = cat.id;
      renderToolCategoryTabs();
      renderToolList(toolSearch?.value || "");
    });
    toolCategoriesEl.appendChild(btn);
  }
}

export function renderToolList(filter = "") {
  const { toolList } = ctx;
  if (!toolList) return;

  const q = filter.toLowerCase().trim();
  toolList.innerHTML = "";

  const grid = document.createElement("div");
  grid.className = "tools-grid";

  const autoCard = document.createElement("div");
  autoCard.className = `tool-card tool-card-wide${preferredTool === "auto" ? " active" : ""}`;
  autoCard.innerHTML = `
    <div class="tool-card-main">
      <span class="tool-item-name">auto</span>
      <span class="tool-item-desc">A IA escolhe a ferramenta ideal para cada pedido — recomendado na maioria dos casos</span>
    </div>
  `;
  autoCard.addEventListener("click", () => selectTool("auto"));
  grid.appendChild(autoCard);

  for (const cat of toolCategories) {
    if (activeToolCategory !== "all" && cat.id !== activeToolCategory) continue;

    const tools = cat.tools.filter((t) => {
      const id = t.id || t;
      const summary = t.summary || "";
      return !q || id.toLowerCase().includes(q) || summary.toLowerCase().includes(q) || cat.name.toLowerCase().includes(q);
    });
    if (tools.length === 0) continue;

    for (const tool of tools) {
      const id = tool.id || tool;
      const summary = tool.summary || "";
      const example = tool.example || "";

      const card = document.createElement("div");
      card.className = `tool-card${preferredTool === id ? " active" : ""}`;

      const main = document.createElement("div");
      main.className = "tool-card-main";
      main.innerHTML = `
        <span class="tool-item-cat">${escapeHtml(cat.name)}</span>
        <span class="tool-item-name">${escapeHtml(id)}</span>
        <span class="tool-item-desc">${escapeHtml(summary)}</span>
        ${example ? `<code class="tool-item-example">${escapeHtml(example)}</code>` : ""}
      `;
      main.addEventListener("click", () => selectTool(id));

      const actions = document.createElement("div");
      actions.className = "tool-card-actions";

      if (example) {
        const useBtn = document.createElement("button");
        useBtn.type = "button";
        useBtn.className = "tool-use-btn";
        useBtn.textContent = "usar";
        useBtn.title = "Seleciona ferramenta e coloca exemplo no prompt";
        useBtn.addEventListener("click", (e) => {
          e.stopPropagation();
          selectTool(id, example);
        });
        actions.appendChild(useBtn);
      }

      card.appendChild(main);
      if (actions.childElementCount) card.appendChild(actions);
      grid.appendChild(card);
    }
  }

  toolList.appendChild(grid);
}

export function selectTool(tool, exampleText = null) {
  setPreferredTool(tool);
  ctx.closeOverlay?.(ctx.overlayTools);
  const { input } = ctx;
  if (exampleText && input) {
    input.value = exampleText;
    input.focus();
    ctx.toast?.(`ferramenta: ${tool} · exemplo no prompt`, "success");
  } else {
    ctx.toast?.(tool === "auto" ? "modo auto — IA escolhe" : `ferramenta fixa: ${tool}`);
  }
}

export async function loadTools() {
  try {
    const res = await apiFetch("/api/tools");
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data.categories) && data.categories.length > 0) {
        toolCategories = data.categories;
        renderToolCategoryTabs();
        return true;
      }
    }
  } catch { /* ignore */ }
  toolCategories = [];
  return false;
}

export function renderQuickObjectives() {
  const { quickObjectivesEl, autopilotObjective } = ctx;
  if (!quickObjectivesEl) return;

  quickObjectivesEl.innerHTML = "";
  const label = document.createElement("span");
  label.className = "quick-obj-label";
  label.textContent = "objetivos rápidos:";
  quickObjectivesEl.appendChild(label);

  for (const obj of QUICK_OBJECTIVES) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "quick-obj-btn";
    btn.textContent = obj.length > 55 ? obj.slice(0, 55) + "…" : obj;
    btn.title = obj;
    btn.addEventListener("click", () => {
      if (autopilotObjective) {
        autopilotObjective.value = obj;
        autopilotObjective.focus();
      }
    });
    quickObjectivesEl.appendChild(btn);
  }
}

export async function openToolsPanel() {
  const { toolSearch } = ctx;
  await loadTools();
  if (toolSearch) toolSearch.value = "";
  activeToolCategory = "all";
  renderToolCategoryTabs();
  renderToolList();
  ctx.openOverlay?.(ctx.overlayTools);
}
