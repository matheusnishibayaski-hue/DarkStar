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
  modelTrigger?.setAttribute("aria-expanded", "false");
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
    modelTrigger.setAttribute("aria-expanded", "true");
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
  const short = (selectedModel.name || "flash").split(" ").pop().toLowerCase();
  modelLabel.textContent = short;
  if (modelTrigger) {
    modelTrigger.title = `${selectedModel.name} · ${selectedModel.tier_label || "model"}`;
    modelTrigger.classList.toggle("model-gemini", selectedModel.provider === "gemini");
    modelTrigger.classList.toggle("model-deepseek", selectedModel.provider === "deepseek");
  }
}

function resolveTierForModel(modelId, preferredTierId) {
  if (!modelCatalog?.tiers) return null;
  if (preferredTierId) {
    const tier = modelCatalog.tiers.find((t) => t.id === preferredTierId);
    if (tier?.models.some((m) => m.id === modelId)) return tier;
  }
  for (const tier of modelCatalog.tiers) {
    if (tier.models.some((m) => m.id === modelId)) return tier;
  }
  return null;
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

  const head = document.createElement("div");
  head.className = "model-menu-head";
  head.innerHTML = `<span class="model-menu-cmd">select</span> <span class="model-menu-arg">--model</span>`;
  modelMenu.appendChild(head);

  for (const tier of modelCatalog.tiers) {
    const block = document.createElement("div");
    block.className = "model-tier";

    const tierHead = document.createElement("div");
    tierHead.className = "model-tier-head";
    tierHead.innerHTML = `
      <span class="model-tier-tag"># ${escapeHtml(tier.label.toLowerCase())}</span>
      <span class="model-tier-desc">${escapeHtml(tier.description || "")}</span>
    `;
    block.appendChild(tierHead);

    const grid = document.createElement("div");
    grid.className = "model-tier-grid";

    for (const m of tier.models) {
      const isActive =
        selectedModel?.id === m.id &&
        (selectedModel?.tier_id === tier.id || !selectedModel?.tier_id);
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = `model-option model-option--${m.provider}${isActive ? " active" : ""}`;
      btn.setAttribute("role", "option");
      btn.setAttribute("aria-selected", isActive ? "true" : "false");
      btn.innerHTML = `
        <span class="model-option-marker" aria-hidden="true">${isActive ? ">" : " "}</span>
        <span class="model-option-provider" aria-hidden="true">${m.provider === "deepseek" ? "DS" : "G"}</span>
        <span class="model-option-body">
          <span class="model-option-name">${escapeHtml(m.name)}</span>
          <span class="model-option-desc">${escapeHtml(m.description)}</span>
        </span>
      `;
      btn.addEventListener("click", () => selectModel({
        id: m.id,
        name: m.name,
        fallback: m.fallback,
        provider: m.provider,
        tier_id: tier.id,
        tier_label: tier.label,
      }));
      grid.appendChild(btn);
    }

    block.appendChild(grid);
    modelMenu.appendChild(block);
  }
}

export async function loadModels() {
  try {
    const res = await apiFetch("/api/models");
    if (!res.ok) return false;
    modelCatalog = await res.json();
    const saved = loadSelectedModel();
    if (saved?.id) {
      const tier = resolveTierForModel(saved.id, saved.tier_id);
      selectedModel = {
        ...saved,
        tier_id: tier?.id || saved.tier_id,
        tier_label: tier?.label || saved.tier_label,
      };
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
            tier_id: tier.id,
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
