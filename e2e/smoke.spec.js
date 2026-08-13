import { test, expect } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("darkstar-onboarded", "1");
    localStorage.setItem("chat-ia-kali-onboarded", "1");
  });
});

test("boot — health e versão 2.0.0", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator("#status-pill-docker")).toBeVisible();
  const healthRes = await page.request.get("/api/health");
  expect(healthRes.ok()).toBeTruthy();
  const health = await healthRes.json();
  expect(health.version).toBe("2.0.0");
  expect(health).toHaveProperty("scope_warning");
});

test("intel — abre workspace mapa e aba relatórios", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator("#status-pill-docker")).toBeVisible();
  await page.keyboard.press("Alt+c");
  await expect(page.locator("#view-workspace")).toBeVisible();
  await expect(page.locator("#ws-panel-mapa")).toBeVisible();
  await expect(page.locator("#workspace-map-body")).toBeAttached();
  await page.click('[data-ws-tab="report"]');
  await expect(page.locator("#ws-panel-report")).toBeVisible();
  await expect(page.locator('[data-ws-tab="report"]')).toHaveClass(/active/);
});

test("files — abre Relatórios e lista ou empty state", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator("#status-pill-docker")).toBeVisible();
  await page.keyboard.press("Alt+f");
  await expect(page.locator("#view-workspace")).toBeVisible();
  await expect(page.locator("#ws-panel-report")).toBeVisible();
  await expect(page.locator("#files-list")).toContainText(
    /relat[oó]rio|pdf|conversa|arquivo|artefato|listando|nenhum/i
  );
});
