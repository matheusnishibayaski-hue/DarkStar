import { test, expect } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("chat-ia-kali-onboarded", "1");
  });
});

test("boot — health e versão 1.1.0", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator("#status-pill-docker")).toBeVisible();
  const healthRes = await page.request.get("/api/health");
  expect(healthRes.ok()).toBeTruthy();
  const health = await healthRes.json();
  expect(health.version).toBe("1.1.0");
  expect(health).toHaveProperty("scope_warning");
});

test("intel — abre painel e abas recon/threats", async ({ page }) => {
  await page.goto("/");
  await page.keyboard.press("Alt+i");
  await expect(page.locator("#overlay-intel")).toBeVisible();
  await expect(page.locator("#intel-tab-recon")).toHaveClass(/active/);
  await page.click("#intel-tab-threats");
  await expect(page.locator("#intel-pane-threats")).toBeVisible();
  await expect(page.locator("#threat-frame")).toBeAttached();
});

test("files — abre painel e lista ou empty state", async ({ page }) => {
  await page.goto("/");
  await page.keyboard.press("Alt+f");
  await expect(page.locator("#overlay-files")).toBeVisible();
  await expect(page.locator("#files-list")).toContainText(/artefato|listando|arquivo/i);
});
