import { test, expect } from "@playwright/test";

test("API — X-Request-ID e /api/metrics", async ({ request }) => {
  const health = await request.get("/api/health", {
    headers: { "X-Request-ID": "e2e-req-fixed-001" },
  });
  expect(health.ok()).toBeTruthy();
  expect(health.headers()["x-request-id"]).toBe("e2e-req-fixed-001");

  const metrics = await request.get("/api/metrics");
  expect(metrics.ok()).toBeTruthy();
  const body = await metrics.json();
  expect(body).toHaveProperty("requests_total");
  expect(body).toHaveProperty("tool_executions_total");
  expect(body).toHaveProperty("errors_total");
  expect(typeof body.requests_total).toBe("number");
});

test("API — OpenAPI inclui métricas e playbooks", async ({ request }) => {
  const res = await request.get("/openapi.json");
  expect(res.ok()).toBeTruthy();
  const paths = (await res.json()).paths;
  expect(paths).toHaveProperty("/api/metrics");
  expect(paths).toHaveProperty("/api/playbooks");
  expect(paths).toHaveProperty("/api/audit");
});
