// Browser acceptance for the shipped static page with a controlled native bridge.
// No provider credentials, node writes or model requests are used by this fixture.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile, mkdir } from "node:fs/promises";
import { resolve, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const out = fileURLToPath(new URL("../out/", import.meta.url));
const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname === "/health") { res.end("ok"); return; }
  if (url.pathname === "/objectives") { res.setHeader("Content-Type", "application/json"); res.end('{"objectives":[]}'); return; }
  if (!url.pathname.startsWith("/ui/")) { res.writeHead(404).end(); return; }
  const suffix = decodeURIComponent(url.pathname.slice(4));
  const path = resolve(out, suffix.endsWith("/") ? suffix + "index.html" : suffix);
  if (!path.startsWith(out)) { res.writeHead(403).end(); return; }
  try {
    const body = await readFile(path);
    res.setHeader("Content-Type", ({ ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".json": "application/json" })[extname(path)] ?? "application/octet-stream");
    res.end(body);
  } catch { res.writeHead(404).end(); }
});
await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
const url = `http://127.0.0.1:${server.address().port}/ui/coordination/`;
const browser = await chromium.launch({ executablePath: process.env.CAIRN_BROWSER_PATH || undefined });
try {
  const context = await browser.newContext({ userAgent: "CairnApp/1" });
  await context.addInitScript(() => {
    const empty = { phase: "idle", brief: "", budget: "", message: "", provider: "" };
    let state = JSON.parse(sessionStorage.getItem("coordination-fixture") ?? "null") ?? empty;
    window.__coordinationCalls = [];
    window.__failGeneration = false;
    const save = (next) => { state = next; sessionStorage.setItem("coordination-fixture", JSON.stringify(state)); return state; };
    window.webkit = { messageHandlers: { cairn: { postMessage: async (request) => {
      window.__coordinationCalls.push(request);
      if (request.kind === "coordination-status") return state;
      if (request.kind === "draft-coordination") {
        if (window.__failGeneration) throw new Error("Provider unavailable. Try again.");
        const next = { ...empty, phase: "drafting", brief: request.brief, budget: request.budget, provider: "Configured AI" };
        save(next);
        setTimeout(() => save({ ...next, phase: "ready", draftId: "native-checked-spec",
          objectiveId: "sha256:" + "a".repeat(64), spec: '{"piecework":{"units":16,"unit_price":10},"reward":160}',
          statement: "Compute each square for integers 0 through 15.", unit: "One integer and its exact square.",
          units: "16", unitPrice: "10", reward: "160", notes: "",
          message: "The checker accepted the valid example and rejected the incorrect and empty examples." }), 150);
        return next;
      }
      if (request.kind === "launch-coordination") {
        if (request.draftId !== state.draftId) throw new Error("Wrong draft");
        return save({ ...state, phase: "posted", message: "Challenge launched." });
      }
      if (request.kind === "cancel-coordination") return save(empty);
      return true;
    } } } };
  });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto(url);
  await page.getByLabel("Describe the task").fill("compute integer squares");
  await page.getByRole("button", { name: "Generate challenge spec", exact: true }).click();
  await page.getByRole("heading", { name: "Your challenge spec" }).waitFor();
  assert.equal(await page.getByText("Give this to your agent", { exact: true }).count(), 0);
  assert.equal(await page.getByRole("button", { name: "Write the agent prompt", exact: true }).count(), 0);
  for (const width of [360, 1280]) {
    await page.setViewportSize({ width, height: 900 });
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `overflow at ${width}`);
  }
  if (process.env.CAIRN_UX_SCREENSHOTS) {
    await mkdir(process.env.CAIRN_UX_SCREENSHOTS, { recursive: true });
    await page.locator("#launch").screenshot({ path: resolve(process.env.CAIRN_UX_SCREENSHOTS, "coordination-spec.png"), animations: "disabled" });
  }
  // Reload recovers the exact native receipt, without another paid generation.
  await page.reload();
  await page.getByRole("heading", { name: "Your challenge spec" }).waitFor();
  await page.getByRole("button", { name: "Launch challenge", exact: true }).click();
  const link = page.getByRole("link", { name: "View running challenge" });
  await link.waitFor();
  assert((await link.getAttribute("href")).includes(encodeURIComponent("sha256:" + "a".repeat(64))));
  assert.deepEqual(await page.evaluate(() => window.__coordinationCalls.filter((r) => r.kind === "launch-coordination")),
    [{ kind: "launch-coordination", draftId: "native-checked-spec" }]);
  await page.getByLabel("Describe the task").fill("compute a different set of squares");
  assert.equal(await page.getByRole("button", { name: "Launch challenge", exact: true }).count(), 0);
  await page.evaluate(() => { window.__failGeneration = true; });
  await page.getByRole("button", { name: "Generate challenge spec", exact: true }).click();
  await page.getByRole("alert").filter({ hasText: "Provider unavailable" }).waitFor();
  assert.deepEqual(errors, []);
  const browserOnly = await browser.newPage();
  await browserOnly.goto(url);
  await browserOnly.getByText(/Open this node in Cairn for Mac/).waitFor();
  assert(await browserOnly.getByRole("button", { name: "Generate challenge spec", exact: true }).isDisabled());
  console.log("PASS background generation, spec preview, reload recovery, exact-id launch, stale preview, provider error, browser fallback and responsive layout");
} finally {
  await browser.close();
  await new Promise((ok) => server.close(ok));
}
