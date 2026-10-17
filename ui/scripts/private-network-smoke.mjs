// Acceptance against the actual packaged reader, not the `ui` build flag.
// Every process owns a disposable directory. No production node is contacted.
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const binary = resolve(process.env.CAIRN_BIN ?? fileURLToPath(new URL("../../target/debug/cairn", import.meta.url)));
const version = execFileSync(binary, ["--version"], { encoding: "utf8" });
assert(/^\s*ui\s+embedded(?:\s|$)/m.test(version), "Acceptance requires an embedded Cairn build");
const directory = await mkdtemp(join(tmpdir(), "cairn-private-reader-"));
const report = { binary, scenarios: [], externalRequests: [], pageErrors: [] };
const allocate = () => new Promise((done, reject) => {
  const server = createServer();
  server.on("error", reject);
  server.listen(0, "127.0.0.1", () => {
    const port = server.address().port;
    server.close((error) => error ? reject(error) : done(port));
  });
});
const read = async (url) => fetch(url, { signal: AbortSignal.timeout(2_000) });
const start = async (profile, dir, port = null) => {
  port ??= await allocate();
  const origin = `http://127.0.0.1:${port}`;
  const child = spawn(binary, ["--data-dir", dir, "run", "--no-mcp", "--listen", "127.0.0.1:0", "--serve", `127.0.0.1:${port}`], {
    cwd: dir,
    env: {
      PATH: process.env.PATH,
      CAIRN_NETWORK: profile,
      CAIRN_KEY: join(dir, "absent-key"),
      CAIRN_SEEDS: "off", CAIRN_SEEDS_REFRESH: "off",
      CAIRN_BEACON_PORT: "off", CAIRN_PORTMAP: "off", CAIRN_PORTMAP_HTTP: "off",
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (bytes) => { stderr += bytes; });
  const stop = async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    const exit = once(child, "exit");
    child.kill();
    await exit;
  };
  try {
    let ready = false;
    for (let attempt = 0; attempt < 100; attempt++) {
      assert(child.exitCode === null, `node exited: ${stderr}`);
      try { ready = (await read(`${origin}/health`)).ok; } catch { /* retry startup only */ }
      if (ready) break;
      await new Promise((done) => setTimeout(done, 100));
    }
    assert(ready, `node startup timed out: ${stderr}`);
    return { origin, port, stop };
  } catch (error) {
    await stop();
    throw error;
  }
};

let browser;
let node;
try {
  node = await start("private", directory);
  const response = await read(`${node.origin}/ui/`);
  assert.equal(response.status, 200, "ui feature flag did not attest actual packaged HTML");
  assert.equal(response.headers.get("cache-control"), "no-store");
  const html = await response.text();
  assert(html.includes('<meta name="cairn-network" content="private"/>'));
  const bundle = html.match(/<script[^>]+src="([^"]+\.js[^\"]*)"/);
  assert(bundle, "packaged HTML contains no local JavaScript bundle");
  const bundleURL = new URL(bundle[1], node.origin);
  assert.equal(bundleURL.origin, node.origin, "packaged reader depends on an external script");
  const script = await read(bundleURL);
  assert.equal(script.status, 200, "packaged JavaScript is missing");
  assert.equal(script.headers.get("cache-control"), "no-store");
  assert((await script.text()).length > 0);
  assert.deepEqual((await (await read(`${node.origin}/ui/seeds.json`)).json()).seeds, []);

  browser = await chromium.launch({
    executablePath: process.env.CAIRN_BROWSER_PATH || undefined,
    args: process.env.CAIRN_UX_NO_SANDBOX === "1" ? ["--no-sandbox"] : [],
  });
  const context = await browser.newContext();
  const page = await context.newPage();
  page.setDefaultTimeout(10_000);
  let seeds = 0;
  page.on("pageerror", (error) => report.pageErrors.push(error.message));
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (/^https?:$/.test(url.protocol) && url.origin !== node.origin) {
      report.externalRequests.push(url.href);
      return route.abort();
    }
    if (url.pathname === "/ui/seeds.json") seeds++;
    return route.continue();
  });
  await page.route("**/health", (route) => route.fulfill({ status: 503, body: "Health unavailable" }));
  await page.goto(`${node.origin}/ui/`);
  const dialog = page.getByRole("dialog", { name: "Get this node online" });
  await dialog.waitFor();
  assert.match(await dialog.innerText(), /private installation/);
  assert.match(await dialog.innerText(), /WireGuard/);
  assert.doesNotMatch(await dialog.innerText(), /tailscale|funnel|open internet/i);
  await page.waitForFunction(() => window.performance.getEntriesByType("resource").some(({ name }) => name.endsWith("/ui/seeds.json")));
  assert(seeds > 0, "forced-health failure did not exercise real seed fallback");
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
  await dialog.waitFor({ state: "detached" });
  await page.reload();
  await page.getByRole("heading", { level: 1 }).first().waitFor();
  assert.equal(await dialog.count(), 0, "dismissal was not preserved on reload");
  await page.getByRole("button", { name: "Get this node online →", exact: true }).click();
  await dialog.waitFor();
  assert.match(await dialog.innerText(), /private installation/);
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
  await page.getByRole("button", { name: "Get this node online →", exact: true }).click();
  await dialog.waitFor();
  assert.match(await dialog.innerText(), /WireGuard/);
  report.scenarios.push("packaged private HTML and JS; no-store; private health-failure guidance; empty real seed fallback; persisted dismissal and repeated explicit recovery");
  await context.close();
  await node.stop();
  node = null;

  const publicDir = await mkdtemp(join(tmpdir(), "cairn-public-reader-"));
  node = await start("public", publicDir);
  const publicHTML = await (await read(`${node.origin}/ui/`)).text();
  assert(!publicHTML.includes('name="cairn-network"'), "private marker leaked into public mode");
  const publicContext = await browser.newContext();
  const publicPage = await publicContext.newPage();
  publicPage.on("pageerror", (error) => report.pageErrors.push(error.message));
  await publicPage.route("**/*", (route) => {
    const url = new URL(route.request().url());
    if (/^https?:$/.test(url.protocol) && url.origin !== node.origin) {
      report.externalRequests.push(url.href);
      return route.abort();
    }
    return route.continue();
  });
  await publicPage.goto(`${node.origin}/ui/`);
  const publicDialog = publicPage.getByRole("dialog", { name: "Get this node online" });
  await publicDialog.waitFor();
  assert.match(await publicDialog.innerText(), /tailscale up/);
  assert.match(await publicDialog.innerText(), /tailscale funnel/);
  assert.doesNotMatch(await publicDialog.innerText(), /private installation/);
  report.scenarios.push("public HTML and existing public setup guidance unchanged");
  await publicContext.close();
  assert.deepEqual(report.externalRequests, []);
  assert.deepEqual(report.pageErrors, []);
  console.log(JSON.stringify(report, null, 2));
} catch (error) {
  report.failure = String(error);
  console.error(`Acceptance failed; disposable evidence: ${directory}`);
  throw error;
} finally {
  await writeFile(join(directory, "acceptance.json"), JSON.stringify(report, null, 2));
  if (browser) await browser.close();
  if (node) await node.stop();
}
