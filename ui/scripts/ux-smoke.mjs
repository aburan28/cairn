// Browser regressions against a running local reader and a disposable node.
// No submissions or external transfers: the only POST is canonicalization.
import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import { chromium } from "playwright";

const reader = new URL(process.env.CAIRN_UX_URL ?? "http://127.0.0.1:3101/ui/");
assert(["127.0.0.1", "localhost", "[::1]"].includes(reader.hostname), "Use a local test reader");
const screenshots = process.env.CAIRN_UX_SCREENSHOTS;
if (screenshots) await mkdir(screenshots, { recursive: true });
const browser = await chromium.launch({
  executablePath: process.env.CAIRN_BROWSER_PATH || undefined,
  args: process.env.CAIRN_UX_NO_SANDBOX === "1" ? ["--no-sandbox"] : [],
});
const context = await browser.newContext();
await context.addInitScript(() => {
  window.__uxReads = 0;
  window.__uxLastRead = performance.now();
  const track = async (read) => {
    window.__uxReads += 1;
    try { return await read(); }
    finally { window.__uxReads -= 1; window.__uxLastRead = performance.now(); }
  };
  const fetch = window.fetch.bind(window);
  window.fetch = async (...args) => {
    const response = await track(() => fetch(...args));
    for (const method of ["json", "text", "arrayBuffer"]) {
      const read = response[method].bind(response);
      response[method] = (...options) => track(() => read(...options));
    }
    return response;
  };
});
const page = await context.newPage();
page.setDefaultTimeout(15_000);
const errors = [];
context.on("page", (next) => next.on("pageerror", (error) => errors.push(error.message)));
page.on("pageerror", (error) => errors.push(error.message));
const url = (route) => new URL(route, reader).href;
const go = async (route) => {
  await page.goto(url(route));
  await page.getByRole("heading", { level: 1 }).first().waitFor();
  // Measure the loaded data, not a skeleton. Track the reader's actual fetch
  // and body promises: browser lifecycle events can miss an aborted/coalesced
  // health request and leave networkidle unset after the reads have finished.
  await page.waitForFunction(() => window.__uxReads === 0 && performance.now() - window.__uxLastRead > 250);
};
const inDialog = () => page.evaluate(() => Boolean(document.activeElement?.closest("dialog[open]")));

try {
  const listing = await (await page.request.get(`${reader.origin}/objectives`)).json();
  const objective = listing.objectives[0];
  assert(objective, "Seed the test node with at least one objective");
  const detail = await (await page.request.get(`${reader.origin}/objective/${objective.id}`)).json();
  const routes = ["", "objectives/", "coordination/", "network/", "log/", "knowledge/", "goals/",
    "contribute/", "submit/", "payouts/", "peers/", "how-it-works/",
    `challenge/?id=${objective.id}`, `frontier/?id=${objective.id}`, `task/?id=${objective.id}`];
  if (objective.piecework) routes.push(`coordination/?id=${objective.id}`);
  for (const width of [320, 360, 1280]) {
    await page.setViewportSize({ width, height: 900 });
    for (const route of routes) {
      await go(route);
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `${route} overflows at ${width}px`);
    }
    console.log(`PASS route layout at ${width}px`);
  }
  console.log(`PASS ${routes.length} routes at 320, 360 and 1280px`);

  await go("contribute/");
  const opener = page.getByRole("button", { name: /Offer compute/ }).first();
  await opener.click();
  await page.getByRole("dialog").waitFor();
  for (let i = 0; i < 14; i++) {
    await page.keyboard.press(i % 2 ? "Tab" : "Shift+Tab");
    assert(await inDialog(), "Contribution sheet leaked keyboard focus");
  }
  await page.keyboard.press("Escape");
  await page.getByRole("dialog").waitFor({ state: "detached" });
  assert(await opener.evaluate((element) => element === document.activeElement), "Sheet lost its opener's focus");

  const jump = page.getByRole("button", { name: "Open the command palette" }).first();
  await jump.click();
  await page.getByRole("dialog").waitFor();
  await page.keyboard.press("Shift+Tab");
  assert(await inDialog(), "Command palette leaked keyboard focus");
  await page.getByRole("textbox", { name: "Find a page" }).focus();
  for (let i = 0; i < 12; i++) await page.keyboard.press("ArrowDown");
  assert(await page.locator("dialog li[data-current=true]").evaluate((element) => {
    const row = element.getBoundingClientRect();
    const list = element.parentElement.getBoundingClientRect();
    return row.top >= list.top && row.bottom <= list.bottom + 1;
  }), "Keyboard-selected route scrolled out of view");
  await page.getByRole("button", { name: "Close command palette" }).click();
  assert(await jump.evaluate((element) => element === document.activeElement), "Palette lost its opener's focus");
  await page.setViewportSize({ width: 360, height: 640 });
  await page.getByRole("button", { name: "Open the command palette" }).last().click();
  if (screenshots) await page.screenshot({ path: `${screenshots}/palette-mobile.png` });
  await page.getByRole("button", { name: "Close command palette" }).click();
  console.log("PASS modal focus, restoration, keyboard scrolling and phone dismissal");

  await go("objectives/");
  await page.getByRole("button", { name: "Refresh", exact: true }).waitFor();
  const search = page.getByRole("textbox", { name: "Search", exact: true });
  await search.fill("nothing-could-match-this-ux-check");
  await page.getByRole("button", { name: "Clear filters" }).click();
  assert.equal(await search.inputValue(), "");
  await page.route("**/objectives", (route) => route.fulfill({ status: 503, body: "Temporarily offline" }));
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await page.getByText("Could not refresh objectives; showing the last read", { exact: true }).waitFor();
  assert(await page.locator("main table tbody tr").count() > 0, "A failed refresh erased the last listing");
  await page.unroute("**/objectives");
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await page.getByText("Could not refresh objectives; showing the last read", { exact: true }).waitFor({ state: "detached" });

  await go(`challenge/?id=${objective.id}`);
  await page.route("**/objectives", (route) => route.fulfill({ status: 503, body: "Temporarily offline" }));
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await page.getByText("This challenge could not be refreshed", { exact: true }).waitFor();
  assert(!await page.getByText("No such challenge", { exact: true }).count(), "An outage became a missing challenge");
  await page.unroute("**/objectives");
  console.log("PASS filter recovery and stale-data recovery without a reload");

  await go(`payouts/?id=${objective.id}`);
  await page.getByText("Funded in Cairn", { exact: true }).waitFor();
  assert.equal(await page.getByText("Could not read attribution", { exact: true }).count(), 0);
  console.log("PASS attribution reads a real sha256: objective");

  if (objective.piecework) {
    await go(`coordination/?id=${objective.id}`);
    await page.getByText("Slice details", { exact: true }).click();
    assert(await page.getByRole("columnheader", { name: "Pieces (inclusive)" }).isVisible());
    assert(await page.getByRole("columnheader", { name: "Machines reporting" }).isVisible());
    await go(`task/?id=${objective.id}`);
    await page.getByText("Search details and history", { exact: true }).click();
    if (await page.getByText("Coverage details", { exact: true }).count()) {
      await page.getByText("Coverage details", { exact: true }).click();
      assert(await page.getByRole("heading", { name: "Live assignments this epoch" }).isVisible());
    }
    console.log("PASS coordination details without hovering");
  }

  await go("submit/");
  await page.getByRole("link", { name: "A goal names the question. It cannot be blank." }).click();
  assert(await page.locator("#goal").evaluate((element) => element === document.activeElement));
  const record = { ...detail.record, funder: "ux-check", reward: 1 };
  await page.locator("input[type=file]").first().setInputFiles({ name: "objective.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(record)) });
  const pin = await page.locator("#sha").inputValue();
  // Hold a real file digest across canonicalization, reproducing a late file
  // response without replacing the node's canonical bytes with a mock.
  await page.evaluate(() => {
    const digest = crypto.subtle.digest.bind(crypto.subtle);
    crypto.subtle.digest = async (...args) => {
      const result = await digest(...args);
      window.__uxHashWaiting = true;
      await new Promise((resolve) => { window.__uxFinishHash = resolve; });
      return result;
    };
  });
  await page.locator("input[type=file]").nth(1).setInputFiles({ name: "late-checker.py", mimeType: "text/plain", buffer: Buffer.from("late checker") });
  await page.waitForFunction(() => window.__uxHashWaiting);
  let finishPrepare;
  const prepareGate = new Promise((resolve) => { finishPrepare = resolve; });
  await page.route("**/objective/prepare", async (route) => {
    const response = await route.fetch();
    await prepareGate;
    await route.fulfill({ response });
  });
  await page.getByRole("button", { name: "Canonicalize", exact: true }).click();
  await page.waitForFunction(() => document.getElementById("goal").matches(":disabled"));
  await page.evaluate(() => window.__uxFinishHash());
  assert.equal(await page.locator("#sha").inputValue(), pin, "A late file digest changed the authorized draft");
  finishPrepare();
  await page.getByRole("heading", { name: "What the wallet signs" }).waitFor();
  await page.locator("#goal").fill("UX-updated-question");
  assert.equal(await page.getByRole("heading", { name: "What the wallet signs" }).count(), 0, "An edit retained old authorization");
  console.log("PASS actionable validation, request locking and late-file invalidation");
  await page.unroute("**/objective/prepare");

  // A test-only injected wallet holds its response open. Its signature is
  // never submitted: this checks the form lifecycle, not Ed25519 itself.
  await page.addInitScript(() => {
    window.solana = {
      connect: async () => ({ publicKey: "11111111111111111111111111111111" }),
      signMessage: () => new Promise((resolve) => {
        window.__uxFinishSign = () => resolve({ signature: new Uint8Array(64) });
      }),
    };
  });
  await page.reload();
  await page.getByText("Injected wallet connected", { exact: true }).waitFor();
  await page.locator("input[type=file]").first().setInputFiles({ name: "objective.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(record)) });
  await page.getByRole("button", { name: "Canonicalize", exact: true }).click();
  await page.getByRole("heading", { name: "What the wallet signs" }).waitFor();
  await page.getByRole("button", { name: "Sign with Injected wallet", exact: true }).click();
  await page.waitForFunction(() => typeof window.__uxFinishSign === "function");
  assert(await page.locator("#reward").isDisabled(), "Draft remained editable while the wallet was signing");
  await page.evaluate(() => window.__uxFinishSign());
  await page.getByText("Signed. The node will verify it against the funder key.", { exact: true }).waitFor();
  await page.locator("#reward").fill("2");
  assert(await page.getByRole("button", { name: "Submit to the node", exact: true }).isDisabled(), "An edit retained a signature for a different draft");
  console.log("PASS wallet wait locking and signature invalidation on edit");

  // A public-site-like origin reads a real node under the localhost alias.
  // Only discovery is intercepted; health and data at the seed are real.
  const seedContext = await browser.newContext();
  const seedPage = await seedContext.newPage();
  const seed = new URL(reader.origin);
  seed.hostname = reader.hostname === "localhost" ? "127.0.0.1" : "localhost";
  await seedPage.route(`${reader.origin}/health`, (route) => route.fulfill({ contentType: "text/html", body: "<html>Static host</html>" }));
  await seedPage.route("**/seeds.json", (route) => route.fulfill({ json: { version: 1, seeds: [{ http: seed.origin }] } }));
  await seedPage.goto(url("submit/"));
  await seedPage.locator(`span[title="A node answered at ${seed.origin}."]`).first().waitFor();
  await seedPage.getByRole("link", { name: "Open this node’s challenge form →" }).waitFor();
  assert.equal(await seedPage.getByRole("link", { name: "Open this node’s challenge form →" }).getAttribute("href"), `${seed.origin}/ui/submit/`);
  assert(await seedPage.getByRole("button", { name: "Canonicalize", exact: true }).isDisabled());
  await seedContext.close();
  console.log("PASS seed-aware node status and same-origin posting guidance");
  assert.deepEqual(errors, [], "Reader raised browser exceptions");
  console.log("PASS no browser exceptions; no records submitted");
} finally {
  await browser.close();
}
