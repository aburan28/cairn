// Read-only acceptance against the reader served by the actual Windows exe.
import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import { chromium } from "playwright";

const base = new URL(process.env.CAIRN_WINDOWS_READER_URL);
assert(["127.0.0.1", "localhost"].includes(base.hostname), "Use the isolated local Windows fixture");
const shots = process.env.CAIRN_UX_SCREENSHOTS;
if (shots) await mkdir(shots, { recursive: true });
const browser = await chromium.launch({ executablePath: process.env.CAIRN_BROWSER_PATH || undefined, args: process.env.CAIRN_UX_NO_SANDBOX === "1" ? ["--no-sandbox"] : [] });
try {
  const page = await browser.newPage();
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto(base.href);
  const firstRun = page.getByRole("dialog", { name: "Get this node online", exact: true });
  await firstRun.waitFor();
  const welcome = await firstRun.innerText();
  assert(!welcome.includes("127.0.0.1") && !welcome.includes("0.0.0.0"), "First-run sharing prompt displays raw endpoints");
  await firstRun.getByRole("button", { name: "Close", exact: true }).focus();
  await page.keyboard.press("Tab");
  assert(await page.evaluate(() => document.activeElement?.tagName === "SUMMARY"), "Advanced setup is unreachable by keyboard");
  await page.keyboard.press("Enter");
  assert((await firstRun.innerText()).includes("127.0.0.1"), "Advanced setup lost its real commands");
  for (let i = 0; i < 14; i++) {
    await page.keyboard.press(i < 7 ? "Tab" : "Shift+Tab");
    assert(await page.evaluate(() => Boolean(document.activeElement?.closest("dialog[open]"))), "First-run dialog leaked keyboard focus");
  }
  await page.keyboard.press("Escape");
  await firstRun.waitFor({ state: "detached" });
  for (const width of [320, 360, 1280]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto(new URL("network/", base).href);
    await page.getByText("Availability", { exact: true }).waitFor();
    const text = await page.locator("body").innerText();
    assert(!text.includes("127.0.0.1") && !text.includes("0.0.0.0"), "Main UI displays listener plumbing");
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `Network overflows at ${width}px`);
    if (shots) await page.screenshot({ path: `${shots}/windows-network-${width}.png`, fullPage: true });
  }
  await page.keyboard.press("Control+k");
  await page.getByRole("textbox", { name: "Find a page" }).fill("Diagnostics");
  await page.keyboard.press("Enter");
  await page.getByRole("heading", { level: 1, name: "Diagnostics", exact: true }).waitFor();
  await page.getByText("Reader listener", { exact: true }).waitFor();
  assert((await page.locator("body").innerText()).includes("127.0.0.1"), "Diagnostics lost the actual local endpoint");
  assert.deepEqual(errors, [], "Windows-served reader raised browser exceptions");
  console.log("PASS Windows-served browser UI: three widths, no prominent placeholders, Ctrl K and Diagnostics");
} finally {
  await browser.close();
}
