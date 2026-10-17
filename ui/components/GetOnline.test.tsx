// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { GetOnline, GetOnlineLink } from "./GetOnline";

let root: Root;
let container: HTMLDivElement;
const dialog = () => container.querySelector('[role="dialog"]');
const click = async (label: string) => {
  const button = Array.from(container.querySelectorAll("button")).find((button) =>
    button.getAttribute("aria-label") === label || button.textContent?.trim() === label);
  expect(button, `missing actual trigger ${label}`).toBeDefined();
  await act(async () => { button!.click(); });
};
const mount = async () => {
  root = createRoot(container);
  await act(async () => root.render(<><GetOnline /><GetOnlineLink /></>));
};

beforeEach(() => {
  Reflect.set(globalThis, "IS_REACT_ACT_ENVIRONMENT", true);
  window.localStorage.clear();
  document.head.innerHTML = "";
  container = document.createElement("div");
  document.body.appendChild(container);
});
afterEach(async () => {
  await act(async () => root?.unmount());
  container.remove();
  vi.restoreAllMocks();
});

describe("setup recovery lifecycle through the actual trigger", () => {
  for (const profile of ["private", "public"] as const) {
    it(`remembers automatic dismissal and permits repeated explicit recovery (${profile})`, async () => {
      if (profile === "private") document.head.innerHTML = '<meta name="cairn-network" content="private"/>';
      const expected = profile === "private" ? /private installation/ : /tailscale up/;
      const unexpected = profile === "private" ? /tailscale|funnel/i : /private installation/;
      await mount();
      expect(dialog()?.textContent).toMatch(expected);
      expect(dialog()?.textContent).not.toMatch(unexpected);
      await click("Close");
      expect(dialog()).toBeNull();
      await act(async () => root.unmount());
      await mount();
      expect(dialog()).toBeNull(); // A fresh mount honors the saved preference.
      for (let attempt = 0; attempt < 2; attempt++) {
        await click("Get this node online →");
        expect(dialog(), "explicit recovery request must reopen the dismissed setup").not.toBeNull();
        expect(dialog()?.textContent).toMatch(expected);
        expect(dialog()?.textContent).not.toMatch(unexpected);
        await click("Close");
        expect(dialog()).toBeNull();
      }
    });
  }

  it("still dismisses and explicitly reopens when storage is unavailable", async () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new Error("storage blocked"); });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("storage blocked"); });
    await mount();
    expect(dialog()).not.toBeNull();
    await click("Close");
    expect(dialog()).toBeNull();
    await click("Get this node online →");
    expect(dialog()).not.toBeNull();
  });
});
