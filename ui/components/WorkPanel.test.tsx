// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { WorkStatus } from "@/lib/work-control";
import { WorkPanel } from "./WorkPanel";

let root: Root;
let container: HTMLDivElement;
let sent: unknown[];

/** Stand in for Cairn.app's `window.webkit.messageHandlers.cairn`. */
const installApp = (status: WorkStatus) => {
  sent = [];
  Reflect.set(window, "webkit", {
    messageHandlers: {
      cairn: {
        postMessage: async (message: { kind: string }) => {
          sent.push(message);
          return message.kind === "work-status" ? status : true;
        },
      },
    },
  });
};

const render = async (element: React.ReactElement) => {
  await act(async () => root.render(element));
  // Let the first `work-status` round trip settle.
  await act(async () => {});
};
const button = (label: string) =>
  Array.from(container.querySelectorAll("button")).find((element) => element.textContent?.trim() === label);
const text = () => container.textContent ?? "";

beforeEach(() => {
  Reflect.set(globalThis, "IS_REACT_ACT_ENVIRONMENT", true);
  Reflect.deleteProperty(window, "webkit");
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
  Reflect.deleteProperty(window, "webkit");
  vi.restoreAllMocks();
});

describe("WorkPanel in a browser tab", () => {
  it("links to Contribute with this goal already chosen", async () => {
    await render(<WorkPanel objective="sha256:a" base="" />);
    expect(text()).toMatch(/Open this goal in Cairn\.app/);
    const link = container.querySelector<HTMLAnchorElement>('a[href*="contribute"]');
    expect(link?.getAttribute("href")).toBe(`/contribute?objective=${encodeURIComponent("sha256:a")}#compute`);
  });

  it("drops the link back to Contribute when it is already inside that sheet", async () => {
    await render(<WorkPanel objective="sha256:a" base="" embedded />);
    expect(container.querySelector('a[href*="contribute"]')).toBeNull();
  });

  it("draws no outer margin, so each caller spaces it once", async () => {
    await render(<WorkPanel objective="sha256:a" base="" />);
    expect(container.querySelector("section")!.className).not.toMatch(/\bm[btyl]?-\d/);
  });

  it("shows no app controls, since a tab cannot start a process", async () => {
    await render(<WorkPanel objective="sha256:a" base="" onChooseSolver={() => {}} />);
    expect(container.querySelectorAll("button")).toHaveLength(0);
  });
});

describe("WorkPanel inside Cairn.app", () => {
  it("puts the solver choice beside Set up & start", async () => {
    installApp({ state: "idle" });
    const onChooseSolver = vi.fn();
    await render(<WorkPanel objective="sha256:a" base="" embedded onChooseSolver={onChooseSolver} />);
    const start = button("Set up & start");
    const solver = button("Solver…");
    expect(start).toBeDefined();
    expect(solver?.parentElement).toBe(start?.parentElement);
    await act(async () => solver!.click());
    expect(onChooseSolver).toHaveBeenCalledOnce();
  });

  it("omits the solver button where the page does not ask for it", async () => {
    installApp({ state: "idle" });
    await render(<WorkPanel objective="sha256:a" base="" />);
    expect(button("Set up & start")).toBeDefined();
    expect(button("Solver…")).toBeUndefined();
  });

  it("starts work on the panel's goal through the app", async () => {
    installApp({ state: "idle" });
    await render(<WorkPanel objective="sha256:a" base="" />);
    await act(async () => button("Set up & start")!.click());
    expect(sent).toContainEqual({ kind: "start-work", objective: "sha256:a" });
  });
});
