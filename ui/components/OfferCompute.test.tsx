// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Objective } from "@/lib/site";
import type { Underserved } from "@/lib/goals";
import { OfferCompute } from "./OfferCompute";

let root: Root;
let container: HTMLDivElement;

const goal = (id: string, statement: string, extra: Partial<Objective> = {}): Objective =>
  ({ id, goal: "", statement, reward: 10_000, funder: "treasury", verifier_kind: "certificate", settled: false, open: true, settlement: null, ...extra }) as Objective;

const ECC = goal("sha256:ecc", "Find the private key for the ECC2K-130 challenge curve.");
const RHO = goal("sha256:rho", "Contribute distinguished orbits to the shared rho search.", {
  piecework: { unit_price: 100, paid_units: 18, paid_total: 1800, pool_remaining: 0, units: 4096 },
});

type Props = Parameters<typeof OfferCompute>[0];
const defaults = (): Props => ({
  network: null,
  objectives: [],
  live: true,
  onRetry: () => {},
  requestedObjective: null,
  underserved: [],
  origin: "",
  bridge: null,
  busy: false,
  onShare: () => {},
  onWork: () => {},
});

const render = async (props: Partial<Props> = {}) => {
  await act(async () => root.render(<OfferCompute {...defaults()} {...props} />));
};
const text = () => container.textContent ?? "";
const select = () => container.querySelector<HTMLSelectElement>("select");
const button = (label: string) =>
  Array.from(container.querySelectorAll("button")).find((element) => element.textContent?.trim() === label);
const link = (label: string) =>
  Array.from(container.querySelectorAll("a")).find((element) => element.textContent?.trim() === label);

beforeEach(() => {
  Reflect.set(globalThis, "IS_REACT_ACT_ENVIRONMENT", true);
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
  vi.restoreAllMocks();
});

describe("Offer compute with no goal to offer", () => {
  it("says it is reading before the first answer, not that the node is empty", async () => {
    await render({ live: null });
    expect(text()).toMatch(/Reading open goals/);
    expect(text()).not.toMatch(/No open goal/);
    expect(select()).toBeNull();
  });

  it("tells a failed read apart from an empty node and offers a retry", async () => {
    const onRetry = vi.fn();
    await render({ live: false, onRetry });
    expect(text()).toMatch(/Could not read this node.s goals/);
    expect(text()).not.toMatch(/No open goal/);
    await act(async () => button("Try again now")!.click());
    expect(onRetry).toHaveBeenCalledOnce();
  });

  it("explains an empty node and points somewhere useful", async () => {
    await render({ live: true, objectives: [] });
    expect(text()).toMatch(/No open goal on this node/);
    expect(link("Check peers")?.getAttribute("href")).toMatch(/\/network/);
    expect(link("Fund a question →")?.getAttribute("href")).toMatch(/\/submit/);
  });

  it("shows no disabled controls or worker metrics footnote", async () => {
    await render({ live: true, objectives: [] });
    expect(container.querySelector("button:disabled, select:disabled")).toBeNull();
    expect(text()).not.toMatch(/CPU use is measured/);
    expect(container.querySelector('[aria-label="My work on this Mac"]')).toBeNull();
  });
});

describe("Offer compute with open goals", () => {
  it("lists the open goals and shows what the chosen one pays", async () => {
    await render({ objectives: [ECC, RHO] });
    expect(Array.from(select()!.options).map((option) => option.value)).toEqual([ECC.id, RHO.id]);
    expect(select()!.value).toBe(ECC.id);
    expect(text()).toMatch(/Bounty 10,000/);
    expect(link("Details →")?.getAttribute("href")).toBe(`/challenge?id=${encodeURIComponent(ECC.id)}`);
    expect(container.querySelector('[aria-label="My work on this Mac"]')).not.toBeNull();
  });

  it("shows price per unit and units left on a divided search", async () => {
    await render({ objectives: [RHO] });
    expect(text()).toMatch(/100 per unit · 4,078 of 4,096 left/);
  });

  it("preselects the goal a link asked for", async () => {
    await render({ objectives: [ECC, RHO], requestedObjective: RHO.id });
    expect(select()!.value).toBe(RHO.id);
  });

  it("preselects and flags an underserved goal", async () => {
    const scarce = { objectives: [RHO.id] } as Underserved;
    await render({ objectives: [ECC, RHO], underserved: [scarce] });
    expect(select()!.value).toBe(RHO.id);
    expect(text()).toMatch(/needs workers/);
  });

  it("moves to another goal when the chosen one closes", async () => {
    await render({ objectives: [ECC, RHO], requestedObjective: RHO.id });
    await render({ objectives: [ECC], requestedObjective: RHO.id });
    expect(select()!.value).toBe(ECC.id);
    await render({ objectives: [] });
    expect(text()).toMatch(/No open goal on this node/);
  });

  it("does not repeat the open-in-Cairn.app hint or link back to this page outside the app", async () => {
    await render({ objectives: [ECC] });
    expect(text().match(/in Cairn\.app/g)?.length ?? 0).toBeLessThanOrEqual(2);
    expect(link("See ways to contribute →")).toBeUndefined();
    expect(button("Worker settings…")).toBeUndefined();
  });

  it("offers sharing only when other machines cannot reach the node", async () => {
    const onShare = vi.fn();
    const network = { node: { reach: { lan: false } } } as unknown as Props["network"];
    const bridge = { postMessage: async () => ({ state: "idle" }) };
    await render({ objectives: [ECC], network, bridge, onShare });
    expect(text()).toMatch(/Other machines cannot reach this node yet/);
    await act(async () => button("Share this node on my network")!.click());
    expect(onShare).toHaveBeenCalledOnce();
  });
});
