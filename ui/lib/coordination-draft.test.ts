import { describe, expect, it } from "vitest";
import { type Bridge } from "./draft";
import { coordinationBudget, coordinationStatus, generateCoordination, launchCoordination } from "./coordination-draft";

const idle = { phase: "idle", brief: "", budget: "", message: "", provider: "" };
function recorder(reply: unknown = idle) {
  const sent: unknown[] = [];
  const bridge: Bridge = { postMessage: async (value) => { sent.push(value); return reply; } };
  return { bridge, sent };
}

describe("background coordinated challenge drafting", () => {
  it("preserves exact amounts including integers beyond JavaScript's safe range", () => {
    expect(coordinationBudget(" 18,446,744,073,709,551,615 ")).toBe("18446744073709551615");
    expect(coordinationBudget("9_007_199_254_740_993")).toBe("9007199254740993");
    expect(coordinationBudget("  ")).toBe("");
    for (const amount of ["0", "-1", "1.5", "1e3", "18446744073709551616", ",", "１２"]) {
      expect(() => coordinationBudget(amount)).toThrow();
    }
  });

  it("sends the description and budget directly to the native background flow", async () => {
    const { bridge, sent } = recorder({ ...idle, phase: "drafting" });
    expect((await generateCoordination(bridge, "  work on ecc2p 130 challenge  ", "8,000")).phase).toBe("drafting");
    expect(sent).toEqual([{ kind: "draft-coordination", brief: "work on ecc2p 130 challenge", budget: "8000" }]);
  });

  it("does not send invalid inputs or credentials", async () => {
    const { bridge, sent } = recorder();
    await expect(generateCoordination(bridge, "short", "100")).rejects.toThrow();
    await expect(generateCoordination(bridge, "compute integer squares", "1.5")).rejects.toThrow();
    expect(sent).toEqual([]);
  });

  it("launches by the checked native draft id without accepting a spec from the page", async () => {
    const { bridge, sent } = recorder();
    await launchCoordination(bridge, "checked-draft-id");
    expect(sent).toEqual([{ kind: "launch-coordination", draftId: "checked-draft-id" }]);
  });

  it("refuses incomplete ready responses and old app handlers", async () => {
    await expect(coordinationStatus(recorder({ ...idle, phase: "ready", spec: "{}" }).bridge)).rejects.toThrow(/incomplete/);
    await expect(coordinationStatus(recorder(true).bridge)).rejects.toThrow(/Update Cairn/);
    const bridge: Bridge = { postMessage: async () => { throw new Error("Add a provider key in Settings → AI."); } };
    await expect(generateCoordination(bridge, "compute integer squares", "")).rejects.toThrow(/provider key/);
  });
});
