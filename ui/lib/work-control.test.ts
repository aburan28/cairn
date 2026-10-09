import { describe, expect, it } from "vitest";
import type { Bridge } from "./draft";
import { readWorkStatus, startWork, stopWork } from "./work-control";

describe("Cairn.app worker bridge", () => {
  it("names only an objective when asking the app to start its saved solver", async () => {
    const sent: unknown[] = [];
    const bridge: Bridge = { postMessage: async (message) => { sent.push(message); return true; } };
    const objective = `sha256:${"ab".repeat(32)}`;
    await startWork(bridge, objective);
    await stopWork(bridge);
    expect(sent).toEqual([{ kind: "start-work", objective }, { kind: "stop-work" }]);
  });

  it("reads local state and refuses an unknown app reply", async () => {
    const bridge: Bridge = { postMessage: async () => ({ state: "running", cpu_percent: 125 }) };
    await expect(readWorkStatus(bridge)).resolves.toMatchObject({ state: "running", cpu_percent: 125 });
    await expect(readWorkStatus({ postMessage: async () => ({ state: "stopping" }) })).resolves.toMatchObject({ state: "stopping" });
    await expect(readWorkStatus({ postMessage: async () => ({ state: "mystery" }) })).rejects.toThrow("unknown work state");
  });
});
