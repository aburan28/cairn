import { describe, expect, it } from "vitest";
import {
  type FleetWorker,
  classLabel,
  fleetTotals,
  formatMemory,
  formatUptime,
  reachTone,
  roleWarning,
  share,
  sumByClass,
} from "./network";

const worker = (
  name: string,
  status: FleetWorker["status"],
  cls: FleetWorker["class"],
  rate: number | null,
  lanes: number | null = null,
): FleetWorker => ({
  worker: name,
  objective_id: "sha256:o",
  goal: "ECC2K-130",
  status,
  age_seconds: 10,
  device: cls === "unreported" ? "unreported" : `a ${cls}`,
  class: cls,
  lanes,
  client: null,
  steps_per_second: rate,
  epoch: 3,
  units: null,
});

describe("fleetTotals", () => {
  it("sums rates and lanes over live workers only, and counts the rest", () => {
    const totals = fleetTotals([
      worker("a", "live", "gpu", 5000, 128),
      worker("b", "live", "cpu", 40, 16),
      worker("c", "stale", "gpu", 9999, 999),
      worker("d", "gone", "apple", null),
      worker("e", "live", "unreported", null),
    ]);
    expect(totals).toEqual({
      workers: 5,
      live: 3,
      stale: 1,
      gone: 1,
      steps_per_second: 5040,
      lanes: 144,
    });
  });

  it("is zero over nobody", () => {
    expect(fleetTotals([]).steps_per_second).toBe(0);
    expect(fleetTotals([]).workers).toBe(0);
  });
});

describe("sumByClass", () => {
  it("groups by class with the fastest class first and counts stale workers without their rate", () => {
    const rows = sumByClass([
      worker("a", "live", "gpu", 5000),
      worker("b", "live", "cpu", 40),
      worker("c", "stale", "cpu", 1_000_000),
      worker("d", "live", "gpu", 3000),
    ]);
    expect(rows.map((r) => r.class)).toEqual(["gpu", "cpu"]);
    expect(rows[0]).toMatchObject({ workers: 2, live: 2, steps_per_second: 8000 });
    expect(rows[1]).toMatchObject({ workers: 2, live: 1, steps_per_second: 40 });
  });
});

describe("labels and tones", () => {
  it("names every class the node can send, and says other for one it cannot", () => {
    expect(classLabel("gpu")).toBe("GPU");
    expect(classLabel("apple")).toBe("Apple silicon");
    expect(classLabel("fpga")).toBe("FPGA");
    expect(classLabel("unreported")).toBe("unreported");
    expect(classLabel("quantum")).toBe("other");
  });

  it("colours reach so that lost reads as nothing and unreached as a problem", () => {
    expect(reachTone("reached")).toBe("accent");
    expect(reachTone("recent")).toBe("warn");
    expect(reachTone("lost")).toBe("neutral");
    expect(reachTone("unreached")).toBe("bad");
  });

  it("picks the node's own warning for a role, and nothing for a backed one", () => {
    const warnings = [
      "declares coordinator but accepts no submissions (started without --queue): …",
      "declares relay but this process runs no p2p service …",
    ];
    expect(roleWarning("coordinator", warnings)).toMatch(/--queue/);
    expect(roleWarning("relay", warnings)).toMatch(/p2p/);
    expect(roleWarning("verifier", warnings)).toBeNull();
  });
});

describe("formatting", () => {
  it("formats uptime in the largest two units that matter", () => {
    expect(formatUptime(40)).toBe("40s");
    expect(formatUptime(12 * 60)).toBe("12m");
    expect(formatUptime(2 * 3600 + 5 * 60)).toBe("2h 05m");
    expect(formatUptime(3 * 86_400 + 4 * 3600)).toBe("3d 4h");
    expect(formatUptime(-1)).toBe("—");
  });

  it("formats memory in MiB below a GiB and GiB above, and dashes the unknown", () => {
    expect(formatMemory(512)).toBe("512 MiB");
    expect(formatMemory(15932)).toBe("15.6 GiB");
    expect(formatMemory(1024 * 1024)).toBe("1024 GiB");
    expect(formatMemory(null)).toBe("—");
  });

  it("clamps a share into [0, 1] and is 0 with no total", () => {
    expect(share(50, 200)).toBe(0.25);
    expect(share(500, 200)).toBe(1);
    expect(share(null, 200)).toBe(0);
    expect(share(5, 0)).toBe(0);
  });
});
