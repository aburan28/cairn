import { describe, expect, it } from "vitest";
import type { ReportedWorker } from "./progress";
import {
  type TaskLeases,
  claimCommand,
  coverageSummary,
  epochProgress,
  leaseRows,
  leaseTone,
  partitionHolders,
  partitionUnits,
  taskTone,
} from "./leases";

const reported = (
  worker: string,
  status: ReportedWorker["status"],
  units: { first: number; end: number } | null,
): ReportedWorker => ({
  worker,
  status,
  first_seen_at: "2026-10-04T12:00:00+00:00",
  received_at: "2026-10-04T12:01:00+00:00",
  age_seconds: 10,
  epoch: 1,
  units,
  unit: null,
  steps: 0,
  trails: 0,
  capped: 0,
  units_pending: 0,
  units_submitted: 0,
  reported_steps_per_second: null,
  measured_steps_per_second: null,
  device: null,
  lanes: null,
  client: null,
});

const lease = (
  task: string,
  holder: string,
  status: "held" | "contended" | "expired" | "released",
  expiresIn: number,
  units: { first: number; end: number } | null = null,
): TaskLeases => ({
  task,
  status: status === "held" || status === "contended" ? "held" : "open",
  holder: status === "held" ? holder : null,
  completed_by: null,
  leases: [
    {
      holder,
      status,
      since: "2026-10-04T12:00:00+00:00",
      renewed_at: "2026-10-04T12:00:00+00:00",
      expires_at: "2026-10-04T12:10:00+00:00",
      expires_in_seconds: expiresIn,
      ttl_seconds: 600,
      units,
      epoch: 1,
      note: null,
      released: status === "released" ? { at: "2026-10-04T12:05:00+00:00", outcome: "failed" } : null,
    },
  ],
});

describe("partitionUnits", () => {
  it("abuts neighbouring partitions and runs the last one to the end, as the node does", () => {
    // The node's own test: 4 partitions over 4096 units are [0,1024), …, [3072,4096).
    const ranges = [0, 1, 2, 3].map((k) => partitionUnits(k, 4, 4096));
    expect(ranges[0]).toEqual({ first: 0, end: 1024 });
    expect(ranges[3]).toEqual({ first: 3072, end: 4096 });
    for (let k = 1; k < 4; k += 1) expect(ranges[k].first).toBe(ranges[k - 1].end);
  });

  it("gives the remainder of a truncating step to the last partition", () => {
    // 2^32 / 3 truncates, so the first two slices are short and the third
    // absorbs what is left; in units the three still partition the space.
    const ranges = [0, 1, 2].map((k) => partitionUnits(k, 3, 1_000_000));
    expect(ranges[0].first).toBe(0);
    expect(ranges[2].end).toBe(1_000_000);
    expect(ranges[1].first).toBe(ranges[0].end);
    expect(ranges[2].first).toBe(ranges[1].end);
    expect(ranges[2].end - ranges[2].first).toBeGreaterThanOrEqual(ranges[0].end - ranges[0].first);
  });

  it("survives a unit count a double would lose, by doing the arithmetic in BigInt", () => {
    // ECC2K-130's 2^48 units: 2^48 * 2^32 = 2^80 overflows a double's mantissa.
    const units = 2 ** 48;
    const last = partitionUnits(7, 8, units);
    expect(last.end).toBe(units);
    expect(last.first).toBe(7 * 2 ** 45);
  });

  it("covers nothing for a malformed ask, rather than somebody else's slice", () => {
    expect(partitionUnits(4, 4, 4096)).toEqual({ first: 0, end: 0 });
    expect(partitionUnits(0, 0, 4096)).toEqual({ first: 0, end: 0 });
  });
});

describe("partitionHolders", () => {
  it("places live workers and live leases on the partitions their ranges overlap", () => {
    const cells = partitionHolders(
      [
        reported("alice", "live", { first: 0, end: 1024 }),
        reported("bob", "live", { first: 1000, end: 2048 }), // straddles 0 and 1
        reported("carol", "stale", { first: 2048, end: 3072 }), // stale: not on it
        reported("dave", "live", null), // no range: nowhere
      ],
      [lease("unit:3100", "erin", "held", 300, { first: 3100, end: 3101 })],
      4096,
      4,
    );
    expect(cells.map((c) => c.holders)).toEqual([["alice", "bob"], ["bob"], [], []]);
    expect(cells.map((c) => c.leased)).toEqual([[], [], [], ["erin"]]);
    expect(coverageSummary(cells)).toEqual({ covered: 1, uncovered: 2, contested: 1 });
  });

  it("is empty with no units or no partitions", () => {
    expect(partitionHolders([], [], 0, 4)).toEqual([]);
    expect(partitionHolders([], [], 4096, 0)).toEqual([]);
  });
});

describe("leaseRows", () => {
  it("lists held first, then contended, expired and released, soonest expiry first", () => {
    const rows = leaseRows([
      lease("b", "x", "released", 0),
      lease("a", "y", "held", 500),
      lease("c", "z", "held", 100),
      lease("d", "w", "contended", 50),
      lease("e", "v", "expired", 0),
    ]);
    expect(rows.map((r) => `${r.task}:${r.status}`)).toEqual([
      "c:held",
      "a:held",
      "d:contended",
      "e:expired",
      "b:released",
    ]);
    expect(rows[0].taskStatus).toBe("held");
  });
});

describe("the epoch clock and tones", () => {
  it("reads 0 at the start of an epoch and 1 at its turn", () => {
    expect(epochProgress(600, 600)).toBe(0);
    expect(epochProgress(600, 150)).toBe(0.75);
    expect(epochProgress(600, 0)).toBe(1);
    expect(epochProgress(0, 0)).toBe(0);
  });

  it("colours a held lease as good, a contended one as a warning", () => {
    expect(leaseTone("held")).toBe("accent");
    expect(leaseTone("contended")).toBe("warn");
    expect(leaseTone("expired")).toBe("neutral");
    expect(leaseTone("released")).toBe("info");
    expect(taskTone("completed")).toBe("info");
    expect(taskTone("open")).toBe("neutral");
  });

  it("writes a claim command against the node that served the page, with a unit inside the space", () => {
    const text = claimCommand("http://127.0.0.1:8080", "sha256:abc", 100);
    expect(text).toContain("http://127.0.0.1:8080/lease");
    expect(text).toContain('"task": "unit:99"');
    expect(text).toContain('"first": 99, "end": 100');
    expect(claimCommand("", "sha256:abc", null)).toContain('"task": "unit:4017"');
  });
});
