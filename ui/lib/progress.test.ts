import { describe, expect, it } from "vitest";
import {
  type DerivedWorker,
  type ReportedWorker,
  assignedBins,
  collisionOdds,
  coverageFraction,
  denseHours,
  etaSeconds,
  formatDuration,
  formatLog2,
  formatPercent,
  formatRate,
  mergeWorkers,
  shareOfExpected,
  workForOdds,
  workerRate,
} from "./progress";

const derived = (submitter: string, units_paid: number): DerivedWorker => ({
  submitter,
  claims_paid: 1,
  claims: 1,
  rejected: 0,
  in_flight: 0,
  elements: units_paid,
  units_paid,
  reward: units_paid * 100,
  steps: units_paid * 1000,
  first_paid_at: "2026-10-03T12:00:00+00:00",
  last_paid_at: "2026-10-03T12:00:00+00:00",
});

const reported = (
  worker: string,
  status: ReportedWorker["status"],
  extra: Partial<ReportedWorker> = {},
): ReportedWorker => ({
  worker,
  status,
  first_seen_at: "2026-10-03T12:00:00+00:00",
  received_at: "2026-10-03T12:01:00+00:00",
  age_seconds: 10,
  epoch: 1,
  units: null,
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
  ...extra,
});

describe("mergeWorkers", () => {
  it("puts the two halves on one row by name and orders live first", () => {
    const rows = mergeWorkers(
      [derived("alice", 30), derived("bob", 50), derived("carol", 0)],
      [reported("bob", "stale"), reported("dave", "live"), reported("alice", "live")],
    );
    expect(rows.map((r) => r.name)).toEqual(["alice", "dave", "bob", "carol"]);
    expect(rows[0].derived?.units_paid).toBe(30);
    expect(rows[0].reported?.status).toBe("live");
    expect(rows[1].derived).toBeNull();
    expect(rows[3].status).toBe("settled");
    expect(rows[3].reported).toBeNull();
  });

  it("prefers the node's measured rate to the worker's own", () => {
    expect(workerRate(reported("a", "live", { reported_steps_per_second: 5 }))).toBe(5);
    expect(
      workerRate(reported("a", "live", { reported_steps_per_second: 5, measured_steps_per_second: 7 })),
    ).toBe(7);
    expect(workerRate(reported("a", "live"))).toBeNull();
    expect(workerRate(null)).toBeNull();
  });
});

describe("the search as a whole", () => {
  const E = 2 ** 60.81;

  it("measures share and odds against the expected cost", () => {
    expect(shareOfExpected(E, E)).toBe(1);
    expect(shareOfExpected(0, E)).toBe(0);
    expect(shareOfExpected(1, 0)).toBeNull();
    // At the expected cost the birthday bound gives 1 - exp(-pi/4) = 0.544.
    expect(collisionOdds(E, E)).toBeCloseTo(0.5443, 3);
    expect(collisionOdds(0, E)).toBe(0);
    // Even odds at 0.94 E, nine in ten at 1.71 E: the inverse agrees.
    expect(workForOdds(0.5, E)! / E).toBeCloseTo(0.9394, 3);
    expect(workForOdds(0.9, E)! / E).toBeCloseTo(1.712, 2);
    expect(collisionOdds(workForOdds(0.5, E)!, E)).toBeCloseTo(0.5, 6);
    expect(workForOdds(1, E)).toBeNull();
  });

  it("gives an ETA only with a rate, and a negative one past the expected cost", () => {
    expect(etaSeconds(0, 1000, 10)).toBe(100);
    expect(etaSeconds(1500, 1000, 10)).toBe(-50);
    expect(etaSeconds(0, 1000, 0)).toBeNull();
    expect(etaSeconds(0, 1000, null)).toBeNull();
  });
});

describe("coverage and history", () => {
  it("counts the bins with anything in them", () => {
    expect(
      coverageFraction({
        bins: 4,
        units: 4096,
        trail_bits: 16,
        counts: [3, 0, 1, 0],
        units_touched: 2,
        unbinned: 0,
        method: "",
      }),
    ).toBe(0.5);
    expect(coverageFraction(null)).toBeNull();
  });

  it("maps live assignments onto the same bins the node uses for paid seeds", () => {
    const workers = [
      reported("a", "live", { units: { first: 0, end: 1024 } }),
      reported("b", "live", { units: { first: 1024, end: 2048 } }),
      reported("c", "stale", { units: { first: 2048, end: 3072 } }),
      reported("d", "live", { units: null }),
    ];
    expect(assignedBins(workers, 4096, 8)).toEqual([
      { name: "a", from: 0, to: 1 },
      { name: "b", from: 2, to: 3 },
    ]);
    expect(assignedBins(workers, 0, 8)).toEqual([]);
  });

  it("fills the hours nobody settled in with zeros", () => {
    const now = new Date("2026-10-03T14:20:00Z");
    const dense = denseHours(
      [
        { hour: "2026-10-03T12:00:00+00:00", claims_paid: 1, units_paid: 8, steps: 80 },
        { hour: "2026-10-03T14:00:00+00:00", claims_paid: 2, units_paid: 16, steps: 160 },
      ],
      4,
      now,
    );
    expect(dense.map((h) => h.units_paid)).toEqual([0, 8, 0, 16]);
    expect(dense[0].hour).toBe("2026-10-03T11:00:00+00:00");
  });
});

describe("formatting", () => {
  it("writes magnitudes the way the campaign page does", () => {
    expect(formatLog2(2 ** 60.81)).toBe("2^60.81");
    expect(formatLog2(0)).toBe("2^−∞");
    expect(formatRate(1.4e10)).toBe("14.0 G it/s");
    expect(formatRate(12_345_678)).toBe("12.3 M it/s");
    expect(formatRate(950)).toBe("950 it/s");
    expect(formatRate(null)).toBe("—");
  });

  it("writes durations and percentages at the precision their size needs", () => {
    expect(formatDuration(42)).toBe("42 s");
    expect(formatDuration(12 * 60)).toBe("12 min");
    expect(formatDuration(3 * 86_400 + 4 * 3600)).toBe("3 d 4 h");
    expect(formatDuration(2.5 * 365.25 * 86_400)).toBe("2.5 y");
    expect(formatDuration(-90)).toBe("past by 2 min");
    expect(formatDuration(null)).toBe("—");
    expect(formatPercent(0)).toBe("0%");
    expect(formatPercent(0.00004)).toBe("4.0e-3%");
    expect(formatPercent(0.0042)).toBe("0.420%");
    expect(formatPercent(0.5443)).toBe("54.4%");
    expect(formatPercent(null)).toBe("—");
  });
});
