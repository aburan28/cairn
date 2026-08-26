import { describe, expect, it } from "vitest";
import { type Objective, type Ratchet, overspent, poolFraction, ratchetProgress } from "./objectives";

const objective = (reward: number, paid: number, remaining: number): Objective => ({
  id: "sha256:o",
  goal: "GOAL",
  funder: "treasury",
  reward,
  statement: "",
  settled: false,
  verifier_kind: "evaluator",
  frontier: {
    claim_id: "sha256:c",
    holder: "carol",
    must_cite: "sha256:c",
    paid_cumulative: paid,
    pool_remaining: remaining,
    score: 1,
  },
});

describe("overspent", () => {
  it("is false with no frontier, because nothing has been paid", () => {
    expect(overspent({ ...objective(100, 0, 100), frontier: undefined })).toBe(false);
  });

  it("is false when paid plus remaining is the reward", () => {
    expect(overspent(objective(1_100_000, 1_100_000, 0))).toBe(false);
    expect(overspent(objective(1_000, 300, 700))).toBe(false);
  });

  it("is false when the pool is under-accounted, which is odd but not overspent", () => {
    expect(overspent(objective(1_000, 300, 600))).toBe(false);
  });

  it("is true when the node published more than the funding covers", () => {
    expect(overspent(objective(1_000, 300, 701))).toBe(true);
  });
});

describe("poolFraction", () => {
  it("is the remaining pool against what was funded", () => {
    expect(poolFraction(objective(1_000, 250, 750))).toBe(0.75);
  });

  it("clamps an overspent pool rather than showing more than all of it", () => {
    expect(poolFraction(objective(1_000, 0, 2_000))).toBe(1);
  });

  it("is null with no frontier or no reward", () => {
    expect(poolFraction({ ...objective(1_000, 0, 0), frontier: undefined })).toBeNull();
    expect(poolFraction(objective(0, 0, 0))).toBeNull();
  });
});

describe("ratchetProgress", () => {
  const maximize: Ratchet = {
    baseline: 9,
    target: 20,
    direction: "maximize",
    min_improvement: 3,
    reward: 1_100_000,
  };
  const minimize: Ratchet = {
    baseline: 100,
    target: 40,
    direction: "minimize",
    min_improvement: 5,
    reward: 1_000,
  };

  it("counts up for maximize", () => {
    expect(ratchetProgress(maximize, 9)).toBe(0);
    expect(ratchetProgress(maximize, 20)).toBe(1);
    expect(ratchetProgress(maximize, 12)).toBeCloseTo(3 / 11);
  });

  it("counts down for minimize", () => {
    // The direction is not consulted; the sign of the span carries it. That
    // is fine as long as a minimize ratchet's target is below its baseline,
    // which is what "minimize" means -- pinned here because a bar that
    // filled as the score rose would show a worse result as progress.
    expect(ratchetProgress(minimize, 100)).toBe(0);
    expect(ratchetProgress(minimize, 40)).toBe(1);
    expect(ratchetProgress(minimize, 70)).toBeCloseTo(0.5);
  });

  it("clamps to [0, 1] beyond the target or behind the baseline", () => {
    expect(ratchetProgress(maximize, 25)).toBe(1);
    expect(ratchetProgress(maximize, 2)).toBe(0);
    expect(ratchetProgress(minimize, 10)).toBe(1);
    expect(ratchetProgress(minimize, 150)).toBe(0);
  });

  it("is null for a degenerate span rather than a confident wrong number", () => {
    expect(ratchetProgress({ ...maximize, target: 9 }, 9)).toBeNull();
  });
});
