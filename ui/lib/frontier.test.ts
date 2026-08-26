import { describe, expect, it } from "vitest";
import { type Frontier, overspent, ratchetProgress } from "./frontier";
import { ratchetProgress as objectivesRatchetProgress } from "./objectives";

// `frontier.ts` keeps its own copies of `ratchetProgress` and `overspent`
// rather than importing them, so the two pages share no dependency. A copy
// is a thing that drifts; these tests hold the copies to the same answers.

const frontier = (paid: number, remaining: number): Frontier => ({
  claim_id: "sha256:c",
  holder: "carol",
  must_cite: "sha256:c",
  paid_cumulative: paid,
  pool_remaining: remaining,
  score: 1,
});

describe("overspent (frontier.ts copy)", () => {
  it("is false when paid plus remaining is at most the reward", () => {
    expect(overspent(frontier(300, 700), 1_000)).toBe(false);
    expect(overspent(frontier(300, 600), 1_000)).toBe(false);
  });

  it("is true when the node published more than the funding covers", () => {
    expect(overspent(frontier(300, 701), 1_000)).toBe(true);
  });
});

describe("ratchetProgress (frontier.ts copy)", () => {
  const maximize = { baseline: 9, target: 20, direction: "maximize", min_improvement: 3, reward: 1 };
  const minimize = { baseline: 100, target: 40, direction: "minimize", min_improvement: 5, reward: 1 };

  it("counts up for maximize and down for minimize", () => {
    expect(ratchetProgress(maximize, 12)).toBeCloseTo(3 / 11);
    expect(ratchetProgress(minimize, 70)).toBeCloseTo(0.5);
  });

  it("clamps and refuses a degenerate span", () => {
    expect(ratchetProgress(maximize, 25)).toBe(1);
    expect(ratchetProgress(minimize, 150)).toBe(0);
    expect(ratchetProgress({ ...minimize, target: 100 }, 100)).toBeNull();
  });

  it("agrees with objectives.ts for every score on both ratchets", () => {
    for (const ratchet of [maximize, minimize]) {
      for (let score = 0; score <= 160; score += 1) {
        expect(ratchetProgress(ratchet, score)).toBe(objectivesRatchetProgress(ratchet, score));
      }
    }
  });
});
