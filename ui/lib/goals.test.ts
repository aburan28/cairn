import { describe, expect, it } from "vitest";
import { type Goal, angleLabel, composeHandle, describeMatch, normalizeGoal, parseHandle } from "./goals";

const goal = (over: Partial<Goal>): Goal => ({
  key: "certicomecc2k130",
  name: "ECC2K-130",
  handle: "GOAL-certicom-ecc2k130",
  handles: ["GOAL-certicom-ecc2k130"],
  known: true,
  aliases: ["ecc2k-130", "ecc2k130"],
  family: "certicom",
  summary: "The Certicom ECC2K-130 challenge.",
  objectives: 0,
  open: 0,
  settled: 0,
  reward_total: 0,
  live_workers: 0,
  angles: [],
  ...over,
});

describe("goal handles", () => {
  it("normalises the way the node does: no prefix, no case, no punctuation", () => {
    for (const spelling of ["GOAL-certicom-ecc2k130", "goal-Certicom_ECC2K-130", "Certicom ECC2K-130"]) {
      expect(normalizeGoal(spelling)).toBe("certicomecc2k130");
    }
    expect(normalizeGoal("goals")).toBe("goals");
  });

  it("takes a handle apart into key and angle, and puts one together", () => {
    expect(parseHandle("GOAL-certicom-ecc2k130/rho/gpu-kernel")).toEqual({
      goal: "GOAL-certicom-ecc2k130",
      key: "certicomecc2k130",
      angle: ["rho", "gpu-kernel"],
    });
    expect(parseHandle("GOAL-capset-lower-bounds").angle).toEqual([]);
    expect(parseHandle(" ECC2K-130 / rho / ").angle).toEqual(["rho"]);
    expect(composeHandle("certicom-ecc2k130", ["Rho", "GPU-Kernel"])).toBe("GOAL-certicom-ecc2k130/rho/gpu-kernel");
    expect(composeHandle("GOAL-x", [])).toBe("GOAL-x");
    expect(angleLabel("")).toBe("no particular approach");
    expect(angleLabel("rho/distributed")).toBe("rho/distributed");
  });
});

describe("describeMatch", () => {
  it("says a known goal nobody funded is open for its first objective", () => {
    expect(describeMatch(goal({}))).toBe(
      "ECC2K-130 is a known goal with nothing funded yet; post the first objective as GOAL-certicom-ecc2k130.",
    );
  });

  it("counts what exists, names the spellings it joined, and points at the angle form", () => {
    const text = describeMatch(
      goal({
        objectives: 4,
        open: 3,
        settled: 1,
        handles: ["GOAL-certicom-ecc2k130", "GOAL-ecc2k-130"],
        angles: [
          { path: "", segments: [], parent: null, objectives: [], open: 1, settled: 0, live_workers: 0 },
          { path: "rho/distributed", segments: ["rho", "distributed"], parent: "rho", objectives: [], open: 1, settled: 0, live_workers: 2 },
          { path: "index-calculus", segments: ["index-calculus"], parent: null, objectives: [], open: 1, settled: 1, live_workers: 0 },
        ],
      }),
    );
    expect(text).toContain("4 objectives (3 open)");
    expect(text).toContain("also written GOAL-ecc2k-130");
    expect(text).toContain("2 angles: rho/distributed, index-calculus");
    expect(text).toContain("Post yours as GOAL-certicom-ecc2k130/<angle>");
  });

  it("says when nobody has named an angle yet", () => {
    const text = describeMatch(
      goal({
        objectives: 1,
        open: 1,
        angles: [{ path: "", segments: [], parent: null, objectives: [], open: 1, settled: 0, live_workers: 0 }],
      }),
    );
    expect(text).toContain("1 objective (1 open)");
    expect(text).toContain("no angle named yet");
  });
});
