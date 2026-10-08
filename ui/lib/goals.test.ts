import { describe, expect, it } from "vitest";
import {
  type Goal,
  type Underserved,
  angleLabel,
  describeAngle,
  composeHandle,
  describeMatch,
  describeUnderserved,
  normalizeGoal,
  parseHandle,
} from "./goals";

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
  });
});

describe("angleLabel and describeAngle", () => {
  const entry = (id: string, reward = 100, kind = "certificate") => ({
    id,
    goal: "GOAL-x",
    statement_excerpt: "",
    verifier_kind: kind,
    reward,
    funder: "f",
    settled: false,
    open: true,
    live_workers: 0,
  });
  const angle = (path: string, ids: string[]) => ({
    path,
    segments: path ? path.split("/") : [],
    parent: path.includes("/") ? path.split("/")[0] : null,
    objectives: ids.map((id) => entry(id)),
    open: ids.length,
    settled: 0,
    live_workers: 0,
  });

  it("names an unnamed approach by its place and its first objective, never 'no particular approach'", () => {
    expect(angleLabel(angle("", ["sha256:7c3e19aa00", "sha256:ffff"]), 0)).toBe("Approach 1 · 7c3e19");
    expect(angleLabel(angle("", ["sha256:0011223344"]), 2)).toBe("Approach 3 · 001122");
    expect(angleLabel(angle("", []), 1)).toBe("Approach 2");
  });

  it("keeps a named angle's own words", () => {
    expect(angleLabel(angle("rho/distributed", ["sha256:ab"]), 4)).toBe("rho/distributed");
  });

  it("explains an angle from its family and what is funded under it", () => {
    const lines = describeAngle({ ...angle("rho/gpu-kernel", ["sha256:a", "sha256:b"]), live_workers: 2 });
    expect(lines[0]).toMatch(/^Pollard rho/);
    expect(lines).toContain("A refinement of rho.");
    expect(lines).toContain("2 objectives (2 open), 200 units funded in all, answers checked by certificate.");
    expect(lines).toContain("2 machines are working on it now.");
    expect(describeAngle(angle("", ["sha256:a"]))[0]).toMatch(/named no method/);
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

describe("describeUnderserved", () => {
  const row = (over: Partial<Underserved>): Underserved => ({
    goal: "certicomecc2k130",
    goal_name: "ECC2K-130",
    angle: "rho/fpga",
    handle: "GOAL-certicomecc2k130/rho/fpga",
    open_objectives: 2,
    open_reward: 300000,
    live_workers: 0,
    reward_per_worker: 300000,
    objectives: ["sha256:b", "sha256:c"],
    ...over,
  });
  it("says what is open and that nobody is on it", () => {
    expect(describeUnderserved(row({}))).toBe("300,000 units across 2 open objectives, nobody on it");
  });
  it("counts the workers, in the singular when there is one", () => {
    expect(describeUnderserved(row({ open_objectives: 1, live_workers: 1 }))).toBe(
      "300,000 units across 1 open objective, 1 live worker on it",
    );
  });
});
