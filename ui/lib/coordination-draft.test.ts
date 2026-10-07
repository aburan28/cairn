import { describe, expect, it } from "vitest";
import { draftCoordinatedTask, pieceworkJson, scaffoldCommand } from "./coordination-draft";

describe("draftCoordinatedTask", () => {
  it("keeps an explicit GOAL- handle with its angle", () => {
    const draft = draftCoordinatedTask("Divide GOAL-ecc2k130/rho into 2M orbits at 10 per unit");
    expect(draft.goalHandle).toBe("GOAL-ecc2k130/rho");
    expect(draft.goalFrom).toBe("explicit");
    expect(draft.units).toBe(2_000_000);
    expect(draft.unitPrice).toBe(10);
    expect(draft.pool).toBe(20_000_000);
  });

  it("builds a handle from the first content words when none is given", () => {
    const draft = draftCoordinatedTask("We need to search elliptic curve discrete logs broadly");
    expect(draft.goalHandle).toBe("GOAL-elliptic-curve-discrete-logs");
    expect(draft.goalFrom).toBe("words");
    expect(draft.units).toBeNull();
    expect(draft.pool).toBeNull();
  });

  it("reads counts with k/m suffixes and comma separators beside unit nouns", () => {
    expect(draftCoordinatedTask("check 500k seeds").units).toBe(500_000);
    expect(draftCoordinatedTask("check 1,000,000 keys").units).toBe(1_000_000);
    expect(draftCoordinatedTask("check many seeds").units).toBeNull();
  });

  it("reads the price beside price nouns, and guesses the verifier from vocabulary", () => {
    expect(draftCoordinatedTask("prove the bound over 1000 units paying 5 each").unitPrice).toBe(5);
    expect(draftCoordinatedTask("prove the bound over 1000 units").verifierKind).toBe("lean");
    expect(draftCoordinatedTask("witness search over 1000 units").verifierKind).toBe("certificate");
    expect(draftCoordinatedTask("score candidates over 1000 units").verifierKind).toBe("evaluator");
  });

  it("keeps placeholders loud in the JSON and scaffolds the verifier kind", () => {
    const draft = draftCoordinatedTask("search broadly");
    expect(pieceworkJson(draft)).toContain("<units>");
    expect(pieceworkJson(draft)).toContain("<unit-price>");
    expect(scaffoldCommand(draft)).toContain("--kind evaluator");
    const full = draftCoordinatedTask("Divide GOAL-x into 100 units at 3 per unit with a witness");
    expect(pieceworkJson(full)).toContain('"units": 100');
    expect(scaffoldCommand(full)).toContain("--kind certificate");
  });
});
