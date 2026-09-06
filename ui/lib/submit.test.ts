import { describe, expect, it } from "vitest";
import { EMPTY_DRAFT, type Draft, problems, reachableForWrites, toRecord } from "./submit";

const CREATED = "2026-01-01T00:00:00+00:00";

function draft(overrides: Partial<Draft> = {}): Draft {
  return {
    ...EMPTY_DRAFT,
    goal: "GOAL-collatz",
    statement: "Find an integer with a long trajectory.",
    funder: "alice",
    reward: "1000",
    checker: "examples/collatz/checkers/long_trajectory.py",
    checkerSha256: "df".repeat(32),
    ...overrides,
  };
}

describe("toRecord", () => {
  /**
   * The rule this pins is the one that would be most expensive to break.
   *
   * An objective's id covers its content, and the canonical form *omits* an
   * optional field that is unset rather than nulling it. A record carrying
   * `"deadline": null` is a different record with a different id from one
   * carrying no `deadline` at all — so a form that helpfully filled in nulls
   * for its empty inputs would produce objectives whose ids no other
   * implementation agrees with. See the module docs in `src/records.rs`.
   */
  it("omits unset optional fields rather than nulling them", () => {
    const record = toRecord(draft(), CREATED);
    expect(Object.keys(record).sort()).toEqual([
      "created_at",
      "funder",
      "goal",
      "reward",
      "statement",
      "verifier",
    ]);
    expect("deadline" in record).toBe(false);
    expect("ratchet" in record).toBe(false);
    expect("require_signed_submitter" in record).toBe(false);
  });

  it("includes optional fields once they are set", () => {
    const record = toRecord(
      draft({ deadline: "2026-06-01T00:00:00+00:00", requireSignedSubmitter: true }),
      CREATED,
    );
    expect(record.deadline).toBe("2026-06-01T00:00:00+00:00");
    expect(record.require_signed_submitter).toBe(true);
  });

  it("sends the reward as a number, because money here is an integer", () => {
    // A string reward decodes as a malformed record: `as_i128` refuses it, and
    // the message a funder gets is about types rather than about their form.
    const record = toRecord(draft({ reward: "1000" }), CREATED);
    expect(record.reward).toBe(1000);
    expect(typeof record.reward).toBe("number");
  });

  /**
   * `post_objective` refuses a ratchet whose `reward` disagrees with the
   * objective's. Deriving it from the one field the form collects is what
   * makes that unrepresentable rather than merely validated.
   */
  it("gives the ratchet the objective's own reward", () => {
    const record = toRecord(
      draft({
        verifierKind: "evaluator",
        useRatchet: true,
        baseline: "9",
        target: "20",
        minImprovement: "3",
        reward: "1100000",
      }),
      CREATED,
    );
    expect(record.ratchet).toEqual({
      baseline: 9,
      target: 20,
      direction: "maximize",
      min_improvement: 3,
      reward: 1100000,
    });
    expect(record.reward).toBe(1100000);
  });

  it("trims, so a stray space does not change the id", () => {
    const record = toRecord(draft({ goal: "  GOAL-x  ", funder: " alice " }), CREATED);
    expect(record.goal).toBe("GOAL-x");
    expect(record.funder).toBe("alice");
  });
});

describe("problems", () => {
  it("passes a complete draft", () => {
    expect(problems(draft())).toEqual({});
  });

  it("insists on a whole positive reward", () => {
    expect(problems(draft({ reward: "0" })).reward).toBeDefined();
    expect(problems(draft({ reward: "-5" })).reward).toBeDefined();
    expect(problems(draft({ reward: "1.5" })).reward).toBeDefined();
    expect(problems(draft({ reward: "" })).reward).toBeDefined();
  });

  /**
   * The checker hash is what *pins* the verifier: without it an objective says
   * "run this path", which is a promise about a file that can be edited after
   * anyone starts work. A blank or short value must not reach the node as a
   * plausible-looking field.
   */
  it("requires a full 64-character lowercase checker hash", () => {
    expect(problems(draft({ checkerSha256: "" })).checkerSha256).toBeDefined();
    expect(problems(draft({ checkerSha256: "abc" })).checkerSha256).toBeDefined();
    expect(problems(draft({ checkerSha256: "DF".repeat(32) })).checkerSha256).toBeDefined();
    expect(problems(draft({ checkerSha256: "df".repeat(32) })).checkerSha256).toBeUndefined();
  });

  it("refuses a ratchet on a certificate, which has nothing to score", () => {
    const found = problems(
      draft({ verifierKind: "certificate", useRatchet: true, baseline: "0", target: "1" }),
    );
    expect(found.useRatchet).toBeDefined();
  });

  it("refuses a min_improvement of zero", () => {
    const found = problems(
      draft({
        verifierKind: "evaluator",
        useRatchet: true,
        baseline: "0",
        target: "10",
        minImprovement: "0",
      }),
    );
    expect(found.minImprovement).toBeDefined();
  });

  it("refuses a span of zero", () => {
    const found = problems(
      draft({
        verifierKind: "evaluator",
        useRatchet: true,
        baseline: "5",
        target: "5",
        minImprovement: "1",
      }),
    );
    expect(found.target).toBeDefined();
  });
});

describe("reachableForWrites", () => {
  /**
   * The whole point of this function is to turn an opaque preflight failure
   * into a sentence. An empty base means same-origin, which is the embedded
   * `/ui/` case and the one that works.
   */
  it("treats an empty base as same-origin", () => {
    expect(reachableForWrites("")).toBe(true);
  });

  it("refuses a cross-origin node", () => {
    // jsdom is not configured here, so `window` is undefined and any
    // configured absolute URL is correctly reported as unwritable.
    expect(reachableForWrites("http://127.0.0.1:8080")).toBe(false);
  });
});
