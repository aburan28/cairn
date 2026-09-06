import { describe, expect, it } from "vitest";
import {
  EMPTY_DRAFT,
  type Draft,
  fromRecord,
  problems,
  reachableForWrites,
  toRecord,
} from "./submit";

const CREATED = "2026-01-01T00:00:00+00:00";

function draft(overrides: Partial<Draft> = {}): Draft {
  return {
    ...EMPTY_DRAFT,
    goal: "GOAL-collatz",
    statement: "Find an integer with a long trajectory.",
    funder: "alice",
    reward: "1000",
    program: "examples/collatz/checkers/long_trajectory.py",
    programSha256: "df".repeat(32),
    ...overrides,
  };
}

/** The shipped examples, verbatim in the fields that matter. */
const CAPSET = {
  goal: "GOAL-capset-lower-bounds",
  statement: "Exhibit a cap set in F_3^4 of size at least 20.",
  verifier: {
    kind: "evaluator",
    evaluator: "examples/capset/evaluators/cap_set.py",
    evaluator_sha256: "05".repeat(32),
    entrypoint: "score",
    threshold: 20,
    direction: "maximize",
  },
  reward: 250000,
  funder: "treasury",
  created_at: "2026-07-28T00:00:00+00:00",
};

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
    expect("artifact_schema" in record).toBe(false);
  });

  it("includes optional fields once they are set", () => {
    const record = toRecord(
      draft({
        deadline: "2026-06-01T00:00:00+00:00",
        requireSignedSubmitter: true,
        artifactSchema: '{"type":"object","required":["n"]}',
      }),
      CREATED,
    );
    expect(record.deadline).toBe("2026-06-01T00:00:00+00:00");
    expect(record.require_signed_submitter).toBe(true);
    expect(record.artifact_schema).toEqual({ type: "object", required: ["n"] });
  });

  it("sends the reward as a number, because money here is an integer", () => {
    const record = toRecord(draft({ reward: "1000" }), CREATED);
    expect(record.reward).toBe(1000);
    expect(typeof record.reward).toBe("number");
  });

  /**
   * The per-kind shape. The published schema requires only `kind`, and the
   * verifier reports a malformed spec only when a verdict is first needed —
   * after the objective is funded and in the log. So this is the one place
   * the shape is decided before money moves, and each kind is pinned against
   * the field names `src/verifiers/mod.rs` reads.
   */
  it("spells a certificate's verifier with checker fields", () => {
    expect(toRecord(draft(), CREATED).verifier).toEqual({
      kind: "certificate",
      checker: "examples/collatz/checkers/long_trajectory.py",
      checker_sha256: "df".repeat(32),
      entrypoint: "check",
    });
  });

  it("spells an evaluator's verifier with evaluator fields, a threshold and a direction", () => {
    const record = toRecord(
      draft({
        verifierKind: "evaluator",
        program: "examples/capset/evaluators/cap_set.py",
        programSha256: "05".repeat(32),
        entrypoint: "score",
        threshold: "20",
        direction: "maximize",
      }),
      CREATED,
    );
    expect(record.verifier).toEqual(CAPSET.verifier);
  });

  it("nests a statistical verifier's program under `statistic`", () => {
    const record = toRecord(
      draft({
        verifierKind: "statistical",
        program: "examples/permutation/stat.py",
        programSha256: "ab".repeat(32),
        entrypoint: "statistic",
        threshold: "0.05",
        direction: "minimize",
      }),
      CREATED,
    );
    expect(record.verifier).toEqual({
      kind: "statistical",
      statistic: { path: "examples/permutation/stat.py", sha256: "ab".repeat(32) },
      entrypoint: "statistic",
      threshold: 0.05,
      direction: "minimize",
    });
  });

  it("gives a lean verifier its statement and no pinned program", () => {
    const record = toRecord(
      draft({
        verifierKind: "lean",
        program: "",
        programSha256: "",
        leanStatement: "theorem t : 1 + 1 = 2",
        leanPreamble: "import Mathlib",
        timeoutSeconds: "30",
      }),
      CREATED,
    );
    expect(record.verifier).toEqual({
      kind: "lean",
      statement: "theorem t : 1 + 1 = 2",
      preamble: "import Mathlib",
      timeout_seconds: 30,
    });
  });

  it("gives a replay verifier an argv, its reproducible fields and no pinned program", () => {
    const record = toRecord(
      draft({
        verifierKind: "replay",
        program: "",
        programSha256: "",
        replayCommand: "python3\nrun.py\n--seed 1\n",
        replayFields: "relations_found, degree",
        replayCwd: "examples/replay",
      }),
      CREATED,
    );
    expect(record.verifier).toEqual({
      kind: "replay",
      command: ["python3", "run.py", "--seed 1"],
      reproducible_fields: ["relations_found", "degree"],
      cwd: "examples/replay",
    });
    const { draft: back } = fromRecord(record);
    expect(back.replayCommand).toBe("python3\nrun.py\n--seed 1");
    expect(back.replayFields).toBe("relations_found, degree");
    expect(problems(draft({ verifierKind: "replay", program: "", programSha256: "" })).replayCommand).toBeDefined();
  });

  it("merges verifier extras but lets the form's own fields win", () => {
    const record = toRecord(
      draft({
        verifierExtras: '{"stepper":{"kind":"python"},"checker":"stale.py"}',
      }),
      CREATED,
    );
    const verifier = record.verifier as Record<string, unknown>;
    expect(verifier.stepper).toEqual({ kind: "python" });
    expect(verifier.checker).toBe("examples/collatz/checkers/long_trajectory.py");
  });

  /**
   * `post_objective` refuses a ratchet whose `reward` disagrees with the
   * objective's. Deriving it from the one field the form collects is what
   * makes that unrepresentable rather than merely validated.
   */
  it("gives the ratchet the objective's own reward and direction", () => {
    const record = toRecord(
      draft({
        verifierKind: "evaluator",
        threshold: "9",
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

describe("fromRecord", () => {
  /**
   * The whole reason the loader exists: a scaffolded `objective.json` should
   * post as the same record it would have posted from the terminal. A round
   * trip that changed a verifier field would change the id, and the funder
   * would learn that only when claims failed to resolve against it.
   */
  it("round-trips a shipped evaluator objective through the form", () => {
    const { draft: loaded, dropped } = fromRecord(CAPSET);
    expect(dropped).toEqual([]);
    expect(loaded.verifierKind).toBe("evaluator");
    expect(loaded.program).toBe(CAPSET.verifier.evaluator);
    expect(loaded.programSha256).toBe(CAPSET.verifier.evaluator_sha256);
    expect(loaded.threshold).toBe("20");
    const posted = toRecord(loaded, CAPSET.created_at);
    expect(posted).toEqual(CAPSET);
  });

  it("keeps verifier fields it has no control for", () => {
    const { draft: loaded } = fromRecord({
      ...CAPSET,
      verifier: { kind: "certificate", checker: "c.py", checker_sha256: "00".repeat(32), entrypoint: "check", stepper: { kind: "python" }, timeout_seconds: 5 },
    });
    expect(JSON.parse(loaded.verifierExtras)).toEqual({
      stepper: { kind: "python" },
      timeout_seconds: 5,
    });
    const posted = toRecord(loaded, CREATED).verifier as Record<string, unknown>;
    expect(posted.stepper).toEqual({ kind: "python" });
    expect(posted.timeout_seconds).toBe(5);
  });

  it("lifts a ratchet and its direction", () => {
    const { draft: loaded } = fromRecord({
      ...CAPSET,
      ratchet: { baseline: 9, target: 20, direction: "minimize", min_improvement: 3, reward: 250000 },
    });
    expect(loaded.useRatchet).toBe(true);
    expect(loaded.baseline).toBe("9");
    expect(loaded.target).toBe("20");
    expect(loaded.minImprovement).toBe("3");
    expect(loaded.direction).toBe("minimize");
  });

  it("names the top-level fields it cannot carry", () => {
    const { dropped } = fromRecord({
      ...CAPSET,
      funding_signature: "ab".repeat(64),
      confidentiality: "embargoed",
    });
    expect(dropped).toEqual(["confidentiality", "funding_signature"]);
  });

  it("refuses anything that is not an object", () => {
    expect(() => fromRecord([])).toThrow();
    expect(() => fromRecord("{}")).toThrow();
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
  it("requires a full 64-character lowercase program hash", () => {
    expect(problems(draft({ programSha256: "" })).programSha256).toBeDefined();
    expect(problems(draft({ programSha256: "abc" })).programSha256).toBeDefined();
    expect(problems(draft({ programSha256: "DF".repeat(32) })).programSha256).toBeDefined();
    expect(problems(draft({ programSha256: "df".repeat(32) })).programSha256).toBeUndefined();
  });

  it("asks scored kinds for a threshold and lean for a statement, and nothing else of them", () => {
    expect(problems(draft({ verifierKind: "evaluator" })).threshold).toBeDefined();
    expect(problems(draft({ verifierKind: "evaluator", threshold: "1" })).threshold).toBeUndefined();
    const lean = problems(draft({ verifierKind: "lean", program: "", programSha256: "" }));
    expect(lean.leanStatement).toBeDefined();
    expect(lean.program).toBeUndefined();
    expect(lean.programSha256).toBeUndefined();
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
        threshold: "0",
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
        threshold: "5",
        useRatchet: true,
        baseline: "5",
        target: "5",
        minImprovement: "1",
      }),
    );
    expect(found.target).toBeDefined();
  });

  it("refuses malformed JSON in the free-text fields", () => {
    expect(problems(draft({ artifactSchema: "{nope" })).artifactSchema).toBeDefined();
    expect(problems(draft({ verifierExtras: "[1]" })).verifierExtras).toBeDefined();
    expect(problems(draft({ verifierExtras: '{"seed":1}' })).verifierExtras).toBeUndefined();
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
