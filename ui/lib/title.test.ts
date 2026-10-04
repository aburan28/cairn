import { describe, expect, it } from "vitest";
import { goalSlug, headline, objectiveTitle } from "./title";

describe("goalSlug", () => {
  it("drops the GOAL- prefix and nothing else", () => {
    expect(goalSlug("GOAL-ecc2k-130")).toBe("ecc2k-130");
    expect(goalSlug("goal_collatz")).toBe("collatz");
    expect(goalSlug("ecc2k-130")).toBe("ecc2k-130");
    expect(goalSlug(undefined)).toBe("");
  });
});

describe("headline", () => {
  it("takes the first sentence, not the first full stop", () => {
    expect(
      headline(
        "Exhibit an integer n in [1, 10^7) whose Collatz trajectory reaches 1 in at least 500 steps.",
      ),
    ).toBe(
      "Exhibit an integer n in [1, 10^7) whose Collatz trajectory reaches 1 in at least 500 steps",
    );
    expect(headline("Grow a cap set in F_3^4 as large as possible. Score is the set size.")).toBe(
      "Grow a cap set in F_3^4 as large as possible",
    );
    expect(
      headline(
        "Grow a cap set in F_3^4 as large as possible (no three distinct points collinear). Score.",
      ),
    ).toBe("Grow a cap set in F_3^4 as large as possible");
  });

  it("cuts a long sentence at its first aside", () => {
    expect(
      headline(
        "Find the private key for the ECC2K-130 challenge curve (a random binary Koblitz curve of the form y^2 + xy = x^3 + a over GF(2^130), with the curve defined elsewhere). More.",
      ),
    ).toBe("Find the private key for the ECC2K-130 challenge curve");
  });

  it("cuts at a word with an ellipsis when there is no aside", () => {
    const long = `Find ${"a very long phrase ".repeat(10)}here`;
    const out = headline(long);
    expect(out.endsWith("…")).toBe(true);
    expect(out.length).toBeLessThanOrEqual(97);
    expect(out).not.toMatch(/\s…$/);
  });

  it("is empty for an empty statement", () => {
    expect(headline("   ")).toBe("");
    expect(headline(null)).toBe("");
  });
});

describe("objectiveTitle", () => {
  it("prefers the statement, then the slug, then the id", () => {
    expect(objectiveTitle({ id: "sha256:x", goal: "GOAL-a-b", statement: "Do it. Now." })).toBe(
      "Do it",
    );
    expect(objectiveTitle({ id: "sha256:x", goal: "GOAL-golomb-ruler-11", statement: "" })).toBe(
      "golomb ruler 11",
    );
    expect(objectiveTitle({ id: "sha256:0123456789abcdef0123", goal: "", statement: "" })).toBe(
      "01234567…0123",
    );
  });
});
