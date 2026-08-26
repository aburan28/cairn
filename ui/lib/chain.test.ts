import { describe, expect, it } from "vitest";
import { type EpochLink, epochScales, firstBrokenLink, totalClaims } from "./chain";

/** A chain whose links name each other, from any list of epochs. The hashes
 *  are not real digests: `firstBrokenLink` compares `prev` to the previous
 *  `link` by value and never recomputes anything, which is the property under
 *  test — a reader that re-derived the hash would be the third implementation
 *  `chain.ts` refuses to be. */
function linked(epochs: number[]): EpochLink[] {
  let prev = "";
  return epochs.map((epoch) => {
    const link = `sha256:link-${epoch}`;
    const out = { epoch, claims: [`sha256:claim-${epoch}`], prev, link };
    prev = link;
    return out;
  });
}

describe("firstBrokenLink", () => {
  it("accepts an empty chain", () => {
    expect(firstBrokenLink([])).toBeNull();
  });

  it("accepts a chain whose every link names the one before it", () => {
    expect(firstBrokenLink(linked([1, 2, 5]))).toBeNull();
  });

  it("requires the first link to name genesis, the empty string", () => {
    const chain = linked([1, 2]);
    chain[0].prev = "sha256:something";
    expect(firstBrokenLink(chain)).toBe(1);
  });

  it("returns the epoch of the first link that does not follow its parent", () => {
    const chain = linked([1, 2, 3, 4]);
    chain[2].prev = "sha256:not-link-2";
    expect(firstBrokenLink(chain)).toBe(3);
  });

  it("reports the first break, not the last", () => {
    const chain = linked([1, 2, 3, 4]);
    chain[1].prev = "sha256:wrong";
    chain[3].prev = "sha256:also-wrong";
    expect(firstBrokenLink(chain)).toBe(2);
  });
});

describe("epochScales", () => {
  it("is one scale for a chain settled under one epoch length", () => {
    // 600-second epochs in 2026 sit around 2.9 million.
    expect(epochScales(linked([2_980_001, 2_980_002, 2_980_007]))).toEqual([6]);
  });

  it("is two scales when the epoch length changed by orders of magnitude", () => {
    // Demo scripts set CAIRN_EPOCH_SECONDS=1, so epochs are unix seconds
    // (~1.7 billion); the default of 600 puts them around 2.9 million.
    expect(epochScales(linked([2_980_001, 1_788_000_000]))).toEqual([9, 6]);
  });

  it("ignores epoch zero, whose log10 is not a number", () => {
    expect(epochScales(linked([0, 5]))).toEqual([0]);
  });

  it("is a heuristic: a chain that legitimately crosses a power of ten is a false positive", () => {
    // Known and accepted. Epochs 999 and 1000 are consecutive under one
    // divisor, and this reports two scales anyway, because the divisor is
    // never stored and there is nothing better to group by. The page labels
    // the panel a heuristic for exactly this reason; this test pins the
    // behaviour so a change to it is a decision rather than an accident.
    expect(epochScales(linked([999, 1000]))).toEqual([3, 2]);
  });
});

describe("totalClaims", () => {
  it("sums claims across every link", () => {
    const chain = linked([1, 2]);
    chain[1].claims.push("sha256:another");
    expect(totalClaims(chain)).toBe(3);
  });
});
