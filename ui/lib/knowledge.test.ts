import { describe, expect, it } from "vitest";
import { type KnowledgeRow, caveats, verification } from "./knowledge";

const row = (over: Partial<KnowledgeRow> = {}): KnowledgeRow => ({
  claim_id: "sha256:c",
  objective_id: "sha256:o",
  submitter: "alice",
  created_at: "2026-10-07T10:00:00+00:00",
  standing: "accepted",
  verdict: "accept",
  reproducible: "yes",
  corroborations: 0,
  refutations: 0,
  disputes: 0,
  superseded_by: [],
  retracted_by: null,
  confidence_per_mille: 600,
  attestations: { accept: 0, reject: 0, slashed: 0 },
  ...over,
});

describe("verification", () => {
  it("climbs one rung per kind of evidence", () => {
    expect(verification(row()).level).toBe(2);
    expect(verification(row({ attestations: { accept: 1, reject: 0, slashed: 0 } })).level).toBe(3);
    const full = verification(
      row({ standing: "corroborated", corroborations: 2, attestations: { accept: 1, reject: 0, slashed: 0 } }),
    );
    expect(full.level).toBe(4);
    expect(full.label).toBe("Replicated");
    expect(full.checks.find((c) => c.key === "replicated")?.why).toBe("2 independent parties reproduced it.");
  });

  it("counts nothing above a verdict that did not accept", () => {
    const refuted = verification(row({ standing: "refuted", verdict: "reject", corroborations: 3 }));
    expect(refuted.level).toBe(0);
    expect(refuted.tone).toBe("bad");
    expect(refuted.checks.every((c) => !c.done)).toBe(true);
    const pending = verification(row({ standing: "unverified", verdict: "unavailable" }));
    expect(pending.level).toBe(0);
    expect(pending.checks[0].why).toMatch(/says nothing about the result/);
  });

  it("does not count a bond that was slashed, and says so", () => {
    const v = verification(row({ attestations: { accept: 1, reject: 0, slashed: 1 } }));
    expect(v.checks.find((c) => c.key === "bonded")?.done).toBe(false);
    expect(v.checks.find((c) => c.key === "bonded")?.why).toMatch(/slashed/);
  });

  it("shows the node's confidence, floored, and survives a node without bond counts", () => {
    expect(verification(row({ confidence_per_mille: 729 })).percent).toBe(72);
    expect(verification(row({ attestations: undefined })).level).toBe(2);
  });

  it("lists what weighs against a result", () => {
    expect(caveats(row({ refutations: 1, disputes: 2, superseded_by: ["x"], retracted_by: "y" }))).toEqual([
      "1 verified claim says it is wrong",
      "2 could not reproduce it",
      "superseded by 1 later result",
      "its author retracted it",
    ]);
    expect(caveats(row())).toEqual([]);
  });
});
