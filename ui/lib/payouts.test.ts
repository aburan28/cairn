import { describe, expect, it } from "vitest";
import { draftReceipt, fetchPayoutPreview, quotePayouts, type PayoutPreview } from "./payouts";

const preview: PayoutPreview = {
  objective_id: "sha256:example",
  ledger: { height: 12, head: "sha256:head" },
  reward_units: "100",
  settled_units: "75",
  payees: [
    { identity: "alice", units: "50" },
    { identity: "bob", units: "25" },
  ],
  attribution: { delta_num: 1, delta_den: 4, max_depth: 6, reserved_num: 0, reserved_den: 1 },
  note: "",
};

describe("external bounty preview", () => {
  it("uses integer arithmetic and leaves unearned and rounded funds unallocated", () => {
    const result = quotePayouts(preview, "101");
    expect(result.rows.map((row) => row.amount)).toEqual([50n, 25n]);
    expect(result.unallocated).toBe(26n);
  });

  it("keeps amounts above JavaScript's safe integer exact", () => {
    const result = quotePayouts(preview, "900719925474099300");
    expect(result.rows[0].amount).toBe(450359962737049650n);
  });

  it("refuses incomplete or inconsistent node attribution", () => {
    expect(() => quotePayouts({ ...preview, settled_units: "76" }, "100"))
      .toThrow("Attributed units do not equal settled units");
    expect(() => quotePayouts(preview, "1.5")).toThrow("integer amount");
  });

  it("exports a draft tied to the observed log head without invented addresses", () => {
    const receipt = JSON.parse(draftReceipt(preview, "bitcoin:mainnet", "101"));
    expect(receipt.ledger.head).toBe("sha256:head");
    expect(receipt.payees[0]).toMatchObject({ identity: "alice", amount_base_units: "50", address: null });
    expect(receipt.status).toBe("draft-unverified");
  });

  it("rejects malformed node amounts before the page renders them", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => new Response(JSON.stringify({ ...preview, reward_units: "bad" }));
    try {
      await expect(fetchPayoutPreview("http://127.0.0.1:52977", preview.objective_id))
        .rejects.toThrow("non-integer unit count");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
