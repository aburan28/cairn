import { describe, expect, it } from "vitest";
import { type LogRecord, buildMoves, kindCounts, parseLog } from "./log";

const OBJECTIVE = "sha256:objective";

/** A record with the fields every entry carries; `payload` is the test's. */
function record(seq: number, kind: string, payload: unknown): LogRecord {
  return {
    seq,
    kind,
    hash: `sha256:entry-${seq}`,
    prev: seq === 0 ? null : `sha256:entry-${seq - 1}`,
    ts: `2026-01-01T00:00:${String(seq).padStart(2, "0")}+00:00`,
    payload,
  };
}

function frontier(seq: number, claim: string, score: number, paid: number): LogRecord {
  return record(seq, "frontier", {
    objective_id: OBJECTIVE,
    claim_id: claim,
    holder: `holder-of-${claim}`,
    score,
    paid_cumulative: paid,
    pool_remaining: 1_000 - paid,
  });
}

function settlement(seq: number, claim: string, reward: number): LogRecord {
  return record(seq, "settlement", {
    objective_id: OBJECTIVE,
    claim_id: claim,
    submitter: `holder-of-${claim}`,
    reward,
  });
}

describe("parseLog", () => {
  it("parses one record per line and skips blank ones", () => {
    const text = [JSON.stringify(record(0, "objective", {})), "", JSON.stringify(record(1, "claim", {})), ""].join(
      "\n",
    );
    const parsed = parseLog(text);
    expect(parsed.records.map((r) => r.seq)).toEqual([0, 1]);
    expect(parsed.problems).toEqual([]);
  });

  it("reports a malformed line by number and keeps every other line", () => {
    // One bad line used to throw out of the loop, and the page rendered an
    // error where the log should have been -- hiding every good line and,
    // with them, the fact that one line was bad.
    const text = [
      JSON.stringify(record(0, "objective", {})),
      '{"seq": 1, "kind": "claim", "hash": "sha256:entry-1", "prev": "sha256:entry-0", "ts": "t", "payload": {',
      JSON.stringify(record(2, "verdict", {})),
    ].join("\n");
    const parsed = parseLog(text);
    expect(parsed.records.map((r) => r.seq)).toEqual([0, 2]);
    expect(parsed.problems).toHaveLength(1);
    expect(parsed.problems[0]).toMatch(/^line 2: /);
  });

  it("reports a line that parses but is not a record", () => {
    const text = [JSON.stringify(record(0, "objective", {})), '{"not": "a record"}', "[1, 2, 3]"].join("\n");
    const parsed = parseLog(text);
    expect(parsed.records).toHaveLength(1);
    expect(parsed.problems).toHaveLength(2);
    expect(parsed.problems[0]).toMatch(/^line 2: .*`seq`/);
    expect(parsed.problems[1]).toMatch(/^line 3: .*an array/);
  });

  it("accepts the genesis record, whose prev is null", () => {
    // `prev` is `null` at genesis and `expectFields` checks for `undefined`,
    // which is why `prev` is not on the required list -- pinned here so it
    // is not added back by someone tidying.
    const parsed = parseLog(JSON.stringify(record(0, "objective", {})));
    expect(parsed.records[0].prev).toBeNull();
    expect(parsed.problems).toEqual([]);
  });
});

describe("kindCounts", () => {
  it("counts in order of first appearance, not alphabetically", () => {
    const records = [
      record(0, "objective", {}),
      record(1, "commitment", {}),
      record(2, "claim", {}),
      record(3, "commitment", {}),
    ];
    expect(kindCounts(records)).toEqual([
      ["objective", 1],
      ["commitment", 2],
      ["claim", 1],
    ]);
  });
});

describe("buildMoves", () => {
  it("lays out the frontier's successive states, oldest first, with each move's own payout", () => {
    const records = [
      frontier(5, "sha256:a", 12, 300),
      settlement(6, "sha256:a", 300),
      frontier(9, "sha256:b", 17, 800),
      settlement(10, "sha256:b", 500),
    ];
    const moves = buildMoves(records, OBJECTIVE);
    expect(moves.map((m) => m.claimId)).toEqual(["sha256:a", "sha256:b"]);
    expect(moves.map((m) => m.paidThisMove)).toEqual([300, 500]);
    expect(moves.map((m) => m.paidCumulative)).toEqual([300, 800]);
    expect(moves.map((m) => m.settlementReward)).toEqual([300, 500]);
    expect(moves.every((m) => m.consistent)).toBe(true);
  });

  it("orders by seq even when the records arrive out of order", () => {
    const records = [frontier(9, "sha256:b", 17, 800), frontier(5, "sha256:a", 12, 300)];
    expect(buildMoves(records, OBJECTIVE).map((m) => m.seq)).toEqual([5, 9]);
  });

  it("ignores other objectives' frontier and settlement records", () => {
    const other = { ...frontier(3, "sha256:x", 99, 999), payload: { ...frontier(3, "sha256:x", 99, 999).payload, objective_id: "sha256:other" } };
    const records = [other, frontier(5, "sha256:a", 12, 300)];
    expect(buildMoves(records, OBJECTIVE).map((m) => m.claimId)).toEqual(["sha256:a"]);
  });

  it("is consistent with no settlement yet, because the log may not have reached it", () => {
    const moves = buildMoves([frontier(5, "sha256:a", 12, 300)], OBJECTIVE);
    expect(moves[0].settlementReward).toBeNull();
    expect(moves[0].consistent).toBe(true);
  });

  it("flags a move whose payout disagrees with the settlement for the same claim", () => {
    // Two records the same node wrote, disagreeing about one payment. The
    // page renders this red rather than picking one -- the same instinct as
    // `overspent`: the reader's only job is to notice, not to adjudicate.
    const records = [
      frontier(5, "sha256:a", 12, 300),
      settlement(6, "sha256:a", 300),
      frontier(9, "sha256:b", 17, 800),
      settlement(10, "sha256:b", 450),
    ];
    const moves = buildMoves(records, OBJECTIVE);
    expect(moves[0].consistent).toBe(true);
    expect(moves[1].paidThisMove).toBe(500);
    expect(moves[1].settlementReward).toBe(450);
    expect(moves[1].consistent).toBe(false);
  });
});
