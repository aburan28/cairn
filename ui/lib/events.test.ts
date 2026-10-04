import { describe, expect, it } from "vitest";
import type { LogRecord } from "./log";
import { ago, eventsFor, indexObjectives, participants, toEvent } from "./events";

const OBJ = "sha256:obj";
const OTHER = "sha256:other";

function rec(seq: number, kind: string, payload: unknown, ts = `2026-10-0${1 + (seq % 8)}T00:00:00+00:00`): LogRecord {
  return { seq, kind, hash: `sha256:h${seq}`, prev: null, ts, payload };
}

const objectivePayload = { goal: "GOAL-x", funder: "treasury", statement: "Do x.", reward: 1000 };

const log: LogRecord[] = [
  rec(0, "objective", objectivePayload),
  rec(1, "commitment", { objective_id: OBJ, submitter: "alice" }),
  rec(2, "commitment", { objective_id: OBJ, submitter: "bob" }),
  rec(3, "claim", { objective_id: OBJ, submitter: "bob", cites: [] }),
  rec(4, "verdict", { objective_id: OBJ, claim_id: "c-bob", verdict: { status: "reject", detail: "no" } }),
  rec(5, "claim", { objective_id: OBJ, submitter: "alice", cites: ["c0"] }),
  rec(6, "verdict", { objective_id: OBJ, claim_id: "c-alice", verdict: { status: "accept" } }),
  rec(7, "settlement", { objective_id: OBJ, claim_id: "c-alice", submitter: "alice", reward: 1000 }),
  rec(8, "attestation", { claim_id: "c-alice", attestor: "val", status: "accept" }),
  rec(9, "commitment", { objective_id: OTHER, submitter: "carol" }),
  rec(10, "batch", { epoch: 7, claims: ["c-alice"], anchor: "" }),
];

const index = indexObjectives([{ id: OBJ, ...objectivePayload }]);

describe("toEvent", () => {
  it("reads core records as sentences", () => {
    expect(toEvent(log[0], index)).toMatchObject({
      actor: "treasury",
      action: "posted a challenge",
      amount: 1000,
      amountLabel: "bounty",
      objectiveId: OBJ,
    });
    expect(toEvent(log[4])).toMatchObject({ actor: "checker", action: "rejected an answer", tone: "bad", detail: "no" });
    expect(toEvent(log[5]).detail).toBe("cites 1 earlier claim");
    expect(toEvent(log[7])).toMatchObject({ actor: "alice", action: "was paid", amount: 1000, tone: "good" });
    expect(toEvent(log[10])).toMatchObject({ actor: null, action: "Epoch 7 closed" });
  });

  it("treats unavailable as neither accept nor reject", () => {
    const e = toEvent(rec(1, "verdict", { verdict: { status: "unavailable" } }));
    expect(e.tone).toBe("warn");
    expect(e.action).toBe("could not check an answer");
  });

  it("still renders a kind it has never seen", () => {
    const e = toEvent(rec(1, "brand_new", { holder: "zed", amount: 5, note: "hi" }));
    expect(e).toMatchObject({ actor: "zed", action: "brand new", amount: 5 });
    expect(e.fields).toContainEqual(["note", "hi"]);
  });

  it("leaves an objective it cannot match unlinked rather than guessing", () => {
    expect(toEvent(rec(0, "objective", { ...objectivePayload, statement: "else" }), index).objectiveId).toBeNull();
  });
});

describe("eventsFor", () => {
  it("collects an objective's records, including ones that name only its claim", () => {
    const seqs = eventsFor(log, OBJ, index).map((e) => e.seq);
    expect(seqs).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8]);
  });
});

describe("participants", () => {
  it("credits verdicts to the claim just before them, and ranks by recency", () => {
    const people = participants(eventsFor(log, OBJ, index));
    const alice = people.find((p) => p.name === "alice");
    const bob = people.find((p) => p.name === "bob");
    expect(alice).toMatchObject({ committed: 1, revealed: 1, accepted: 1, rejected: 0, paid: 1000 });
    expect(bob).toMatchObject({ committed: 1, revealed: 1, accepted: 0, rejected: 1, paid: 0 });
    expect(people.map((p) => p.name)).not.toContain("carol");
    expect(people.map((p) => p.name)).not.toContain("checker");
  });
});

describe("ago", () => {
  it("says how long ago, coarsely", () => {
    const now = Date.parse("2026-10-04T12:00:00Z");
    expect(ago("2026-10-04T11:59:30Z", now)).toBe("just now");
    expect(ago("2026-10-04T11:30:00Z", now)).toBe("30 min ago");
    expect(ago("2026-10-02T12:00:00Z", now)).toBe("2 d ago");
    expect(ago("nonsense", now)).toBe("nonsense");
  });
});
