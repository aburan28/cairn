import { describe, expect, it } from "vitest";
import type { Bridge } from "./draft";
import type { Objective } from "./site";
import {
  DECLARED_BY_ROLE,
  type OpenGoals,
  ROLES,
  afterRead,
  goalPay,
  openSheet,
  pickGoal,
  setRole,
} from "./contribute";

function recorder(reply: () => Promise<unknown> = async () => true) {
  const sent: unknown[] = [];
  const bridge: Bridge = {
    postMessage(message) {
      sent.push(message);
      return reply();
    },
  };
  return { bridge, sent };
}

describe("ROLES", () => {
  it("never says a role is paid that the rules do not pay", () => {
    // `gross_paid_within` credits settlements (solvers and workers), slashed
    // bonds (catchers) and availability settlements. Nothing pays a
    // correct attestation or a relay; if that changes, change this test
    // together with docs/design/roles-and-rewards.md.
    const pay = Object.fromEntries(ROLES.map((r) => [r.id, r.pay]));
    expect(pay).toEqual({
      experimenter: "paid",
      compute: "paid",
      validator: "bonded",
      relay: "unpaid",
      funder: "pays",
    });
  });

  it("declares only role names the node knows", () => {
    const known = new Set(["coordinator", "executor", "verifier", "relay", null]);
    for (const role of ROLES) expect(known.has(role.declares)).toBe(true);
  });

  it("has a button in the app for every role a terminal was the answer to", () => {
    // In Cairn.app no card may fall back to a shell line: each one either
    // flips a role, opens a sheet, or links to a page that does the job.
    for (const role of ROLES) {
      const { inApp, page } = role.start;
      expect(Boolean(inApp?.role || inApp?.open || page), role.id).toBe(true);
    }
  });

  it("reads 'on here' from the role the node declares for each app toggle", () => {
    for (const role of ROLES) {
      const app = role.start.inApp?.role;
      if (app) expect(DECLARED_BY_ROLE[app]).toBe(role.declares);
    }
  });
});

describe("the app bridge", () => {
  it("asks for a role in the shape PageRequest.swift parses", async () => {
    const { bridge, sent } = recorder();
    await setRole(bridge, "worker-host", true);
    await setRole(bridge, "validator", false);
    expect(sent).toEqual([
      { kind: "set-role", role: "worker-host", on: true },
      { kind: "set-role", role: "validator", on: false },
    ]);
  });

  it("opens a sheet, naming the objective only when there is one", async () => {
    const { bridge, sent } = recorder();
    await openSheet(bridge, "work", "sha256:ab");
    await openSheet(bridge, "agents");
    expect(sent).toEqual([
      { kind: "open", sheet: "work", objective: "sha256:ab" },
      { kind: "open", sheet: "agents" },
    ]);
  });

  it("surfaces the app's own refusal, including a declined confirmation", async () => {
    const { bridge } = recorder(async () => {
      throw new Error("Cancelled.");
    });
    await expect(setRole(bridge, "relay", true)).rejects.toThrow("Cancelled.");
    await expect(openSheet(bridge, "peers")).rejects.toThrow("Cancelled.");
  });
});

const goal = (id: string, extra: Partial<Objective> = {}): Objective =>
  ({ id, goal: "", statement: "", reward: 1000, funder: "treasury", verifier_kind: "certificate", settled: false, open: true, settlement: null, ...extra }) as Objective;

describe("pickGoal", () => {
  const open = [goal("a"), goal("b"), goal("c")];

  it("keeps the reader's choice while it is still open", () => {
    expect(pickGoal(open, "c", "a", ["b"])).toBe("c");
  });

  it("drops a choice that closed and picks again", () => {
    expect(pickGoal(open, "gone", null, [])).toBe("a");
  });

  it("prefers the goal a link asked for, then an underserved one, then the first", () => {
    expect(pickGoal(open, "", "b", ["c"])).toBe("b");
    expect(pickGoal(open, "", "not-open", ["closed", "c"])).toBe("c");
    expect(pickGoal(open, "", null, [])).toBe("a");
  });

  it("is empty when nothing is open", () => {
    expect(pickGoal([], "a", "a", ["a"])).toBe("");
  });
});

describe("goalPay", () => {
  it("is the bounty for a single-answer goal", () => {
    expect(goalPay(goal("a", { reward: 10_000 }))).toEqual({ kind: "bounty", reward: 10_000 });
  });

  it("counts units left on a divided search, never below zero", () => {
    const piece = { unit_price: 100, paid_units: 18, paid_total: 1800, pool_remaining: 0, units: 4096 };
    expect(goalPay(goal("a", { piecework: piece }))).toEqual({ kind: "piecework", unitPrice: 100, units: 4096, left: 4078 });
    expect(goalPay(goal("a", { piecework: { ...piece, paid_units: 5000 } }))).toMatchObject({ left: 0 });
  });

  it("leaves units unknown when the node does not publish a total", () => {
    const piece = { unit_price: 100, paid_units: 3, paid_total: 300, pool_remaining: 700 };
    expect(goalPay(goal("a", { piecework: piece }))).toEqual({ kind: "piecework", unitPrice: 100, units: null, left: null });
  });
});

describe("afterRead", () => {
  const start: OpenGoals = { objectives: [], live: null };

  it("keeps only open goals from a live read", () => {
    const next = afterRead(start, { live: true, objectives: [goal("a"), goal("b", { open: false, settled: true })] });
    expect(next).toEqual({ objectives: [goal("a")], live: true });
  });

  it("reports a first failed read as unreadable, not as an empty node", () => {
    expect(afterRead(start, { live: false, objectives: [goal("snapshot")] })).toEqual({ objectives: [], live: false });
  });

  it("keeps the last good answer through a missed poll", () => {
    const good = afterRead(start, { live: true, objectives: [goal("a")] });
    expect(afterRead(good, { live: false, objectives: [] })).toEqual(good);
  });

  it("recovers when the node answers after failing", () => {
    const failed = afterRead(start, { live: false, objectives: [] });
    expect(afterRead(failed, { live: true, objectives: [goal("a")] })).toEqual({ objectives: [goal("a")], live: true });
  });

  it("shows a node that closed its last goal as empty", () => {
    const good = afterRead(start, { live: true, objectives: [goal("a")] });
    expect(afterRead(good, { live: true, objectives: [] })).toEqual({ objectives: [], live: true });
  });
});
