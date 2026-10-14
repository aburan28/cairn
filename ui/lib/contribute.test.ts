import { describe, expect, it } from "vitest";
import type { Bridge } from "./draft";
import {
  DECLARED_BY_ROLE,
  ROLES,
  openSheet,
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
