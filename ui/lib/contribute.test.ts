import { describe, expect, it } from "vitest";
import type { Bridge } from "./draft";
import {
  DECLARED_BY_ROLE,
  ROLES,
  describeOffer,
  lanState,
  offerFlags,
  openSheet,
  setRole,
  workCommand,
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

describe("lanState", () => {
  it("is unknown on a node older than the field", () => {
    expect(lanState(undefined, "http://127.0.0.1:8080")).toEqual({ state: "unknown" });
  });

  it("is local on a loopback bind", () => {
    expect(lanState({ bound: "127.0.0.1:8080", lan: false, urls: [] }, "")).toEqual({
      state: "local",
      bound: "127.0.0.1:8080",
    });
  });

  it("lists the node's addresses, or the page's own non-loopback origin", () => {
    expect(
      lanState({ bound: "0.0.0.0:8080", lan: true, urls: ["http://192.168.1.4:8080"] }, ""),
    ).toEqual({ state: "lan", urls: ["http://192.168.1.4:8080"] });
    expect(lanState({ bound: "0.0.0.0:8080", lan: true, urls: [] }, "http://10.0.0.9:8080")).toEqual(
      { state: "lan", urls: ["http://10.0.0.9:8080"] },
    );
    expect(lanState({ bound: "0.0.0.0:8080", lan: true, urls: [] }, "http://127.0.0.1:8080")).toEqual(
      { state: "lan", urls: [] },
    );
  });
});

describe("workCommand", () => {
  it("fills in what it knows and leaves loud placeholders for the rest", () => {
    const text = workCommand({ node: "http://10.0.0.2:8080", objective: "sha256:ab", worker: "garage gpu" });
    expect(text).toContain("--node http://10.0.0.2:8080");
    expect(text).toContain("--objective sha256:ab");
    expect(text).toContain("--worker garage-gpu");
    expect(workCommand({ node: "", objective: null, worker: "" })).toContain("<objective-id>");
  });

  it("names a fleet leader as the submitter when the node leads one", () => {
    const leader = "a".repeat(64);
    expect(workCommand({ node: "x", objective: "y", worker: "box", leader })).toContain(
      `--submitter ${leader}`,
    );
    expect(workCommand({ node: "x", objective: "y", worker: "box" })).not.toContain("--submitter");
  });

  it("strips the commitment-hash separator from a worker name", () => {
    expect(workCommand({ node: "x", objective: "y", worker: "a|b" })).toContain("--worker a-b");
  });
});

describe("an offer of compute", () => {
  it("becomes cairn work flags, leaving out what was not offered", () => {
    const text = workCommand({
      node: "http://10.0.0.2:8080",
      objective: "sha256:ab",
      worker: "rig",
      offer: { gpus: [2, 0, 2], threads: 8, hoursPerDay: 6, device: "RTX 4090" },
    });
    expect(text).toContain("--gpus 0,2");
    expect(text).toContain("--threads 8");
    expect(text).toContain("--hours-per-day 6");
    expect(text).toContain("--device 'RTX 4090'");
    // The solver stays last, after the separator.
    expect(text.trim().endsWith("-- ./your-solver")).toBe(true);
    expect(offerFlags({ gpus: [], hoursPerDay: 24 })).toEqual(["  --gpus none"]);
    expect(offerFlags(undefined)).toEqual([]);
    expect(offerFlags({ threads: 0, hoursPerDay: 0 })).toEqual([]);
  });

  it("is said in a sentence before anything starts", () => {
    expect(describeOffer({ gpus: [0], hoursPerDay: 6 })).toBe("GPU 0, up to 6 hours a day");
    expect(describeOffer({ gpus: [0, 1], threads: 4 })).toBe("GPUs 0, 1 and 4 threads, around the clock");
    expect(describeOffer({})).toBe("this machine, around the clock");
  });
});
