import { describe, expect, it } from "vitest";
import { ROLES, lanState, workCommand } from "./contribute";

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
