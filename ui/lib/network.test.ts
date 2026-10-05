import { describe, expect, it } from "vitest";
import {
  type External,
  type FleetWorker,
  type ThisNode,
  classLabel,
  describeHost,
  describeReachability,
  fleetMembers,
  fleetSigning,
  fleetTotals,
  formatMemory,
  formatUptime,
  reachTone,
  roleWarning,
  share,
  sumByClass,
} from "./network";

const worker = (
  name: string,
  status: FleetWorker["status"],
  cls: FleetWorker["class"],
  rate: number | null,
  lanes: number | null = null,
): FleetWorker => ({
  worker: name,
  objective_id: "sha256:o",
  goal: "ECC2K-130",
  status,
  age_seconds: 10,
  device: cls === "unreported" ? "unreported" : `a ${cls}`,
  class: cls,
  lanes,
  client: null,
  steps_per_second: rate,
  epoch: 3,
  units: null,
});

describe("fleetTotals", () => {
  it("sums rates and lanes over live workers only, and counts the rest", () => {
    const totals = fleetTotals([
      worker("a", "live", "gpu", 5000, 128),
      worker("b", "live", "cpu", 40, 16),
      worker("c", "stale", "gpu", 9999, 999),
      worker("d", "gone", "apple", null),
      worker("e", "live", "unreported", null),
    ]);
    expect(totals).toEqual({
      workers: 5,
      live: 3,
      stale: 1,
      gone: 1,
      steps_per_second: 5040,
      lanes: 144,
    });
  });

  it("is zero over nobody", () => {
    expect(fleetTotals([]).steps_per_second).toBe(0);
    expect(fleetTotals([]).workers).toBe(0);
  });
});

describe("sumByClass", () => {
  it("groups by class with the fastest class first and counts stale workers without their rate", () => {
    const rows = sumByClass([
      worker("a", "live", "gpu", 5000),
      worker("b", "live", "cpu", 40),
      worker("c", "stale", "cpu", 1_000_000),
      worker("d", "live", "gpu", 3000),
    ]);
    expect(rows.map((r) => r.class)).toEqual(["gpu", "cpu"]);
    expect(rows[0]).toMatchObject({ workers: 2, live: 2, steps_per_second: 8000 });
    expect(rows[1]).toMatchObject({ workers: 2, live: 1, steps_per_second: 40 });
  });
});

describe("labels and tones", () => {
  it("names every class the node can send, and says other for one it cannot", () => {
    expect(classLabel("gpu")).toBe("GPU");
    expect(classLabel("apple")).toBe("Apple silicon");
    expect(classLabel("fpga")).toBe("FPGA");
    expect(classLabel("unreported")).toBe("unreported");
    expect(classLabel("quantum")).toBe("other");
  });

  it("colours reach so that lost reads as nothing and unreached as a problem", () => {
    expect(reachTone("reached")).toBe("accent");
    expect(reachTone("recent")).toBe("warn");
    expect(reachTone("lost")).toBe("neutral");
    expect(reachTone("unreached")).toBe("bad");
  });

  it("picks the node's own warning for a role, and nothing for a backed one", () => {
    const warnings = [
      "declares coordinator but accepts no submissions (started without --queue): …",
      "declares relay but this process runs no p2p service …",
    ];
    expect(roleWarning("coordinator", warnings)).toMatch(/--queue/);
    expect(roleWarning("relay", warnings)).toMatch(/p2p/);
    expect(roleWarning("verifier", warnings)).toBeNull();
  });
});

describe("formatting", () => {
  it("formats uptime in the largest two units that matter", () => {
    expect(formatUptime(40)).toBe("40s");
    expect(formatUptime(12 * 60)).toBe("12m");
    expect(formatUptime(2 * 3600 + 5 * 60)).toBe("2h 05m");
    expect(formatUptime(3 * 86_400 + 4 * 3600)).toBe("3d 4h");
    expect(formatUptime(-1)).toBe("—");
  });

  it("formats memory in MiB below a GiB and GiB above, and dashes the unknown", () => {
    expect(formatMemory(512)).toBe("512 MiB");
    expect(formatMemory(15932)).toBe("15.6 GiB");
    expect(formatMemory(1024 * 1024)).toBe("1024 GiB");
    expect(formatMemory(null)).toBe("—");
  });

  it("clamps a share into [0, 1] and is 0 with no total", () => {
    expect(share(50, 200)).toBe(0.25);
    expect(share(500, 200)).toBe(1);
    expect(share(null, 200)).toBe(0);
    expect(share(5, 0)).toBe(0);
  });
});

describe("describeHost", () => {
  it("names cpus, memory and gpus as the host reported them, grouping identical cards", () => {
    expect(
      describeHost({
        hardware: {
          cpus: 128,
          memory_mb: 515821,
          gpus: [
            { index: 0, vendor: "nvidia", model: "NVIDIA A100-SXM4-80GB", memory_mb: 81920, bus: null, driver: null },
            { index: 1, vendor: "nvidia", model: "NVIDIA A100-SXM4-80GB", memory_mb: 81920, bus: null, driver: null },
            { index: 2, vendor: "amd", model: null, memory_mb: null, bus: null, driver: null },
          ],
        },
      }),
    ).toBe("128 cpus · 504 GiB · 2× NVIDIA A100-SXM4-80GB, amd");
  });

  it("leaves out what the host did not say rather than printing zero", () => {
    expect(describeHost({ hardware: { cpus: 4 } })).toBe("4 cpus");
    expect(describeHost({ hardware: {} })).toBe("unreported");
  });
});

describe("describeReachability", () => {
  const now = Date.parse("2026-10-04T12:00:00Z");
  const node = (external: External | null | undefined, inbound: string | null = null): ThisNode => ({
    peer_id: "ab".repeat(32),
    listen: "0.0.0.0:9000",
    started_at: "2026-10-04T11:00:00Z",
    uptime_seconds: 3600,
    ...(external === undefined ? {} : { external }),
    inbound_from_public_at: inbound,
  });
  const external = (over: Partial<External>): External => ({
    status: "mapped",
    mode: "auto",
    method: "upnp",
    gateway: "192.168.1.1",
    address: "203.0.113.7:9000",
    public: true,
    lease_seconds: 3600,
    detail: null,
    since: "2026-10-04T11:00:05Z",
    renewed_at: null,
    retry_in_seconds: null,
    attempts: 1,
    ...over,
  });

  it("says an older node reported nothing, and that nobody has decided yet", () => {
    expect(describeReachability(null, now).status).toBe("unknown");
    expect(describeReachability(node(undefined), now)).toMatchObject({ status: "unknown", tone: "neutral" });
    expect(describeReachability(node(null), now)).toMatchObject({ status: "unknown", label: "unknown" });
  });

  it("treats a mapping as a claim until a peer from outside dialled in", () => {
    const claim = describeReachability(node(external({})), now);
    expect(claim).toMatchObject({ status: "mapped", tone: "warn", label: "mapped to 203.0.113.7:9000" });
    expect(claim.detail).toContain("UPnP");
    expect(claim.detail).toContain("claim");

    const verified = describeReachability(node(external({ method: "natpmp" }), "2026-10-04T11:57:00Z"), now);
    expect(verified).toMatchObject({ status: "verified", tone: "accent", label: "reachable at 203.0.113.7:9000" });
    expect(verified.detail).toContain("NAT-PMP");
    expect(verified.detail).toContain("3m ago");
  });

  it("calls a private external address what it is, whatever the router said", () => {
    const doubled = describeReachability(
      node(external({ address: "100.64.3.9:9000", public: false, detail: "carrier-grade NAT" })),
      now,
    );
    expect(doubled).toMatchObject({ status: "double_nat", tone: "bad", detail: "carrier-grade NAT" });
    expect(doubled.label).toContain("100.64.3.9:9000 is not public");
  });

  it("reads off, searching and failed, and lets evidence override a failure", () => {
    const off = describeReachability(node(external({ status: "off", method: null, address: null, detail: "off (CAIRN_PORTMAP)" })), now);
    expect(off).toMatchObject({ status: "off", tone: "neutral", detail: "off (CAIRN_PORTMAP)" });

    const searching = describeReachability(node(external({ status: "searching", method: null, address: null, attempts: 2 })), now);
    expect(searching).toMatchObject({ status: "searching", tone: "warn" });
    expect(searching.detail).toContain("attempt 2");

    const failed = describeReachability(
      node(external({ status: "failed", method: null, address: null, detail: "no gateway answered", retry_in_seconds: 300 })),
      now,
    );
    expect(failed).toMatchObject({ status: "failed", tone: "bad" });
    expect(failed.detail).toBe("no gateway answered; asking again in 5m");

    const forwarded = describeReachability(
      node(external({ status: "failed", method: null, address: null, detail: "no gateway answered" }), "2026-10-04T11:59:20Z"),
      now,
    );
    expect(forwarded).toMatchObject({ status: "verified", tone: "accent" });
    expect(forwarded.detail).toContain("40s ago");
    expect(forwarded.detail).toContain("by hand");
  });
});

describe("fleet signing", () => {
  const leader = "ab".repeat(32);
  it("says an enrolled-only leader signs for its members from anywhere", () => {
    const fleet = { sources: ["enrolled"], signs_as: leader, members: { enrolled: 3, live: 1 } };
    expect(fleetSigning(fleet)).toContain("from any address, only for members it enrolled");
    expect(fleetMembers(fleet)).toBe(
      "3 enrolled members, 1 heard from in the last few minutes; `cairn fleet list` on the leader names them",
    );
  });
  it("names the networks it still trusts beside its members", () => {
    const fleet = { sources: ["enrolled", "127.0.0.0/8"], signs_as: leader, members: { enrolled: 1, live: 1 } };
    expect(fleetSigning(fleet)).toContain("for enrolled members, and for anything on 127.0.0.0/8");
    expect(fleetMembers(fleet)).toMatch(/^1 enrolled member,/);
  });
  it("keeps the network-only wording, and no members line, for an older leader", () => {
    const fleet = { sources: ["10.0.0.0/8"], signs_as: leader };
    expect(fleetSigning(fleet)).toBe("unsigned records from these networks that name this node are signed here, as");
    expect(fleetMembers(fleet)).toBeNull();
  });
});
