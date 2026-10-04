/**
 * Readers for `GET /sessions` and `GET /network`.
 *
 * Mirrors `src/p2p/sessions.rs::Sessions::report`, `src/serve.rs::network`
 * and `src/network.rs`. The route carries three kinds of fact and this file
 * keeps them as three types on purpose, because a page has to label them
 * differently:
 *
 * - `NodeFacts` is what this process *declares* (its roles, from
 *   `CAIRN_ROLES`) and what it can see of its own machine. A declaration is
 *   a hint about intent and never a permission; the page says "declared".
 * - `PeersSummary`, `Session` and `Compute` are what peers and workers did
 *   and said recently, held in the node's memory and verified by nobody. A
 *   reached peer proved it holds the key its id names and nothing else; a
 *   worker's device is whatever the worker called itself.
 * - `Evidenced` is recomputed from the log: who funded, whose claims were
 *   accepted, who attested. The one part of the answer a reader can check.
 *
 * Nothing here re-derives any of it. The arithmetic below is on numbers the
 * node published, for a view the page filters on the client.
 */

import type { Liveness } from "./progress";

import { expectFields } from "./shape";

export type Reach = "reached" | "recent" | "lost" | "unreached";

export type Session = {
  peer_id: string;
  status: Reach;
  /** The address of the last session, whichever way it ran. An inbound
   *  peer's is its ephemeral source port, not where it listens. */
  addr: string | null;
  last_direction: "inbound" | "outbound";
  first_seen_at: string;
  last_ok_at: string | null;
  age_seconds: number | null;
  last_failed_at: string | null;
  last_error: string | null;
  inbound_ok: number;
  outbound_ok: number;
  failures: number;
  /** This node's ledger length after the last successful session. */
  entries_after: number | null;
};

export type AddressBook = {
  /** Endpoints with a key this node could dial now. */
  endpoints: number;
  /** Signed peer hints learned over the mesh. */
  hints: number;
  noted_at: string | null;
};

/**
 * What the daemon's port-mapping thread last said, mirrored from
 * `src/p2p/reach.rs::Report::to_value`. Every field is present in every
 * status; `address` is where a peer outside would dial, and it is a router's
 * claim until `ThisNode.inbound_from_public_at` says somebody did.
 */
export type External = {
  status: "off" | "searching" | "mapped" | "failed";
  mode: string;
  method: "natpmp" | "upnp" | null;
  gateway: string | null;
  address: string | null;
  /** False when the router's own address is private: a second router or a carrier NAT. */
  public: boolean | null;
  lease_seconds: number | null;
  detail: string | null;
  since: string;
  renewed_at: string | null;
  retry_in_seconds: number | null;
  attempts: number;
};

export type ThisNode = {
  peer_id: string | null;
  listen: string | null;
  started_at: string;
  uptime_seconds: number;
  /** Absent on a node older than the report; null until the daemon has decided. */
  external?: External | null;
  /** The last inbound session from an address outside every private range. */
  inbound_from_public_at?: string | null;
};

export type SessionsResponse = {
  /** False on a plain `cairn serve`, which runs no p2p service at all. */
  available: boolean;
  peers: Session[];
  reached: number;
  recent: number;
  lost: number;
  unreached: number;
  anonymous_inbound_failures?: number;
  address_book?: AddressBook;
  this_node?: ThisNode;
  reached_within_seconds?: number;
  recent_within_seconds?: number;
  note: string;
};

export type DeviceClass = "gpu" | "cpu" | "apple" | "fpga" | "other" | "unreported";

export type FleetWorker = {
  worker: string;
  objective_id: string;
  goal: string | null;
  status: "live" | "stale" | "gone";
  age_seconds: number;
  /** What the worker called its hardware; `unreported` when it said nothing. */
  device: string;
  /** The node's heuristic over that name (`progress::device_class`). */
  class: DeviceClass;
  lanes: number | null;
  client: string | null;
  /** The node's measured rate where it has one, else the reported one. */
  steps_per_second: number | null;
  epoch: number | null;
  units: { first: number; end: number } | null;
};

export type Sum = {
  workers: number;
  live: number;
  /** Summed over live workers only. */
  steps_per_second: number;
  lanes: number;
};

export type DeviceRow = Sum & { device: string; class: DeviceClass };
export type ClassRow = Sum & { class: DeviceClass };
export type ObjectiveRow = Sum & { objective_id: string; goal: string | null };

/** One accelerator as a host's agent described it. */
export type HostGpu = {
  index: number;
  vendor: string;
  model: string | null;
  memory_mb: number | null;
  bus: string | null;
  driver: string | null;
};

/** A machine that registered with `cairn agent` over `POST /hosts`. */
export type HostRow = {
  host: string;
  agent: string | null;
  status: Liveness;
  age_seconds: number;
  first_seen: string;
  received_at: string;
  posts: number;
  roles: string[];
  hardware: {
    cpus?: number | null;
    cpu_model?: string | null;
    memory_mb?: number | null;
    gpus?: HostGpu[];
    os?: string;
    arch?: string;
    kernel?: string | null;
    kvm?: boolean;
  };
  sandboxes: Record<string, { usable?: boolean; via?: string[]; gpu?: boolean; why?: string | null }>;
  usable_sandboxes: string[];
  jobs: { running?: number; capacity?: number; completed?: number; failed?: number };
  objectives: string[];
};

/**
 * The host roster: registered machines beside heartbeating workers, and the
 * two are never added. A host is where workers run; a box with eight GPUs
 * and no worker yet is capacity, not work.
 */
export type Hosts = {
  hosts: HostRow[];
  registered: number;
  live: number;
  stale: number;
  gone: number;
  /** Summed over live hosts only. */
  cpus: number;
  memory_mb: number;
  gpus: number;
  jobs: { running: number; capacity: number };
  sandboxes: { sandbox: string; hosts: number }[];
  live_within_seconds: number;
  stale_within_seconds: number;
  note: string;
};

export type Compute = {
  workers: FleetWorker[];
  live: number;
  stale: number;
  gone: number;
  steps_per_second: number;
  lanes: number;
  devices: DeviceRow[];
  classes: ClassRow[];
  objectives: ObjectiveRow[];
  /** Absent on a node that predates `POST /hosts`. */
  hosts?: Hosts;
  live_within_seconds: number;
  stale_within_seconds: number;
  note: string;
};

export type RoleName = "coordinator" | "executor" | "verifier" | "relay";

export type KnownRole = { role: RoleName; duty: string; evidence: string };

export type Hardware = {
  cpus: number | null;
  memory_mb: number | null;
  os: string;
  arch: string;
  verifier_limits: { cpus: number | null; memory_mb: number | null };
  note: string;
};

export type NodeFacts = {
  roles: { declared: RoleName[]; source: string; known: KnownRole[] };
  /** Declarations the configuration contradicts, in the node's words. */
  warnings: string[];
  hardware: Hardware;
  verifiers: {
    servable: string[];
    unservable: Record<string, string>;
    sandbox: Record<string, unknown>;
  };
  accepts_submissions: boolean;
  runs_p2p: boolean;
  /** Where this node's HTTP side answers. Absent on a node older than it. */
  reach?: { bound: string | null; lan: boolean; urls?: string[] };
};

export type PeersSummary = {
  available: boolean;
  reached: number;
  recent: number;
  lost: number;
  unreached: number;
  /** `peer` records in the log: announcements, not sessions. */
  announced: number;
  address_book?: AddressBook;
  this_node?: ThisNode;
};

export type EvidencedList<T> = { total: number; shown: number; identities: T[] };

export type Coordinator = {
  identity: string;
  objectives: number;
  reward_total: number;
  piecework: number;
};
export type Executor = { identity: string; accepted_claims: number; objectives: number };
export type Verifier = { identity: string; attestations: number; slashed: number };

export type Evidenced = {
  coordinators: EvidencedList<Coordinator>;
  executors: EvidencedList<Executor>;
  verifiers: EvidencedList<Verifier>;
  note: string;
};

export type NetworkResponse = {
  generated_at: string;
  version: string;
  node: NodeFacts;
  peers: PeersSummary;
  compute: Compute;
  roles: Evidenced;
  note: string;
};

export const NODE_URL = process.env.NEXT_PUBLIC_CAIRN_NODE ?? "";

export class NodeUnreachable extends Error {}
/** The node answered 404 for the route itself: it predates it. */
export class RouteMissing extends Error {}

async function read<T extends object>(
  base: string,
  route: string,
  fields: readonly string[],
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${base}${route}`, { cache: "no-store" });
  } catch (cause) {
    throw new NodeUnreachable(
      `No node answered at ${base || "this origin"}. Start one with \`cairn run\`, or set ` +
        `NEXT_PUBLIC_CAIRN_NODE to where yours is listening.`,
      { cause },
    );
  }
  if (response.status === 404) {
    throw new RouteMissing(
      `${base || "this node"} answered 404 for ${route}. That route is newer than the node ` +
        `you are reading; this page needs a node built after it was added.`,
    );
  }
  if (!response.ok) {
    throw new NodeUnreachable(`${base}${route} answered ${response.status}.`);
  }
  return expectFields<T>(await response.json(), fields, `${base || "this node"}${route}`);
}

export function fetchNetwork(base: string = NODE_URL): Promise<NetworkResponse> {
  return read<NetworkResponse>(base, "/network", ["node", "peers", "compute", "roles"]);
}

export function fetchSessions(base: string = NODE_URL): Promise<SessionsResponse> {
  return read<SessionsResponse>(base, "/sessions", ["available", "peers"]);
}

// -- labels -----------------------------------------------------------------------

/** The class a page prints, from the token the node sends. */
export function classLabel(cls: DeviceClass | string): string {
  switch (cls) {
    case "gpu":
      return "GPU";
    case "cpu":
      return "CPU";
    case "apple":
      return "Apple silicon";
    case "fpga":
      return "FPGA";
    case "unreported":
      return "unreported";
    default:
      return "other";
  }
}

export type Tone = "accent" | "warn" | "bad" | "neutral";

/** Reached is good, recent is a question, lost and unreached are not good. */
export function reachTone(status: Reach): Tone {
  switch (status) {
    case "reached":
      return "accent";
    case "recent":
      return "warn";
    case "lost":
      return "neutral";
    case "unreached":
      return "bad";
  }
}

/** One line about whether a stranger can dial this node, and on what evidence. */
export type Reachability = {
  status: "unknown" | "off" | "searching" | "mapped" | "verified" | "double_nat" | "failed";
  label: string;
  detail: string | null;
  tone: Tone;
};

/**
 * Read `this_node.external` and `inbound_from_public_at` together, which is
 * the only honest way to read either: a mapping is a router's claim, an
 * inbound session from outside is the evidence, and each can exist without
 * the other (a port forwarded by hand verifies with no mapping at all).
 * `nowMs` is a parameter so the ages are testable.
 */
export function describeReachability(self: ThisNode | null, nowMs: number = Date.now()): Reachability {
  const inboundAt = self?.inbound_from_public_at ?? null;
  const inboundAgo = inboundAt === null ? null : Math.max(0, Math.floor((nowMs - Date.parse(inboundAt)) / 1000));
  const evidence =
    inboundAgo === null || !Number.isFinite(inboundAgo)
      ? null
      : `a peer from outside reached this node ${formatUptime(inboundAgo)} ago`;
  const external = self?.external;
  if (external === undefined) {
    return {
      status: "unknown",
      label: "not reported",
      detail: evidence ?? "this node predates the port-mapping report",
      tone: evidence ? "accent" : "neutral",
    };
  }
  if (external === null) {
    return {
      status: evidence ? "verified" : "unknown",
      label: evidence ? "reachable" : "unknown",
      detail: evidence ?? "the daemon has not yet said whether it asked its router",
      tone: evidence ? "accent" : "neutral",
    };
  }
  const by = external.method ? `by ${external.method === "natpmp" ? "NAT-PMP" : "UPnP"}` : "";
  const via = external.gateway ? ` via ${external.gateway}` : "";
  switch (external.status) {
    case "off":
      return evidence
        ? { status: "verified", label: "reachable", detail: `${evidence}; port mapping is off`, tone: "accent" }
        : { status: "off", label: "not asked", detail: external.detail, tone: "neutral" };
    case "searching":
      return {
        status: "searching",
        label: "asking the router…",
        detail: `attempt ${external.attempts}, ${external.mode}`,
        tone: "warn",
      };
    case "mapped": {
      const address = external.address ?? "?";
      if (external.public === false) {
        return {
          status: "double_nat",
          label: `mapped ${by}, but ${address} is not public`,
          detail: external.detail,
          tone: "bad",
        };
      }
      if (evidence) {
        return {
          status: "verified",
          label: `reachable at ${address}`,
          detail: `mapped ${by}${via}; ${evidence}`,
          tone: "accent",
        };
      }
      return {
        status: "mapped",
        label: `mapped to ${address}`,
        detail: `${by}${via}; a claim until a peer outside dials in`,
        tone: "warn",
      };
    }
    case "failed":
      if (evidence) {
        return {
          status: "verified",
          label: "reachable without a mapping",
          detail: `${evidence}; the router granted nothing — a port forwarded by hand, probably`,
          tone: "accent",
        };
      }
      return {
        status: "failed",
        label: "not reachable from outside",
        detail:
          (external.detail ?? "no gateway granted a mapping") +
          (external.retry_in_seconds ? `; asking again in ${formatUptime(external.retry_in_seconds)}` : ""),
        tone: "bad",
      };
  }
}

/** `3d 4h`, `2h 05m`, `12m`, `40s`. */
export function formatUptime(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  const s = Math.floor(seconds);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${String(m % 60).padStart(2, "0")}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

/** `15.9 GiB`, `512 MiB`; a dash where the node could not tell. */
export function formatMemory(mb: number | null): string {
  if (mb === null || !Number.isFinite(mb)) return "—";
  if (mb < 1024) return `${mb} MiB`;
  const gib = mb / 1024;
  return `${gib >= 100 ? gib.toFixed(0) : gib.toFixed(1)} GiB`;
}

// -- client-side views over the fleet ---------------------------------------------

/**
 * The totals the node publishes, recomputed over a subset of the fleet, so a
 * page that hides `gone` workers or shows one objective still has honest
 * numbers under its tiles. Rates and lanes sum over live workers only, as
 * the node's do; a stale worker's last rate is a number about the past.
 */
export function fleetTotals(workers: FleetWorker[]): Sum & { stale: number; gone: number } {
  const out = { workers: 0, live: 0, stale: 0, gone: 0, steps_per_second: 0, lanes: 0 };
  for (const worker of workers) {
    out.workers += 1;
    if (worker.status === "live") {
      out.live += 1;
      out.steps_per_second += worker.steps_per_second ?? 0;
      out.lanes += worker.lanes ?? 0;
    } else if (worker.status === "stale") out.stale += 1;
    else out.gone += 1;
  }
  return out;
}

/** The fleet summed by class, over whatever subset the page is showing. */
export function sumByClass(workers: FleetWorker[]): ClassRow[] {
  const rows = new Map<DeviceClass, ClassRow>();
  for (const worker of workers) {
    const row = rows.get(worker.class) ?? {
      class: worker.class,
      workers: 0,
      live: 0,
      steps_per_second: 0,
      lanes: 0,
    };
    row.workers += 1;
    if (worker.status === "live") {
      row.live += 1;
      row.steps_per_second += worker.steps_per_second ?? 0;
      row.lanes += worker.lanes ?? 0;
    }
    rows.set(worker.class, row);
  }
  return [...rows.values()].sort(
    (a, b) => b.steps_per_second - a.steps_per_second || b.live - a.live || a.class.localeCompare(b.class),
  );
}

/** A row's share of a total, for a bar; 0 when there is no total. */
export function share(part: number | null, total: number): number {
  if (part === null || !(total > 0)) return 0;
  return Math.max(0, Math.min(1, part / total));
}

/**
 * Whether a declared role is contradicted, backed, or merely declared, from
 * the node's own warnings and what the node can do. The node already computes
 * the warnings; this only picks the one for a role, so the page can put it
 * on the role's row rather than in a list underneath.
 */
export function roleWarning(role: RoleName, warnings: string[]): string | null {
  return warnings.find((warning) => warning.startsWith(`declares ${role}`)) ?? null;
}

/**
 * One line for a registered host: its CPUs, memory and GPUs as it described
 * them, with absent numbers shown as absent rather than as zero. A host
 * that reported no `hardware` block at all is "unreported".
 */
export function describeHost(row: Pick<HostRow, "hardware">): string {
  const hw = row.hardware ?? {};
  const parts: string[] = [];
  if (typeof hw.cpus === "number") parts.push(`${hw.cpus} cpus`);
  if (typeof hw.memory_mb === "number") parts.push(formatMemory(hw.memory_mb));
  const gpus = hw.gpus ?? [];
  if (gpus.length > 0) {
    const models = new Map<string, number>();
    for (const gpu of gpus) {
      const name = gpu.model ?? gpu.vendor;
      models.set(name, (models.get(name) ?? 0) + 1);
    }
    parts.push(
      [...models.entries()].map(([name, count]) => (count > 1 ? `${count}× ${name}` : name)).join(", "),
    );
  }
  return parts.length === 0 ? "unreported" : parts.join(" · ");
}
