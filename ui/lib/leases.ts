/**
 * Readers for the coordination of one divided search: the epoch's work
 * assignment (`GET /work_assignment`), the advisory task leases
 * (`GET /leases/{id}`, `src/lease.rs`), and the arithmetic that lays the
 * live workers' reported ranges over the epoch's partitions.
 *
 * Two things are kept apart here as everywhere else. The assignment is a
 * pure function of public inputs that anyone recomputes; what a worker
 * *reports* holding (its heartbeat's `units`) and what it *leases* are
 * statements the worker made, held in the node's memory and verified by
 * nobody. A lease is advice to the next worker, never a lock -- nothing that
 * pays reads one -- and the page says so where it draws them.
 *
 * The partition arithmetic below mirrors `partition::Assignment::share` and
 * `piecework::Piecework::unit_range` exactly, in BigInt, because a unit count
 * of 2^48 times a slice bound of 2^32 does not fit a double and a boundary
 * off by one would draw a worker in its neighbour's slice.
 */

import { expectFields } from "./shape";
import type { ReportedWorker } from "./progress";

export type LeaseStatus = "held" | "contended" | "expired" | "released";
export type Outcome = "completed" | "failed" | "abandoned";

export type Lease = {
  holder: string;
  status: LeaseStatus;
  since: string;
  renewed_at: string;
  expires_at: string;
  expires_in_seconds: number;
  ttl_seconds: number;
  units: { first: number; end: number } | null;
  epoch: number | null;
  note: string | null;
  released: { at: string; outcome: Outcome } | null;
  /** Claimed by an enrolled fleet member. Absent on a node older than enrollment. */
  member?: boolean;
};

export type TaskLeases = {
  task: string;
  /** `held` while a live lease holds it, `completed` once released so, else `open`. */
  status: "held" | "open" | "completed";
  holder: string | null;
  completed_by: string | null;
  leases: Lease[];
};

export type LeasesResponse = {
  objective_id: string;
  generated_at: string;
  tasks: TaskLeases[];
  held: number;
  contended: number;
  expired: number;
  released: number;
  completed: number;
  default_ttl_seconds: number;
  max_ttl_seconds: number;
  note: string;
};

export type Assignment = {
  node_id: string;
  objective_id: string;
  epoch: number;
  epoch_seconds: number;
  epoch_ends_in_seconds: number;
  anchor: string;
  partition: number;
  partitions: number;
  slice: { lo: number; hi: number };
  units: { first: number; end: number; of: number; unit_price: number } | null;
  note: string;
};

export const NODE_URL = process.env.NEXT_PUBLIC_CAIRN_NODE ?? "";

export class NodeUnreachable extends Error {}
export class ObjectiveNotFound extends Error {}
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
    const text = await response.text();
    if (text.includes("no such objective")) {
      throw new ObjectiveNotFound("This node knows no such objective.");
    }
    throw new RouteMissing(
      `${base || "this node"} answered 404 for ${route.split("?")[0]}. That route is newer ` +
        `than the node you are reading; this page needs a node built after it was added.`,
    );
  }
  if (!response.ok) {
    throw new NodeUnreachable(`${base}${route} answered ${response.status}.`);
  }
  return expectFields<T>(await response.json(), fields, `${base || "this node"}${route}`);
}

/** One objective's leases. The id is `sha256:…` and the server matches the
 *  raw remainder after `/leases/`, so it is not percent-encoded. */
export function fetchLeases(id: string, base: string = NODE_URL): Promise<LeasesResponse> {
  return read<LeasesResponse>(base, `/leases/${id}`, ["objective_id", "tasks"]);
}

export function fetchLeaseIndex(base: string = NODE_URL): Promise<{ objectives: string[] }> {
  return read<{ objectives: string[] }>(base, "/leases", ["objectives"]);
}

/**
 * The epoch's assignment for `nodeId`. The page asks as a reader -- any
 * name works, since the answer is a pure function -- for the epoch clock,
 * the anchor and the unit count; the partition it is handed is one slice
 * among `partitions`, drawn like any other.
 */
export function fetchAssignment(
  id: string,
  nodeId: string,
  partitions: number,
  base: string = NODE_URL,
): Promise<Assignment> {
  const query = new URLSearchParams({
    objective_id: id,
    node_id: nodeId,
    partitions: String(partitions),
  });
  return read<Assignment>(base, `/work_assignment?${query}`, [
    "epoch",
    "epoch_seconds",
    "epoch_ends_in_seconds",
    "partitions",
  ]);
}

// -- the epoch -----------------------------------------------------------------------

/** How far through the epoch the clock is, 0 at the start and 1 at the turn. */
export function epochProgress(epochSeconds: number, endsInSeconds: number): number {
  if (!(epochSeconds > 0)) return 0;
  const elapsed = epochSeconds - endsInSeconds;
  return Math.max(0, Math.min(1, elapsed / epochSeconds));
}

// -- partitions over the unit space ---------------------------------------------------

/** `partition::SPACE`: the unit interval scaled to 2^32. */
const SPACE = 1n << 32n;

export type PartitionCell = {
  index: number;
  /** `[first, end)` of the objective's units this partition covers. */
  first: number;
  end: number;
  /** Live workers whose reported range overlaps this partition. */
  holders: string[];
  /** Live leases whose range overlaps this partition. */
  leased: string[];
};

/**
 * The unit range of partition `index` of `partitions`, exactly as the node
 * computes it: `step = floor(2^32 / partitions)`, the slice is
 * `[index * step, index * step + step)` except that the last partition runs
 * to `2^32`, and each bound maps to a unit by `floor(bound * units / 2^32)`.
 * Two floor divisions, so neighbouring partitions abut.
 */
export function partitionUnits(
  index: number,
  partitions: number,
  units: number,
): { first: number; end: number } {
  if (!(partitions > 0) || !(units >= 0) || index < 0 || index >= partitions) {
    return { first: 0, end: 0 };
  }
  const n = BigInt(partitions);
  const step = SPACE / n;
  const lo = BigInt(index) * step;
  const hi = index === partitions - 1 ? SPACE : lo + step;
  const u = BigInt(Math.floor(units));
  return { first: Number((lo * u) / SPACE), end: Number((hi * u) / SPACE) };
}

/**
 * Every partition of the unit space, with the live workers and live leases
 * that overlap it. A worker is placed by the `units` range it reported this
 * epoch; a lease by the range it declared. Both are the worker's own words.
 * Stale and gone workers are left out: a range somebody reported half an
 * hour ago is a range nobody is on.
 */
export function partitionHolders(
  workers: ReportedWorker[],
  leases: TaskLeases[],
  units: number,
  partitions: number,
): PartitionCell[] {
  if (!(partitions > 0) || !(units > 0)) return [];
  const cells: PartitionCell[] = [];
  for (let index = 0; index < partitions; index += 1) {
    const { first, end } = partitionUnits(index, partitions, units);
    cells.push({ index, first, end, holders: [], leased: [] });
  }
  const overlaps = (range: { first: number; end: number }, cell: PartitionCell) =>
    range.end > range.first && range.first < cell.end && range.end > cell.first;
  for (const worker of workers) {
    if (worker.status !== "live" || !worker.units) continue;
    for (const cell of cells) {
      if (overlaps(worker.units, cell)) cell.holders.push(worker.worker);
    }
  }
  for (const task of leases) {
    for (const lease of task.leases) {
      if (lease.status !== "held" && lease.status !== "contended") continue;
      if (!lease.units) continue;
      for (const cell of cells) {
        if (overlaps(lease.units, cell) && !cell.leased.includes(lease.holder)) {
          cell.leased.push(lease.holder);
        }
      }
    }
  }
  return cells;
}

/** How many partitions nobody, one worker, or more than one worker reports holding. */
export function coverageSummary(cells: PartitionCell[]): {
  covered: number;
  uncovered: number;
  contested: number;
} {
  let covered = 0;
  let uncovered = 0;
  let contested = 0;
  for (const cell of cells) {
    if (cell.holders.length === 0) uncovered += 1;
    else if (cell.holders.length === 1) covered += 1;
    else contested += 1;
  }
  return { covered, uncovered, contested };
}

// -- leases as rows ----------------------------------------------------------------

export type LeaseRow = Lease & { task: string; taskStatus: TaskLeases["status"] };

/**
 * Every lease on every task as one list: held first, then contended, then
 * expired, then released; within a group the one expiring soonest first,
 * then by task name. The order a worker scans for "what is free".
 */
export function leaseRows(tasks: TaskLeases[]): LeaseRow[] {
  const rank: Record<LeaseStatus, number> = { held: 0, contended: 1, expired: 2, released: 3 };
  const rows: LeaseRow[] = [];
  for (const task of tasks) {
    for (const lease of task.leases) {
      rows.push({ ...lease, task: task.task, taskStatus: task.status });
    }
  }
  return rows.sort((a, b) => {
    if (rank[a.status] !== rank[b.status]) return rank[a.status] - rank[b.status];
    if (a.expires_in_seconds !== b.expires_in_seconds) {
      return a.expires_in_seconds - b.expires_in_seconds;
    }
    return a.task.localeCompare(b.task) || a.holder.localeCompare(b.holder);
  });
}

export type Tone = "accent" | "warn" | "bad" | "neutral";

export function leaseTone(status: LeaseStatus): Tone {
  switch (status) {
    case "held":
      return "accent";
    case "contended":
      return "warn";
    case "expired":
      return "neutral";
    case "released":
      return "neutral";
  }
}

export function taskTone(status: TaskLeases["status"]): Tone {
  switch (status) {
    case "held":
      return "accent";
    case "completed":
      return "accent";
    case "open":
      return "neutral";
  }
}

/** The body a worker posts to claim a task, for the copy button. */
export function claimCommand(origin: string, objectiveId: string, units: number | null): string {
  const example = units && units > 0 ? `unit:${Math.min(4017, units - 1)}` : "unit:4017";
  const range =
    units && units > 0
      ? `,\n  "units": {"first": ${Math.min(4017, units - 1)}, "end": ${Math.min(4018, units)}}`
      : "";
  return [
    `curl -s -H 'content-type: application/json' ${origin}/lease -d '{`,
    `  "objective_id": "${objectiveId}",`,
    `  "task": "${example}", "holder": "<your name>", "ttl_seconds": 600${range}}'`,
  ].join("\n");
}
