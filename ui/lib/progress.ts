/**
 * A reader for one objective's search in flight: `GET /progress/{id}`.
 *
 * Mirrors `src/serve.rs::progress_of` and `src/progress.rs`. The answer has
 * two halves and this file keeps them as two types on purpose: `Derived` is
 * recomputed from the node's log and is what the search has been paid for;
 * `Reported` is what workers said about themselves over `POST /progress`,
 * held in the node's memory and verified by nobody. A page renders both and
 * says which is which -- the same rule every other page here follows about
 * live and snapshot numbers, applied to a distinction that matters more,
 * because a reported rate is what a reader will extrapolate from.
 *
 * What this file computes for itself is arithmetic on numbers the node
 * published, plus the expected-cost figures from `lib/jobs.ts`, which are
 * statements about Pollard rho rather than about any node. Nothing here
 * re-derives a payment.
 *
 * Integers arrive as JSON numbers. The node's totals are exact `u128`s; a
 * double keeps 53 bits, so a figure above 2^53 (nine quadrillion) is rounded
 * on the way in. One ECC2K-130 tranche is about 2^46 group operations, so
 * nothing a single objective pays for comes near it, and a display that was
 * off in its sixteenth digit would not change what anyone does.
 */

import { expectFields } from "./shape";

export type Window = { claims_paid: number; units_paid: number; steps: number };

export type DerivedWorker = {
  submitter: string;
  claims_paid: number;
  claims: number;
  rejected: number;
  in_flight: number;
  elements: number;
  units_paid: number;
  reward: number;
  steps: number;
  first_paid_at: string | null;
  last_paid_at: string | null;
};

export type Coverage = {
  bins: number;
  units: number;
  trail_bits: number;
  counts: number[];
  units_touched: number;
  unbinned: number;
  method: string;
};

export type Hour = { hour: string; claims_paid: number; units_paid: number; steps: number };

export type Derived = {
  claims_paid: number;
  claims: number;
  rejected: number;
  in_flight: number;
  elements: number;
  units_paid: number;
  reward: number;
  steps: number;
  first_paid_at: string | null;
  last_paid_at: string | null;
  workers: DerivedWorker[];
  hourly: Hour[];
  last_hour: Window;
  last_day: Window;
  coverage: Coverage | null;
  steps_method: string;
  note: string;
};

export type Liveness = "live" | "stale" | "gone";

export type ReportedWorker = {
  worker: string;
  status: Liveness;
  first_seen_at: string;
  received_at: string;
  age_seconds: number;
  epoch: number | null;
  units: { first: number; end: number } | null;
  unit: number | null;
  steps: number;
  trails: number;
  capped: number;
  units_pending: number;
  units_submitted: number;
  reported_steps_per_second: number | null;
  measured_steps_per_second: number | null;
  device: string | null;
  lanes: number | null;
  client: string | null;
};

export type Reported = {
  workers: ReportedWorker[];
  live: number;
  stale: number;
  gone: number;
  /** Sum over live workers of the measured rate, else the reported one. */
  steps_per_second: number;
  steps: number;
  units_pending: number;
  live_within_seconds: number;
  stale_within_seconds: number;
  note: string;
};

/** A piecework objective's standing, as `lifecycle_fields` publishes it. */
export type PieceworkStanding = {
  unit_price: number;
  /** Settlement entries, which for a batch objective is paid *claims*; the
   *  per-unit figure is `derived.units_paid`. */
  paid_units: number;
  paid_total: number;
  pool_remaining: number;
  units?: number;
  key?: string | string[];
  items?: string;
};

export type ProgressResponse = {
  objective_id: string;
  goal: string;
  kind: "piecework" | "ratchet" | "certificate" | string;
  generated_at: string;
  settled: boolean;
  open: boolean;
  piecework?: PieceworkStanding;
  derived: Derived;
  reported: Reported;
  note: string;
};

export const NODE_URL = process.env.NEXT_PUBLIC_CAIRN_NODE ?? "";

export class NodeUnreachable extends Error {}
export class ObjectiveNotFound extends Error {}
/** The node answered 404 for the route itself: it predates `/progress`. */
export class RouteMissing extends Error {}

/**
 * Fetch one objective's progress, or throw.
 *
 * Two 404s are told apart by the body. The node's own "no such objective"
 * is an answer about the id; anything else on 404 is a node built before
 * this route existed, which is worth saying in those words -- a reader who
 * installed last month's release and sees "not found" will check the id.
 */
export async function fetchProgress(
  id: string,
  base: string = NODE_URL,
  options: { trailBits?: number; bins?: number } = {},
): Promise<ProgressResponse> {
  const query = new URLSearchParams();
  if (options.trailBits !== undefined) query.set("trail_bits", String(options.trailBits));
  if (options.bins !== undefined) query.set("bins", String(options.bins));
  const suffix = query.size > 0 ? `?${query}` : "";
  // Not `encodeURIComponent`: the id is `sha256:<hex>` and the server matches
  // the raw remainder after `/progress/`. See `loadObjective` in `site.ts`.
  const url = `${base}/progress/${id}${suffix}`;
  let response: Response;
  try {
    response = await fetch(url, { cache: "no-store" });
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
      throw new ObjectiveNotFound(`This node knows no objective ${short(id)}.`);
    }
    throw new RouteMissing(
      `${base || "this node"} answered 404 for /progress. That route is newer than the ` +
        `node you are reading; this page needs a node built after it was added.`,
    );
  }
  if (!response.ok) {
    throw new NodeUnreachable(`${url} answered ${response.status}.`);
  }
  return expectFields<ProgressResponse>(
    await response.json(),
    ["objective_id", "derived", "reported"],
    `${base || "this node"}/progress/${short(id)}`,
  );
}

/** Post a heartbeat the way a worker does. Here for the demo page and tests;
 *  a worker in production uses `orbit_worker.py`, which posts the same body. */
export async function postHeartbeat(
  base: string,
  heartbeat: Record<string, unknown>,
): Promise<{ status: number; body: unknown }> {
  const response = await fetch(`${base}/progress`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(heartbeat),
  });
  return { status: response.status, body: await response.json().catch(() => null) };
}

export function short(id: string): string {
  const bare = id.startsWith("sha256:") ? id.slice(7) : id;
  return bare.length <= 12 ? bare : `${bare.slice(0, 8)}…${bare.slice(-4)}`;
}

// -- the two halves on one row ------------------------------------------------

/** One worker as the table shows it: what the log paid, beside what it said. */
export type WorkerRow = {
  name: string;
  derived: DerivedWorker | null;
  reported: ReportedWorker | null;
  /** The reported status, or `"settled"` for a name only the log knows. */
  status: Liveness | "settled";
};

/**
 * Join the two halves on the worker's name, which is the submitter the claims
 * were made under. Live workers first, then stale, then gone, then names the
 * log knows and no heartbeat does; within a group, most paid first.
 */
export function mergeWorkers(derived: DerivedWorker[], reported: ReportedWorker[]): WorkerRow[] {
  const rows = new Map<string, WorkerRow>();
  for (const worker of derived) {
    rows.set(worker.submitter, {
      name: worker.submitter,
      derived: worker,
      reported: null,
      status: "settled",
    });
  }
  for (const worker of reported) {
    const row = rows.get(worker.worker);
    if (row) {
      row.reported = worker;
      row.status = worker.status;
    } else {
      rows.set(worker.worker, {
        name: worker.worker,
        derived: null,
        reported: worker,
        status: worker.status,
      });
    }
  }
  const rank: Record<WorkerRow["status"], number> = { live: 0, stale: 1, gone: 2, settled: 3 };
  return [...rows.values()].sort((a, b) => {
    if (rank[a.status] !== rank[b.status]) return rank[a.status] - rank[b.status];
    const paid = (row: WorkerRow) => row.derived?.units_paid ?? 0;
    if (paid(a) !== paid(b)) return paid(b) - paid(a);
    return a.name.localeCompare(b.name);
  });
}

/** A worker's own rate: the one the node measured when it has one, else the
 *  one the worker reported, else nothing. */
export function workerRate(worker: ReportedWorker | null): number | null {
  if (!worker) return null;
  return worker.measured_steps_per_second ?? worker.reported_steps_per_second ?? null;
}

// -- the search as a whole ------------------------------------------------------

/** `steps / expected`, unclamped: a search past its expected cost reads over 1. */
export function shareOfExpected(steps: number, expected: number): number | null {
  if (!(expected > 0) || !Number.isFinite(steps)) return null;
  return steps / expected;
}

/**
 * The chance a collision has already happened after `steps` of a search whose
 * expected cost is `expected`: `1 - exp(-pi/4 * (W/E)^2)`, the birthday bound
 * with the expectation normalised to `E`. Even odds fall at 0.94 E and nine
 * in ten at 1.71 E, which is why a search "past its expected cost" is not
 * late. The campaign's status page draws the same curve.
 */
export function collisionOdds(steps: number, expected: number): number | null {
  const ratio = shareOfExpected(steps, expected);
  if (ratio === null) return null;
  return -Math.expm1((-Math.PI / 4) * ratio * ratio);
}

/** The work at which the odds reach `p`: the inverse of `collisionOdds`. */
export function workForOdds(p: number, expected: number): number | null {
  if (!(expected > 0) || !(p > 0) || !(p < 1)) return null;
  return expected * Math.sqrt((-4 * Math.log1p(-p)) / Math.PI);
}

/**
 * Seconds until the search reaches its expected cost at `rate` steps a
 * second, or null with no rate. Negative means past it, which `collisionOdds`
 * says is a 54% chance of being done, not an overrun.
 */
export function etaSeconds(steps: number, expected: number, rate: number | null): number | null {
  if (rate === null || !(rate > 0) || !(expected > 0)) return null;
  return (expected - steps) / rate;
}

// -- coverage and history -------------------------------------------------------

/** The share of bins with at least one paid element in them. */
export function coverageFraction(coverage: Coverage | null): number | null {
  if (!coverage || coverage.bins === 0) return null;
  return coverage.counts.filter((count) => count > 0).length / coverage.bins;
}

/**
 * Which bins of the unit space the live workers hold this epoch, from their
 * reported `units` ranges. `[first, end)` of `units` maps onto bins the way
 * the node bins paid seeds: `bin = unit * bins / units`, so the two layers
 * of the strip line up.
 */
export function assignedBins(
  workers: ReportedWorker[],
  units: number,
  bins: number,
): { name: string; from: number; to: number }[] {
  if (!(units > 0) || !(bins > 0)) return [];
  const out: { name: string; from: number; to: number }[] = [];
  for (const worker of workers) {
    if (worker.status !== "live" || !worker.units) continue;
    const { first, end } = worker.units;
    if (end <= first) continue;
    const from = Math.min(bins - 1, Math.floor((first * bins) / units));
    // The last unit of the range, not `end`, so a range ending on a bin
    // boundary does not light the bin after it.
    const to = Math.min(bins - 1, Math.floor(((end - 1) * bins) / units));
    out.push({ name: worker.worker, from, to });
  }
  return out;
}

/**
 * The last `hours` hourly buckets ending at the hour containing `now`, with
 * empty hours as zeros, so a chart shows the gaps -- an hour with no
 * settlement is a fact about the search, not a missing bar.
 */
export function denseHours(hourly: Hour[], hours: number, now: Date): Hour[] {
  const byStart = new Map<number, Hour>();
  for (const hour of hourly) {
    const at = Date.parse(hour.hour);
    if (Number.isFinite(at)) byStart.set(at - (at % 3_600_000), hour);
  }
  const end = now.getTime() - (now.getTime() % 3_600_000);
  const out: Hour[] = [];
  for (let i = hours - 1; i >= 0; i -= 1) {
    const start = end - i * 3_600_000;
    out.push(
      byStart.get(start) ?? {
        hour: new Date(start).toISOString().replace(".000Z", "+00:00"),
        claims_paid: 0,
        units_paid: 0,
        steps: 0,
      },
    );
  }
  return out;
}

// -- formatting -------------------------------------------------------------------

/** `2^60.81`, for a count whose magnitude is the point. */
export function formatLog2(value: number): string {
  if (!(value > 0)) return "2^−∞";
  return `2^${Math.log2(value).toFixed(2)}`;
}

/** `1.40 G it/s`, `12.3 M it/s`, `950 it/s`. */
export function formatRate(stepsPerSecond: number | null): string {
  if (stepsPerSecond === null || !Number.isFinite(stepsPerSecond)) return "—";
  return `${formatMagnitude(stepsPerSecond)} it/s`;
}

export function formatMagnitude(value: number): string {
  const units: [number, string][] = [
    [1e15, "P"],
    [1e12, "T"],
    [1e9, "G"],
    [1e6, "M"],
    [1e3, "k"],
  ];
  for (const [scale, suffix] of units) {
    if (value >= scale) {
      const scaled = value / scale;
      return `${scaled >= 100 ? scaled.toFixed(0) : scaled >= 10 ? scaled.toFixed(1) : scaled.toFixed(2)} ${suffix}`;
    }
  }
  return value.toLocaleString("en-US", { maximumFractionDigits: 0 });
}

/** `3d 4h`, `12 min`, `2.5 y`; negative reads as `past by …`. */
export function formatDuration(seconds: number | null): string {
  if (seconds === null || !Number.isFinite(seconds)) return "—";
  const past = seconds < 0;
  const s = Math.abs(seconds);
  let text: string;
  if (s < 60) text = `${Math.round(s)} s`;
  else if (s < 3600) text = `${Math.round(s / 60)} min`;
  else if (s < 86_400) text = `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min`;
  else if (s < 365.25 * 86_400) text = `${Math.floor(s / 86_400)} d ${Math.round((s % 86_400) / 3600)} h`;
  else text = `${(s / (365.25 * 86_400)).toFixed(1)} y`;
  return past ? `past by ${text}` : text;
}

/** A percentage with the precision its size deserves: 0.004% is not 0%. */
export function formatPercent(fraction: number | null): string {
  if (fraction === null || !Number.isFinite(fraction)) return "—";
  const pct = fraction * 100;
  if (pct === 0) return "0%";
  if (pct < 0.01) return `${pct.toExponential(1)}%`;
  if (pct < 1) return `${pct.toFixed(3)}%`;
  if (pct < 10) return `${pct.toFixed(2)}%`;
  return `${pct.toFixed(1)}%`;
}

/** `42 s ago`, `3 min ago`, `2 h ago`. */
export function formatAge(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)} s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 86_400) return `${Math.round(seconds / 3600)} h ago`;
  return `${Math.round(seconds / 86_400)} d ago`;
}

export function amount(value: number | null | undefined): string {
  return typeof value === "number" ? value.toLocaleString("en-US") : "—";
}
