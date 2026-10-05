/**
 * Goals and angles, as `GET /goals` publishes them (`src/goals.rs`).
 *
 * A goal is the problem -- ECC2K-130 -- and its angles are the approaches
 * funded against it, read off the `goal` handle every objective already
 * carries: `GOAL-<key>[/<angle>/<angle>]`. Two spellings of one goal collapse
 * through the node's alias catalog; the page shows the handles it joined so a
 * reader can see the join. Nothing here is a record: the node derives it from
 * the objectives on every request.
 */

import { NODE_URL } from "./site";
import { expectFields } from "./shape";
import { RouteMissing, NodeUnreachable } from "./network";

export type GoalEntry = {
  id: string;
  goal: string;
  statement_excerpt: string;
  verifier_kind: string;
  reward: number;
  funder: string;
  settled: boolean;
  open: boolean;
  live_workers: number;
};

export type Angle = {
  /** `rho/gpu-kernel`; empty for objectives whose goal names no approach. */
  path: string;
  segments: string[];
  /** The angle this one refines (`rho` for `rho/gpu-kernel`), or null. */
  parent: string | null;
  objectives: GoalEntry[];
  open: number;
  settled: number;
  live_workers: number;
};

export type Goal = {
  /** The canonical normalised key: `certicomecc2k130`. */
  key: string;
  /** The name people use: the catalog's, else the handle less its prefix. */
  name: string;
  /** The handle to post under: `GOAL-certicom-ecc2k130`. */
  handle: string;
  /** Every distinct handle that mapped here, in order of first appearance. */
  handles: string[];
  known: boolean;
  aliases: string[];
  family: string | null;
  summary: string | null;
  objectives: number;
  open: number;
  settled: number;
  reward_total: number;
  live_workers: number;
  angles: Angle[];
  /** On a search result only: how the query matched. */
  match?: "alias" | "contains";
};

/**
 * An angle where compute is scarce: open reward over the workers live on it,
 * plus one -- the one being whoever reads this. A ranking, never a payment.
 */
export type Underserved = {
  goal: string;
  goal_name: string;
  angle: string;
  handle: string;
  open_objectives: number;
  open_reward: number;
  live_workers: number;
  reward_per_worker: number;
  /** Open objective ids, richest first. */
  objectives: string[];
};

export type GoalsResponse = {
  goals: Goal[];
  total: number;
  /** Richest per worker first. Absent on a node older than the field. */
  underserved?: Underserved[];
  catalog: { known: number; source: string };
  handle: string;
  note: string;
};

export type GoalSearch = {
  query: string;
  matches: Goal[];
  total: number;
  note: string;
};

async function read<T extends object>(base: string, route: string, fields: readonly string[]): Promise<T> {
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

export function fetchGoals(base: string = NODE_URL): Promise<GoalsResponse> {
  return read<GoalsResponse>(base, "/goals", ["goals", "total"]);
}

export function findGoals(query: string, base: string = NODE_URL): Promise<GoalSearch> {
  return read<GoalSearch>(base, `/goals?q=${encodeURIComponent(query)}`, ["query", "matches"]);
}

export function fetchGoal(key: string, base: string = NODE_URL): Promise<Goal> {
  return read<Goal>(base, `/goals/${encodeURIComponent(key)}`, ["key", "angles"]);
}

// -- pure helpers, mirrored from src/goals.rs ---------------------------------------

/** Lowercase, no `GOAL-`, letters and digits only: the key two spellings share. */
export function normalizeGoal(text: string): string {
  let t = text.trim();
  if (t.slice(0, 5).toUpperCase() === "GOAL-") t = t.slice(5);
  return t.replace(/[^A-Za-z0-9]/g, "").toLowerCase();
}

/** `GOAL-<key>/<angle>/<angle>` taken apart; never fails. */
export function parseHandle(goal: string): { goal: string; key: string; angle: string[] } {
  const parts = goal.trim().split("/");
  const head = (parts.shift() ?? "").trim();
  return {
    goal: head,
    key: normalizeGoal(head),
    angle: parts.map((s) => s.trim()).filter((s) => s.length > 0),
  };
}

/** `GOAL-<key>/<angle>`, angle segments lowercased, for a drafting tool. */
export function composeHandle(key: string, angle: string[]): string {
  const bare = key.trim().replace(/^GOAL-/i, "");
  const path = angle
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length > 0)
    .join("/");
  return path ? `GOAL-${bare}/${path}` : `GOAL-${bare}`;
}

/** One line for an underserved angle: what is open, and who is on it. */
export function describeUnderserved(row: Underserved): string {
  const objectives = `${row.open_objectives} open objective${row.open_objectives === 1 ? "" : "s"}`;
  const workers =
    row.live_workers === 0
      ? "nobody on it"
      : `${row.live_workers} live worker${row.live_workers === 1 ? "" : "s"} on it`;
  return `${row.open_reward.toLocaleString("en-US")} units across ${objectives}, ${workers}`;
}

/** What an angle path reads as on a page. */
export function angleLabel(path: string): string {
  return path === "" ? "no particular approach" : path;
}

/**
 * One line for a search result: what it is and what is already there, so a
 * person about to post can decide whether to add an angle instead.
 */
export function describeMatch(goal: Goal): string {
  if (goal.objectives === 0) {
    return `${goal.name} is a known goal with nothing funded yet; post the first objective as ${goal.handle}.`;
  }
  const angles = goal.angles.filter((a) => a.path !== "").map((a) => a.path);
  const spelled = goal.handles.length > 1 ? ` (also written ${goal.handles.slice(1).join(", ")})` : "";
  const approaches =
    angles.length === 0
      ? "no angle named yet"
      : `${angles.length} angle${angles.length === 1 ? "" : "s"}: ${angles.join(", ")}`;
  return `${goal.name} already has ${goal.objectives} objective${goal.objectives === 1 ? "" : "s"} (${goal.open} open) under ${goal.handle}${spelled}, ${approaches}. Post yours as ${goal.handle}/<angle>.`;
}
