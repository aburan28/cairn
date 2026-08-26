/**
 * A reader for one objective's frontier: the best verified result, and
 * every result it displaced.
 *
 * Mirrors `GET /objective/:id` (see `src/serve.rs::objective`) for the
 * objective itself, and reads `GET /log` (via `lib/log.ts`) to lay out the
 * successive frontier states — the cairn itself, in the order stones were
 * added. Nothing here recomputes a score or a payout; see `buildMoves` in
 * `lib/log.ts` for what is and is not re-derived and why.
 */

import { type Ratchet, type Verifier, short as shortId } from "@/lib/objectives";
import { type FrontierMove, buildMoves, fetchLog } from "@/lib/log";
import { expectFields } from "@/lib/shape";

export { short } from "@/lib/objectives";
export type { FrontierMove };

export type Frontier = {
  claim_id: string;
  holder: string;
  must_cite: string;
  paid_cumulative: number;
  pool_remaining: number;
  score: number;
};

export type ObjectiveRecord = {
  created_at?: string;
  funder: string;
  goal: string;
  reward: number;
  statement: string;
  ratchet?: Ratchet;
  verifier?: Verifier;
};

export type ObjectiveResponse = {
  id: string;
  frontier?: Frontier;
  record: ObjectiveRecord;
};

export const NODE_URL = process.env.NEXT_PUBLIC_CAIRN_NODE ?? "";

export class NodeUnreachable extends Error {}
export class ObjectiveNotFound extends Error {}

/** Fetch one objective's full record, or throw. Unlike
 *  `fetchObjectiveDetail` in `objectives.ts` — written as an enhancement
 *  that quietly resolves to `null` for a card that already has a summary —
 *  this page has nothing to fall back to, so a failure here is an error the
 *  page must show. */
export async function fetchObjective(
  id: string,
  base: string = NODE_URL,
): Promise<ObjectiveResponse> {
  let response: Response;
  try {
    response = await fetch(`${base}/objective/${id}`, { cache: "no-store" });
  } catch (cause) {
    throw new NodeUnreachable(
      `No node answered at ${base}. Start one with \`make serve\`, or set ` +
        `NEXT_PUBLIC_CAIRN_NODE to where yours is listening.`,
      { cause },
    );
  }
  if (response.status === 404) {
    throw new ObjectiveNotFound(`This node knows no objective ${shortId(id)}.`);
  }
  if (!response.ok) {
    throw new NodeUnreachable(`${base}/objective/${id} answered ${response.status}.`);
  }
  return expectFields<ObjectiveResponse>(
    await response.json(),
    ["id", "record"],
    `${base}/objective/${id}`,
  );
}

/**
 * The move history for one objective, oldest first.
 *
 * A second request, against `/log`, deliberately not folded into
 * `fetchObjective`: the objective endpoint answers in one read of the node's
 * in-memory state, while this walks the whole log, and a page that always
 * paid that cost even for an objective with no claims yet would make every
 * card slower for a feature most cards do not need.
 */
export async function fetchMoves(
  objectiveId: string,
  base: string = NODE_URL,
): Promise<MoveHistory> {
  const { records, problems } = await fetchLog(base);
  return { moves: buildMoves(records, objectiveId), problems };
}

/** The moves, and any log line that could not be read on the way to them.
 *  Carried rather than dropped: a move history built from a log with a
 *  corrupt line is a history with a hole in it, and the page must say so. */
export type MoveHistory = { moves: FrontierMove[]; problems: string[] };

/**
 * How far a ratchet has travelled from baseline to target, in [0, 1].
 *
 * Identical to `ratchetProgress` in `objectives.ts` — kept here too rather
 * than imported, because the two pages otherwise share no dependency and a
 * six-line direction-aware division is not worth coupling them for.
 */
export function ratchetProgress(ratchet: Ratchet, score: number): number | null {
  const span = ratchet.target - ratchet.baseline;
  if (span === 0) return null;
  const moved = (score - ratchet.baseline) / span;
  return Math.max(0, Math.min(1, moved));
}

/** Integer amounts, grouped. See `objectives.ts` for why no currency symbol
 *  and no decimal point. */
export function amount(value: number): string {
  return value.toLocaleString("en-US");
}

/**
 * Whether the published pool can be accounted for by its own moves.
 *
 * The frontier's own `paid_cumulative` plus `pool_remaining` should equal
 * the objective's `reward` (this is `overspent` from `objectives.ts`,
 * repeated here so this page makes the same check on the same two numbers)
 * — and separately, the moves list's own running total should land on that
 * same `paid_cumulative`. Two independent sums disagreeing with the node's
 * headline number is worth a red panel rather than a silent pick.
 */
export function overspent(frontier: Frontier, reward: number): boolean {
  return frontier.paid_cumulative + frontier.pool_remaining > reward;
}
