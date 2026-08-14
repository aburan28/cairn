/**
 * A reader for one node's objectives.
 *
 * Mirrors the shape `GET /objectives` returns (see `src/serve.rs::objectives`).
 * Like `chain.ts`, nothing here re-derives anything: the node decided what is
 * settled and where each frontier stands, and a second opinion computed in
 * TypeScript would be a third place for the rule to drift.
 *
 * The one thing this file *does* compute is how far a ratchet has travelled,
 * and that is arithmetic on two numbers the node already published rather than
 * a judgement about them.
 */

/** Where a ratcheted objective currently stands. Absent until the first claim. */
export type Frontier = {
  claim_id: string;
  /** The submitter's public key, hex. */
  holder: string;
  /** The claim any improvement must cite. Equal to `claim_id` today. */
  must_cite: string;
  paid_cumulative: number;
  pool_remaining: number;
  score: number;
};

export type Objective = {
  id: string;
  goal: string;
  funder: string;
  reward: number;
  statement: string;
  settled: boolean;
  /** "certificate" for pass/fail, "evaluator" for a scored ratchet. */
  verifier_kind: string;
  frontier?: Frontier;
};

export type Objectives = { objectives: Objective[] };

/** Same-origin by default; see the note in `chain.ts`. The daemon serves
 *  this build at /ui/, so relative fetches reach the node that served it. */
export const NODE_URL = process.env.NEXT_PUBLIC_PROOFWORK_NODE ?? "";

export class NodeUnreachable extends Error {}

/**
 * Fetch the objectives.
 *
 * `cache: "no-store"` for the reason `chain.ts` gives: a node that just settled
 * has moved a frontier, and a cached answer would show a pool that is no longer
 * there — which is the number somebody is deciding whether to work against.
 */
export async function fetchObjectives(
  base: string = NODE_URL,
): Promise<Objective[]> {
  let response: Response;
  try {
    response = await fetch(`${base}/objectives`, { cache: "no-store" });
  } catch (cause) {
    throw new NodeUnreachable(
      `No node answered at ${base}. Start one with \`make serve\`, or set ` +
        `NEXT_PUBLIC_PROOFWORK_NODE to where yours is listening.`,
      { cause },
    );
  }
  if (!response.ok) {
    throw new Error(`${base}/objectives answered ${response.status}.`);
  }
  const body = (await response.json()) as Objectives;
  return body.objectives ?? [];
}

/**
 * How much of the funded pool is still payable, as a fraction in [0, 1].
 *
 * `pool_remaining` against `reward` rather than against `paid_cumulative +
 * pool_remaining`: the reward is what was funded, and if those two ever
 * disagree the objective has paid out something the funding did not cover,
 * which is worth seeing rather than normalising away.
 */
export function poolFraction(objective: Objective): number | null {
  if (!objective.frontier || objective.reward <= 0) return null;
  const fraction = objective.frontier.pool_remaining / objective.reward;
  return Math.max(0, Math.min(1, fraction));
}

/**
 * Whether the node published a pool that its own reward cannot account for.
 *
 * Rendered rather than hidden. Everything else on the page is the node's word
 * taken at face value; this is the one arithmetic check the page can do for
 * itself, and the same instinct as `firstBrokenLink` in `chain.ts`.
 */
export function overspent(objective: Objective): boolean {
  if (!objective.frontier) return false;
  const { paid_cumulative, pool_remaining } = objective.frontier;
  return paid_cumulative + pool_remaining > objective.reward;
}

/** A hash or key, short enough to scan a column of them. */
export function short(value: string): string {
  const bare = value.startsWith("sha256:") ? value.slice(7) : value;
  return bare.length <= 12 ? bare : `${bare.slice(0, 8)}…${bare.slice(-4)}`;
}

/**
 * Integer amounts, grouped.
 *
 * No currency symbol and no decimal point: these are integer units, and money
 * in this system is `u64` with checked arithmetic precisely so that nothing
 * renders a fraction of one.
 */
export function amount(value: number): string {
  return value.toLocaleString("en-US");
}

/** A ratcheted objective's declared progression. From `GET /objective/:id`. */
export type Ratchet = {
  baseline: number;
  target: number;
  direction: "maximize" | "minimize" | string;
  min_improvement: number;
  reward: number;
};

/** The verifier an objective pins. Its hash is part of the objective's id. */
export type Verifier = {
  kind: string;
  checker?: string;
  checker_sha256?: string;
  evaluator?: string;
  evaluator_sha256?: string;
  entrypoint?: string;
  threshold?: number;
  direction?: string;
};

/** What `GET /objective/:id` adds over the list view. */
export type ObjectiveDetail = {
  created_at?: string;
  ratchet?: Ratchet;
  verifier?: Verifier;
};

/**
 * Fetch the full record for one objective.
 *
 * The list endpoint carries a summary; the ratchet, the pinned verifier and
 * `created_at` only exist here. Fetched per card rather than folded into the
 * list, because widening `/objectives` would make every reader pay for detail
 * most of them do not want — and this is a reader, so N small requests against
 * a local node is the cheaper mistake.
 *
 * Resolves to `null` on any failure. Detail is an enhancement: a card that
 * cannot load it should show what the list already gave it rather than
 * becoming an error.
 */
export async function fetchObjectiveDetail(
  base: string,
  id: string,
): Promise<ObjectiveDetail | null> {
  try {
    const response = await fetch(`${base}/objective/${id}`, {
      cache: "no-store",
    });
    if (!response.ok) return null;
    const body = (await response.json()) as { record?: ObjectiveDetail };
    return body.record ?? null;
  } catch {
    return null;
  }
}

/**
 * How far a ratchet has travelled from baseline to target, in [0, 1].
 *
 * Direction-aware, because a `minimize` objective counts *down* and a bar that
 * filled as the score rose would show a submitter making things worse as
 * progress. Returns null when the span is degenerate rather than dividing by
 * zero and rendering a confident wrong number.
 */
export function ratchetProgress(
  ratchet: Ratchet,
  score: number,
): number | null {
  const span = ratchet.target - ratchet.baseline;
  if (span === 0) return null;
  const moved = (score - ratchet.baseline) / span;
  return Math.max(0, Math.min(1, moved));
}
