/**
 * The site's data layer: a live node when one answers, the settled log when
 * none does.
 *
 * # Why there is a fallback at all
 *
 * Yukon's landing page labels its own leaderboard SIMULATED. For a project
 * whose single claim is that anyone can re-derive every settled result from the
 * log alone, inventing a leaderboard would refute the pitch on the page making
 * it. So the fallback is not mock data: it is `launch/cairn.jsonl`, a genuinely
 * settled log that ships in the repository, signed at merkle root 3ae18b50… and
 * audited by both implementations — and every page that renders it says so, and
 * prints the command that re-derives it.
 *
 * # The node always wins when it answers
 *
 * `NEXT_PUBLIC_CAIRN_NODE`, else same-origin — because a node serves this very
 * page at `/ui/`, so the node that served you the HTML is the one to ask. The
 * snapshot appears only when that fetch fails, and never silently: callers get
 * `live: false` and are expected to show it.
 */

import { readCheckpoint } from "./checkpoint";
import snapshot from "./snapshot.json";
import { ShapeMismatch, expectFields } from "./shape";

export type Frontier = {
  claim_id: string;
  holder: string;
  score: number;
  must_cite: string;
  paid_cumulative: number;
  pool_remaining: number;
};

export type Objective = {
  id: string;
  goal: string;
  statement: string;
  reward: number;
  funder: string;
  verifier_kind: string;
  settled: boolean;
  frontier?: Frontier;
  record?: {
    ratchet?: {
      baseline: number;
      target: number;
      direction: string;
      min_improvement: number;
      reward: number;
    } | null;
    verifier?: Record<string, unknown>;
    created_at?: string;
  };
};

/** What `GET /chain` said about the snapshot log. Same field names as the
 *  endpoint, so the live and fallback values are the same shape and a page
 *  cannot render one where it meant the other. */
export type ChainFacts = {
  head: string;
  links: number;
  /** Ledger entry count — the unit a checkpoint's `height` is in. */
  height: number;
  ledger_head: string;
};

/** `launch/checkpoint.json`'s signed body, plus the key that signed it. */
export type CheckpointFacts = {
  head: string;
  height: number;
  root: string;
  issued_at: string;
  public_key: string;
};

export type Snapshot = {
  source: string;
  /** Flattened copies of the two objects below. Kept because the snapshot
   *  is a committed file that more than one change regenerates, and a
   *  removed key is a conflict for no gain. The site reads the nested ones. */
  merkle_root: string;
  head: string;
  height: number;
  issued_at: string;
  links: number;
  chain: ChainFacts;
  checkpoint: CheckpointFacts;
  objectives: Objective[];
};

export const SNAPSHOT = snapshot as unknown as Snapshot;

/** The node this site reads. Same-origin unless told otherwise. */
export const NODE_URL = process.env.NEXT_PUBLIC_CAIRN_NODE ?? "";

/**
 * The repository, which is the only external thing this site links to.
 *
 * One constant rather than the string typed into each page: the site links out
 * dozens of times, and a moved repository should be one edit rather than a
 * grep that misses two.
 */
export const REPO = "https://github.com/aburan28/distributed-researcher";

/**
 * A path inside the repository, on the default branch.
 *
 * Links rather than copies, and that is the point: every prose page here could
 * restate what `docs/economics.md` says, and the restatement would be wrong
 * within a month. The site is a way in, and the repository stays the source.
 *
 * A trailing slash means a directory, which GitHub serves under `tree` and not
 * `blob`.
 */
export function repoLink(path: string): string {
  return `${REPO}/${path.endsWith("/") ? "tree" : "blob"}/main/${path}`;
}

export type Feed = {
  objectives: Objective[];
  /** False when this came from the bundled log rather than a node. */
  live: boolean;
  /** Where it came from, for a line the reader can check. */
  origin: string;
  /** Why the page is showing the snapshot when a node *did* answer — the
   *  answer was not the shape this page reads. Rendered, because a node and
   *  a page that disagree about a field name is a bug, and a fallback that
   *  hid it would be the incident `units` documents, again. */
  warning?: string;
};

/**
 * One value and where it came from.
 *
 * The landing page shows numbers from three endpoints, and each falls back
 * on its own: a node that answers `/objectives` and not `/checkpoint` is an
 * ordinary node that nobody has run `cairn checkpoint` on. So provenance is
 * per value rather than per page, and every stat says which it is. Before
 * this, one sentence claimed the numbers came from the live node while the
 * merkle root beside it was always the snapshot's.
 */
export type Sourced<T> = {
  value: T;
  live: boolean;
  origin: string;
  /** A reason worth showing beside the value — the node answered but had
   *  no checkpoint, or answered in a shape this page does not read. */
  note?: string;
};

/** The label every stat carries. One function so the wording cannot drift
 *  between the places it is rendered. */
export function provenance(sourced: { live: boolean; origin: string }): string {
  return sourced.live ? `live from ${sourced.origin}` : `from ${sourced.origin} snapshot`;
}

/**
 * Objectives from a node, or from the settled log if none answers.
 *
 * Never throws: a landing page that renders an error where its content should
 * be is worse than one that renders real, older, clearly-labelled content.
 */
export async function loadObjectives(base: string = NODE_URL): Promise<Feed> {
  try {
    const response = await fetch(`${base}/objectives`, { cache: "no-store" });
    if (!response.ok) throw new Error(String(response.status));
    const body = expectFields<{ objectives: Objective[] }>(
      await response.json(),
      ["objectives"],
      `${base || "this node"}/objectives`,
    );
    const objectives = body.objectives;
    // A node with an empty log is a real answer, but showing a visitor nothing
    // when a settled log ships in the repository helps no one.
    if (objectives.length === 0) {
      return { objectives: SNAPSHOT.objectives, live: false, origin: SNAPSHOT.source };
    }
    return { objectives, live: true, origin: base || "this node" };
  } catch (cause) {
    return {
      objectives: SNAPSHOT.objectives,
      live: false,
      origin: SNAPSHOT.source,
      warning: cause instanceof ShapeMismatch ? cause.message : undefined,
    };
  }
}

/**
 * The chain's link count and the ledger's height, from a node or the snapshot.
 *
 * Never throws, like `loadObjectives`, and for the same reason. A shape
 * mismatch is the one failure that is *not* "no node answered", so it comes
 * back as a `note` beside the fallback rather than disappearing into it.
 */
export async function loadChain(base: string = NODE_URL): Promise<Sourced<ChainFacts>> {
  const fallback = { value: SNAPSHOT.chain, live: false, origin: SNAPSHOT.source };
  try {
    const response = await fetch(`${base}/chain`, { cache: "no-store" });
    if (!response.ok) throw new Error(String(response.status));
    const body = expectFields<ChainFacts>(
      await response.json(),
      ["head", "links", "height", "ledger_head"],
      `${base || "this node"}/chain`,
    );
    return {
      value: {
        head: body.head,
        links: body.links,
        height: body.height,
        ledger_head: body.ledger_head,
      },
      live: true,
      origin: base || "this node",
    };
  } catch (cause) {
    return cause instanceof ShapeMismatch ? { ...fallback, note: cause.message } : fallback;
  }
}

/**
 * The signed checkpoint, from a node or the snapshot.
 *
 * A node that answers its own 404 here is a node nobody has run
 * `cairn checkpoint` on, which is ordinary and is said so in the `note` — the
 * snapshot's checkpoint is shown in its place, labelled as the snapshot's,
 * because a live node's root and a bundled log's signature must not sit in
 * one panel as if they were one fact.
 *
 * Only the node's own 404 earns that sentence. The public site is built with
 * no node URL, so this fetch goes to GitHub Pages, which 404s with an HTML
 * page — and for a while that rendered "this node publishes no checkpoint"
 * on a site with no node behind it. `readCheckpoint` tells the two apart by
 * the body, and a 404 that is not the node's falls back as silently as
 * `/objectives` and `/chain` do.
 */
export async function loadCheckpoint(
  base: string = NODE_URL,
): Promise<Sourced<CheckpointFacts>> {
  const fallback = { value: SNAPSHOT.checkpoint, live: false, origin: SNAPSHOT.source };
  const answer = await readCheckpoint(base);
  switch (answer.kind) {
    case "signed": {
      const { checkpoint, public_key } = answer.value;
      return {
        value: {
          head: checkpoint.head,
          height: checkpoint.height,
          root: checkpoint.root,
          issued_at: checkpoint.issued_at,
          public_key,
        },
        live: true,
        origin: base || "this node",
      };
    }
    case "unsigned":
      return { ...fallback, note: `${base || "this node"} publishes no checkpoint` };
    case "unreadable":
      return { ...fallback, note: answer.message };
    case "no-node":
      return fallback;
  }
}

/**
 * One objective by id, from the same source.
 *
 * The listing omits the full record -- deliberately, since a statement is long
 * and a listing is a listing -- so a live read fetches `/objective/{id}` as
 * well. Without it a challenge page pointed at a real node showed no ratchet at
 * all, because `record.ratchet` is where the baseline and target live. The
 * snapshot already carries the record, so this only ever runs on the live path.
 */
export async function loadObjective(
  id: string,
  base: string = NODE_URL,
): Promise<{ objective: Objective | null; live: boolean; origin: string }> {
  const feed = await loadObjectives(base);
  const found = feed.objectives.find((o) => o.id === id) ?? null;
  if (found && feed.live && !found.record) {
    try {
      // Not `encodeURIComponent`: the id is `sha256:<hex>`, the colon is legal
      // in a path segment, and the server matches on the raw remainder after
      // `/objective/` without decoding. Encoding it produced a 404 and a
      // challenge page that silently fell back to single-bounty wording.
      const response = await fetch(`${base}/objective/${id}`, { cache: "no-store" });
      if (response.ok) {
        const body = (await response.json()) as { record?: Objective["record"] };
        if (body.record) found.record = body.record;
      }
    } catch {
      // A listing without its record still renders: the page falls back to the
      // single-bounty wording, which is wrong-ish rather than blank.
    }
  }
  return { objective: found, live: feed.live, origin: feed.origin };
}

/** `sha256:abcd1234…` — enough to compare by eye, short enough to sit in a row. */
export function short(id: string): string {
  const bare = id.startsWith("sha256:") ? id.slice(7) : id;
  return bare.length <= 12 ? bare : `${bare.slice(0, 8)}…${bare.slice(-4)}`;
}

/** Thousands separators. The unit of account is an integer and stays one.
 *
 *  Tolerates `undefined` because every value it formats arrives from a node
 *  over HTTP, and a field this page did not expect should leave a dash in one
 *  cell rather than replace the whole page with a client-side exception. That
 *  is not hypothetical: this rendered `remaining` for a while, and the node
 *  calls it `pool_remaining`. */
export function units(n: number | undefined | null): string {
  return typeof n === "number" ? n.toLocaleString("en-US") : "—";
}

/**
 * How far along the ratchet a score is, as a percentage.
 *
 * Display only. The payout is integer arithmetic in `frontier.rs` and this is
 * not a second opinion about it — it is a bar on a page.
 */
export function progress(
  score: number,
  ratchet: { baseline: number; target: number; direction: string },
): number {
  const span =
    ratchet.direction === "minimize"
      ? ratchet.baseline - ratchet.target
      : ratchet.target - ratchet.baseline;
  if (span <= 0) return 0;
  const moved =
    ratchet.direction === "minimize" ? ratchet.baseline - score : score - ratchet.baseline;
  return Math.max(0, Math.min(100, Math.round((moved / span) * 100)));
}
