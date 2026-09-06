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
import { loadSeeds, readableEndpoints } from "./seeds";
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

/**
 * A certificate's one payment: who was paid, how much, for which claim.
 *
 * `null` for a ratchet, whose payouts are many and are carried per move by
 * `frontier.paid_cumulative` -- see `lifecycle_fields` in `src/serve.rs`.
 */
export type Settlement = {
  claim_id: string;
  submitter: string;
  reward: number;
};

export type Objective = {
  id: string;
  goal: string;
  statement: string;
  reward: number;
  funder: string;
  verifier_kind: string;
  /**
   * No longer payable. The node decides this, and it is the only thing that
   * does: for a certificate, a settlement exists; for a ratchet, the frontier
   * is at the target or the span left is too small for a move to settle. A
   * ratchet that has paid once is *not* settled, which is why pages must not
   * read a `settlement` record as closure.
   */
  settled: boolean;
  /** `!settled`, published by the node rather than negated here. */
  open: boolean;
  settlement: Settlement | null;
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

/** The build-time override, if one was set. Empty otherwise, and empty is a
 *  real answer — see `resolveNode` below, which is what decides what a page
 *  actually reads. Still exported because every page uses it as the initial
 *  value of its URL box, before resolution has finished. */
export const NODE_URL = process.env.NEXT_PUBLIC_CAIRN_NODE ?? "";

/**
 * Which node to read, decided once per page load.
 *
 * # The order, and why each step is where it is
 *
 * 1. **`NEXT_PUBLIC_CAIRN_NODE`**, if the build set one. An explicit answer
 *    ends the question and costs no requests — this is the operator who built
 *    the site pointed at their own node, and second-guessing them by probing
 *    would be both slower and wrong.
 * 2. **Same origin.** The daemon embeds this export and serves it at `/ui/`,
 *    so the node that served you the HTML is the node to ask, and no seed list
 *    is consulted at all in the case this app was written for.
 * 3. **The published seed list.** Only reached when nobody local answered,
 *    which on `aburan28.github.io` is always. This is the case that used to
 *    fall straight through to the bundled log: the site said "from launch
 *    snapshot" while real nodes were running and reachable.
 * 4. **Nothing**, and `""` is deliberately what that returns. Every loader
 *    below then makes a relative request that fails, and falls back to the
 *    snapshot exactly as it did before this function existed — labelled, as
 *    it always was.
 *
 * # Why a probe rather than trying each endpoint per request
 *
 * A page makes three or four independent requests and each already has its own
 * fallback. Resolving per request would mean each one re-walking the seed list
 * on its own, so a page could end up rendering `/objectives` from one node and
 * `/chain` from another with one provenance line covering both. One `/health`
 * per candidate, once, keeps a page reading one node.
 *
 * Memoised for the life of the page, so the six pages' worth of loaders that
 * call it share one answer and one round of probing. Not cached beyond that:
 * a reload should re-ask, because the point of the list is that seeds move.
 */
let resolving: Promise<string> | null = null;

export function resolveNode(): Promise<string> {
  resolving ??= discoverNode();
  return resolving;
}

/** For tests, and for a page that wants a fresh look after an explicit retry. */
export function forgetResolvedNode(): void {
  resolving = null;
}

/**
 * Does a node answer here? `GET /health` and nothing heavier.
 *
 * `/health` is `text/plain` `ok`, so a 200 carrying an HTML error page — which
 * is what GitHub Pages serves for a path it does not have — is not mistaken for
 * a node. That is not hypothetical for this site: `loadCheckpoint` already
 * carries a comment about Pages' HTML 404 being read as a node's own answer.
 */
async function answers(base: string): Promise<boolean> {
  try {
    const response = await fetch(`${base}/health`, { cache: "no-store" });
    if (!response.ok) return false;
    return (await response.text()).trim() === "ok";
  } catch {
    return false;
  }
}

async function discoverNode(): Promise<string> {
  if (NODE_URL) return NODE_URL;
  if (await answers("")) return "";
  const protocol = typeof window === "undefined" ? "https:" : window.location.protocol;
  for (const seed of readableEndpoints(await loadSeeds(), protocol)) {
    if (await answers(seed)) return seed;
  }
  return "";
}

/**
 * The repository, which is the only external thing this site links to.
 *
 * One constant rather than the string typed into each page: the site links out
 * dozens of times, and a moved repository should be one edit rather than a
 * grep that misses two.
 */
export const REPO = "https://github.com/aburan28/cairn";

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
export async function loadObjectives(base?: string): Promise<Feed> {
  const at = base ?? (await resolveNode());
  try {
    const response = await fetch(`${at}/objectives`, { cache: "no-store" });
    if (!response.ok) throw new Error(String(response.status));
    const body = expectFields<{ objectives: Objective[] }>(
      await response.json(),
      ["objectives"],
      `${at || "this node"}/objectives`,
    );
    const objectives = body.objectives;
    // A node with an empty log is a real answer, but showing a visitor nothing
    // when a settled log ships in the repository helps no one.
    if (objectives.length === 0) {
      return { objectives: SNAPSHOT.objectives, live: false, origin: SNAPSHOT.source };
    }
    return { objectives, live: true, origin: at || "this node" };
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
export async function loadChain(base?: string): Promise<Sourced<ChainFacts>> {
  const at = base ?? (await resolveNode());
  const fallback = { value: SNAPSHOT.chain, live: false, origin: SNAPSHOT.source };
  try {
    const response = await fetch(`${at}/chain`, { cache: "no-store" });
    if (!response.ok) throw new Error(String(response.status));
    const body = expectFields<ChainFacts>(
      await response.json(),
      ["head", "links", "height", "ledger_head"],
      `${at || "this node"}/chain`,
    );
    return {
      value: {
        head: body.head,
        links: body.links,
        height: body.height,
        ledger_head: body.ledger_head,
      },
      live: true,
      origin: at || "this node",
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
export async function loadCheckpoint(base?: string): Promise<Sourced<CheckpointFacts>> {
  const at = base ?? (await resolveNode());
  const fallback = { value: SNAPSHOT.checkpoint, live: false, origin: SNAPSHOT.source };
  const answer = await readCheckpoint(at);
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
        origin: at || "this node",
      };
    }
    case "unsigned":
      return { ...fallback, note: `${at || "this node"} publishes no checkpoint` };
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
  base?: string,
): Promise<{ objective: Objective | null; live: boolean; origin: string }> {
  const at = base ?? (await resolveNode());
  const feed = await loadObjectives(at);
  const found = feed.objectives.find((o) => o.id === id) ?? null;
  if (found && feed.live && !found.record) {
    try {
      // Not `encodeURIComponent`: the id is `sha256:<hex>`, the colon is legal
      // in a path segment, and the server matches on the raw remainder after
      // `/objective/` without decoding. Encoding it produced a 404 and a
      // challenge page that silently fell back to single-bounty wording.
      const response = await fetch(`${at}/objective/${id}`, { cache: "no-store" });
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
