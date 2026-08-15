/**
 * A reader for one node's epoch chain.
 *
 * Mirrors the shape `GET /chain` returns (see `src/serve.rs::chain`). Nothing
 * here re-derives the chain — that is the node's job, and a second
 * implementation of the fold in TypeScript would be a third place for the rule
 * to drift. This only *reads*, and the one thing it does compute is whether
 * each link names the one before it, which is a property of what was served
 * rather than a re-derivation of it.
 */

export type EpochLink = {
  epoch: number;
  /** Sorted claim ids, as the link commits to them. */
  claims: string[];
  /** The previous link; empty string for the first. */
  prev: string;
  link: string;
};

export type Chain = {
  head: string;
  links: number;
  chain: EpochLink[];
  note: string;
};

/** The node this UI reads.
 *
 *  Same-origin by default, which it was not when this app could only run as a
 *  separate `next` process. The daemon now serves this build at `/ui/`, so the
 *  node answering `/chain` is the one that served the page — and an empty base
 *  makes every fetch relative, which is also what keeps it working behind an
 *  SSH tunnel or a reverse proxy on a path nobody told the build about.
 *
 *  `NEXT_PUBLIC_PROOFWORK_NODE` still overrides it, baked in at build time, for
 *  `npm run dev` against a node on another port. Neither is load-bearing: the
 *  page has a URL box, and retargeting it is the entire point of the app —
 *  comparing one node's head against a peer's. */
export const NODE_URL = process.env.NEXT_PUBLIC_PROOFWORK_NODE ?? "";

export class NodeUnreachable extends Error {}

/**
 * Fetch the chain.
 *
 * `cache: "no-store"` because a node that just settled an epoch has a
 * different chain, and a cached answer here would show a stale head — which is
 * precisely the value somebody is checking when they compare against a peer.
 */
export async function fetchChain(base: string = NODE_URL): Promise<Chain> {
  let response: Response;
  try {
    response = await fetch(`${base}/chain`, { cache: "no-store" });
  } catch (cause) {
    throw new NodeUnreachable(
      `No node answered at ${base}. Start one with \`make serve\`, or set ` +
        `NEXT_PUBLIC_PROOFWORK_NODE to where yours is listening.`,
      { cause },
    );
  }
  if (!response.ok) {
    throw new NodeUnreachable(
      `${base}/chain answered ${response.status}. A node older than the epoch ` +
        `chain has no /chain endpoint.`,
    );
  }
  return (await response.json()) as Chain;
}

/**
 * Where a chain stops being a chain.
 *
 * Returns the epoch of the first link whose `prev` is not the link before it,
 * or `null` if the chain is intact. Checked in the reader rather than assumed
 * because this is the one claim the page makes on its own behalf: the node says
 * "here is a chain", and a reader that renders it without checking is taking
 * that on faith, which is the one thing this project does not do anywhere else.
 */
export function firstBrokenLink(chain: EpochLink[]): number | null {
  let expected = "";
  for (const link of chain) {
    if (link.prev !== expected) return link.epoch;
    expected = link.link;
  }
  return null;
}

/** Short form for display. Full values stay in the DOM via `title`. */
export function short(hash: string): string {
  const bare = hash.startsWith("sha256:") ? hash.slice(7) : hash;
  return bare.length > 16 ? `${bare.slice(0, 16)}…` : bare;
}

/**
 * Epoch lengths this chain appears to have been settled under, largest first.
 *
 * An epoch is `unix_seconds / PROOFWORK_EPOCH_SECONDS`, floor-divided, and that
 * divisor is **not stored** — `src/partition.rs` derives it and says so. So a
 * chain settled at one length and then another carries epoch numbers that differ
 * by roughly the ratio of the two, and nothing in the log records why.
 *
 * This groups the epochs by order of magnitude and reports how many distinct
 * groups there are. More than one is worth showing an operator: `docs` calls
 * `PROOFWORK_EPOCH_SECONDS` a *policy* parameter, and two settings disagree
 * about which epoch a record falls in and therefore about which reveals were
 * legal. A log holding both was settled under two different rules.
 *
 * Deliberately a heuristic, and labelled as one wherever it is rendered. The
 * divisor is unrecoverable from the log, so this cannot be a derivation — it
 * notices a discontinuity and says where, which is enough to send somebody to
 * look.
 */
export function epochScales(chain: EpochLink[]): number[] {
  const scales = new Set<number>();
  for (const link of chain) {
    if (link.epoch > 0) scales.add(Math.floor(Math.log10(link.epoch)));
  }
  return [...scales].sort((a, b) => b - a);
}

/** Total claims settled across every link. */
export function totalClaims(chain: EpochLink[]): number {
  return chain.reduce((sum, link) => sum + link.claims.length, 0);
}
