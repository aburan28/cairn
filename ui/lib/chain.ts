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

/** The node this UI reads. Same-origin is useless here — the node is a
 *  separate process — so it is configuration, with the CLI default as the
 *  fallback so `npm run dev` works against `make serve` with no setup. */
export const NODE_URL =
  process.env.NEXT_PUBLIC_PROOFWORK_NODE ?? "http://127.0.0.1:8080";

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
