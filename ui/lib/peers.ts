/**
 * A reader for one node's address book.
 *
 * Mirrors `GET /peers` (see `src/serve.rs::peers`). The name is the one thing
 * to be careful about: these are peers this node has been *told about*, not
 * peers it is talking to. A `peer` record is an announcement that some identity
 * answers at some address, it is append-only like everything else in the log,
 * and nothing retracts it — so an entry here may name a machine that has been
 * gone for months.
 *
 * Live session state is not available to this UI at all. It lives inside
 * `cairn-p2p`, which serves no HTTP, and `cairn-serve` only ever reads
 * a log file. Presenting this as "connected" would be inventing a fact the
 * network never published.
 */

import { expectFields } from "./shape";

export type Peer = {
  /** ed25519 identity — this *is* the submitter name. */
  identity: string;
  /** 32-byte id of the McEliece transport key, not the key (261,120 bytes). */
  transport: string;
  addr: string;
  /** Announcement sequence: a peer that moves appends a higher one. */
  seq: number;
  created_at: string;
};

export type PeersResponse = { peers: Peer[]; note: string };

/** Same-origin by default; see the note in `chain.ts`. The daemon serves
 *  this build at /ui/, so relative fetches reach the node that served it. */
export const NODE_URL = process.env.NEXT_PUBLIC_CAIRN_NODE ?? "";

export class NodeUnreachable extends Error {}

export async function fetchPeers(
  base: string = NODE_URL,
): Promise<PeersResponse> {
  let response: Response;
  try {
    response = await fetch(`${base}/peers`, { cache: "no-store" });
  } catch (cause) {
    throw new NodeUnreachable(
      `No node answered at ${base}. Start one with \`make serve\`, or set ` +
        `NEXT_PUBLIC_CAIRN_NODE to where yours is listening.`,
      { cause },
    );
  }
  if (response.status === 404) {
    throw new Error(
      `${base}/peers answered 404. That route is newer than the node you are ` +
        `reading — this page needs a node built after \`/peers\` was added.`,
    );
  }
  if (!response.ok) {
    throw new Error(`${base}/peers answered ${response.status}.`);
  }
  const body = expectFields<PeersResponse>(
    await response.json(),
    ["peers"],
    `${base}/peers`,
  );
  return { peers: body.peers, note: body.note ?? "" };
}

/** A hash or key, short enough to scan a column of them. */
export function short(value: string): string {
  const bare = value.startsWith("sha256:") ? value.slice(7) : value;
  return bare.length <= 12 ? bare : `${bare.slice(0, 8)}…${bare.slice(-4)}`;
}

/**
 * How long ago a peer said this, in whole units, or null if unparseable.
 *
 * Rendered *beside* the timestamp rather than instead of it. The age is the
 * useful number for a reader deciding whether an address is worth dialling, and
 * it is computed from `created_at` — which the peer chose. `src/time.rs` calls
 * these advisory, so a peer that wants to look freshly announced can simply say
 * so, and a reader should be able to see the raw claim it was derived from.
 */
export function age(created_at: string): string | null {
  const then = Date.parse(created_at);
  if (Number.isNaN(then)) return null;
  const seconds = Math.floor((Date.now() - then) / 1000);
  if (seconds < 0) return "in the future";
  if (seconds < 90) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 90) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}
