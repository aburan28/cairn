/**
 * A reader for what the operator actually signed.
 *
 * Mirrors `GET /checkpoint` (see `src/serve.rs`). This is the only thing a
 * stranger is asked to trust, and until now the UI did not show it at all —
 * which meant the reader displayed a head with no way to see whether anyone had
 * put their name to it.
 *
 * # This does not verify the signature
 *
 * Deliberately, and it is the most important thing on this page to be honest
 * about. Checking an ML-DSA signature in the browser would mean a second
 * implementation of a consensus-critical primitive, in a third language, whose
 * disagreement with the Rust one would be invisible until it mattered. The
 * repository's own rule is that `src/` and `reference/rust/` move together;
 * adding a TypeScript verifier would make that three.
 *
 * So this displays *that a signature is present and what it covers*, and points
 * at `proofwork verify --from`, which is the thing that actually checks it. A
 * reader who wants assurance runs that. A page claiming to have verified
 * something it merely rendered would be worse than one that says plainly it did
 * not.
 */

export type Checkpoint = {
  /** Ledger head the signature covers. */
  head: string;
  /** Entry count at signing time. */
  height: number;
  /** Merkle root over the whole log at that height. */
  root: string;
  /** When the operator signed — self-reported, like every timestamp here. */
  issued_at: string;
};

export type CheckpointResponse = {
  checkpoint: Checkpoint;
  public_key: string;
  signature?: string;
};

/** Same-origin by default; see the note in `chain.ts`. The daemon serves
 *  this build at /ui/, so relative fetches reach the node that served it. */
export const NODE_URL = process.env.NEXT_PUBLIC_PROOFWORK_NODE ?? "";

/**
 * Fetch the checkpoint, or `null` when the node has none.
 *
 * A node that has never been checkpointed is an ordinary state, not an error —
 * `proofwork checkpoint` is a thing an operator chooses to run — so this
 * resolves to `null` rather than throwing and making the caller special-case a
 * message.
 */
export async function fetchCheckpoint(
  base: string = NODE_URL,
): Promise<CheckpointResponse | null> {
  let response: Response;
  try {
    response = await fetch(`${base}/checkpoint`, { cache: "no-store" });
  } catch {
    return null;
  }
  if (response.status === 404) return null;
  if (!response.ok) return null;
  try {
    const body = (await response.json()) as CheckpointResponse;
    return body.checkpoint ? body : null;
  } catch {
    return null;
  }
}

/**
 * Whether the checkpoint's head is the chain head the node also served.
 *
 * The one arithmetic-free check worth making here, and it can legitimately
 * disagree: a checkpoint is a signature over a *prefix*, so an operator who
 * signed and then kept appending has a checkpoint behind their head. That is
 * normal and is why this returns a three-way answer rather than a boolean —
 * "behind" is expected, "unrelated" is not.
 */
export function coversHead(checkpoint: Checkpoint, height: number): "at" | "behind" {
  return checkpoint.height >= height ? "at" : "behind";
}
