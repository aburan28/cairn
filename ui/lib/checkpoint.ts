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
 * at `cairn verify --from`, which is the thing that actually checks it. A
 * reader who wants assurance runs that. A page claiming to have verified
 * something it merely rendered would be worse than one that says plainly it did
 * not.
 */

import { ShapeMismatch, expectFields } from "./shape";

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
  /** The ML-DSA verifying key, hex. Rendered, because a signature nobody can
   *  see the signer of is a green tick and nothing more: the reader has to be
   *  able to compare this against the key they were given out of band. */
  public_key: string;
  signature?: string;
};

/** Same-origin by default; see the note in `chain.ts`. The daemon serves
 *  this build at /ui/, so relative fetches reach the node that served it. */
export const NODE_URL = process.env.NEXT_PUBLIC_CAIRN_NODE ?? "";

/**
 * What `GET /checkpoint` turned out to be, sorted into the four things a page
 * can honestly say about it.
 *
 * Four and not two, because "no checkpoint" was hiding three different facts
 * behind one `null`, and the landing page turned one of them into a sentence
 * about a node that did not exist. With `NEXT_PUBLIC_CAIRN_NODE` unset --
 * which is how `pages.yml` builds the public site, and what `npm run dev`
 * with no node is -- every fetch is relative, and on GitHub Pages or the
 * Next dev server `/checkpoint` is answered by the static host: a 404 with
 * an HTML body. `/objectives` and `/chain` 404 there too and fell back to
 * the snapshot silently, while this one said "this node publishes no
 * checkpoint" on a site where there is no node at all.
 *
 * - `signed`: a checkpoint, with the key that signed it.
 * - `unsigned`: the node's own 404 -- `json_error` in `src/serve.rs` writes
 *   `{"error": "…checkpoint…"}` -- meaning nobody has run `cairn checkpoint`
 *   on it. Ordinary, and worth a sentence.
 * - `no-node`: nothing answered, or a 404 that is not the node's. Nothing
 *   here is a node, so there is nothing to say about one.
 * - `unreadable`: something answered and it was not a checkpoint -- a 5xx, a
 *   200 that is not JSON, a 200 in the wrong shape. A node that is reachable
 *   and answers wrongly is a bug on one side of the seam, and the page
 *   reports it rather than folding it into either silence above.
 */
export type CheckpointAnswer =
  | { kind: "signed"; value: CheckpointResponse }
  | { kind: "unsigned"; reason: string }
  | { kind: "no-node" }
  | { kind: "unreadable"; message: string };

/**
 * Sort one HTTP answer to `/checkpoint` into a `CheckpointAnswer`.
 *
 * Pure -- a status and a body text in, a classification out -- so the test
 * can feed it a static host's 404 page beside the node's JSON 404 and pin
 * that only the second is allowed to say anything about a node.
 *
 * A 404 counts as the node's only if its body is `{"error": <string>}` and
 * the string names a checkpoint. The shape alone would accept any JSON API
 * at this origin that answers `{"error": "not found"}`, which is a 404 from
 * something that is not a node; the word alone would accept an HTML 404
 * page that happens to contain it.
 */
export function classifyCheckpoint(
  status: number,
  body: string,
  what: string,
): CheckpointAnswer {
  if (status === 404) {
    const error = nodeError(body);
    return error !== null && /checkpoint/i.test(error)
      ? { kind: "unsigned", reason: error }
      : { kind: "no-node" };
  }
  if (status < 200 || status >= 300) {
    return { kind: "unreadable", message: `${what} answered ${status}.` };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return {
      kind: "unreadable",
      message: `${what} answered ${status} with a body that is not JSON.`,
    };
  }
  // A 200 that is not a checkpoint is not "no checkpoint"; it is a node and a
  // page that disagree about the shape, and silence here would hide that
  // behind what an unsigned node gets.
  try {
    const signed = expectFields<CheckpointResponse>(parsed, ["checkpoint", "public_key"], what);
    expectFields<Checkpoint>(signed.checkpoint, ["height", "head", "root", "issued_at"], what);
    return { kind: "signed", value: signed };
  } catch (cause) {
    if (cause instanceof ShapeMismatch) return { kind: "unreadable", message: cause.message };
    throw cause;
  }
}

/** The message in a `{"error": "…"}` body, or `null` when the body is not one. */
function nodeError(body: string): string | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  const error = (parsed as Record<string, unknown>).error;
  return typeof error === "string" ? error : null;
}

/**
 * Fetch and classify the checkpoint.
 *
 * Never throws: every outcome, "nothing answered" included, is one of the four
 * kinds above, so a page chooses what to say per kind rather than catching an
 * error and guessing which of them it was.
 */
export async function readCheckpoint(base: string = NODE_URL): Promise<CheckpointAnswer> {
  let status: number;
  let body: string;
  try {
    const response = await fetch(`${base}/checkpoint`, { cache: "no-store" });
    status = response.status;
    body = await response.text();
  } catch {
    return { kind: "no-node" };
  }
  return classifyCheckpoint(status, body, `${base || "this node"}/checkpoint`);
}

/**
 * Where the checkpoint's signed height stands against the ledger the node
 * is serving now.
 *
 * `ledgerHeight` is `Chain.height` from `/chain` — the entry count — and not
 * `Chain.links`. The two were compared for a while, and since a log always
 * holds at least as many entries as batches the answer was "at" for every
 * node that ever ran; a checkpoint could not be seen to fall behind.
 *
 * The one arithmetic-free check worth making here, and it can legitimately
 * disagree: a checkpoint is a signature over a *prefix*, so an operator who
 * signed and then kept appending has a checkpoint behind their head. That is
 * normal and is why this returns a three-way answer rather than a boolean —
 * "behind" is expected, "ahead" is not: it means the checkpoint covers more
 * entries than the node now serves, so either the log was truncated or the
 * checkpoint was signed over a different one.
 */
export function coversHead(
  checkpoint: Checkpoint,
  ledgerHeight: number,
): "at" | "behind" | "ahead" {
  if (checkpoint.height === ledgerHeight) return "at";
  return checkpoint.height < ledgerHeight ? "behind" : "ahead";
}
