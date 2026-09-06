/**
 * Composing a challenge, and getting it into a node's queue.
 *
 * # The three steps, and why there are three
 *
 * 1. **Draft.** A form's values become an objective record. This is a pure
 *    function, tested, and it is the only place in the browser that decides
 *    what an objective *is*.
 * 2. **Prepare.** The node canonicalizes the draft and returns the exact bytes
 *    its funder must sign (`POST /objective/prepare`). The browser does not
 *    compute those bytes. Canonical encoding is consensus-critical and lives
 *    in two implementations that must agree; a third one here — unversioned,
 *    in a browser, unable to run `conformance/vectors.json` — is the drift
 *    AGENTS.md rules out. So the browser relays.
 * 3. **Submit.** The signed record goes to `POST /submit?kind=objective`,
 *    which queues it. **Queued is not admitted.** The operator's `cairn drain`
 *    re-decides every rule against the whole log — verifier registration,
 *    duplicate ids, ratchet coherence, the funding signature again, and
 *    whether the funder can afford the reward in the right tier. A 202 here is
 *    a receipt for a proposal and the UI must never present it as more.
 *
 * # Why submission is same-origin
 *
 * `POST` with `application/json` is not a CORS-simple request, so a browser
 * preflights it, and the node answers `OPTIONS` with a 405 carrying no
 * `access-control-allow-methods`. That is deliberate (see the comment on
 * `respond` in `src/serve.rs`): cross-origin writes would let any page make
 * its visitors' browsers fill a stranger's queue. The consequence for this app
 * is that submitting works from the reader the node serves at `/ui/` and not
 * from `npm run dev` on another port — so `reachableForWrites` exists to say
 * that plainly instead of letting a network error look like a broken node.
 */

import { NODE_URL } from "./objectives";
import { expectFields } from "./shape";

/** What the form collects. Strings throughout: it is a form. */
export type Draft = {
  goal: string;
  statement: string;
  funder: string;
  reward: string;
  verifierKind: string;
  checker: string;
  entrypoint: string;
  checkerSha256: string;
  deadline: string;
  /** Ratchet fields, used only when `verifierKind` is "evaluator". */
  useRatchet: boolean;
  baseline: string;
  target: string;
  direction: string;
  minImprovement: string;
  requireSignedSubmitter: boolean;
};

export const EMPTY_DRAFT: Draft = {
  goal: "",
  statement: "",
  funder: "",
  reward: "",
  verifierKind: "certificate",
  checker: "",
  entrypoint: "check",
  checkerSha256: "",
  deadline: "",
  useRatchet: false,
  baseline: "",
  target: "",
  direction: "maximize",
  minImprovement: "1",
  requireSignedSubmitter: false,
};

/** The verifier kinds this build can dispatch. Mirrors `verifiers::Kind::ALL`. */
export const VERIFIER_KINDS = [
  {
    kind: "certificate",
    title: "Certificate",
    blurb: "Pass or fail. One checker says yes, and the bounty settles once.",
  },
  {
    kind: "evaluator",
    title: "Evaluator",
    blurb:
      "A score. Pays along an improvement curve, so publishing early beats sitting on a result.",
  },
  {
    kind: "lean",
    title: "Lean",
    blurb: "A machine-checked proof. The checker is the Lean toolchain.",
  },
  {
    kind: "replay",
    title: "Replay",
    blurb: "Re-execute a recorded trace and compare the result.",
  },
  {
    kind: "statistical",
    title: "Statistical",
    blurb: "A sampled check with a declared confidence.",
  },
] as const;

/** Why a draft cannot be posted yet, keyed by field. Empty means it can. */
export type Problems = Partial<Record<keyof Draft, string>>;

/**
 * Local validation, ahead of the node's.
 *
 * Deliberately a *subset* of what the node enforces and never a superset: this
 * exists to catch an empty field while the funder is still typing, not to be a
 * second opinion about admissibility. The node decides, and anything this
 * misses it will still refuse.
 */
export function problems(draft: Draft): Problems {
  const found: Problems = {};
  if (!draft.goal.trim()) found.goal = "A goal names the question. It cannot be blank.";
  if (!draft.statement.trim()) {
    found.statement = "Say what a solver has to produce, and what counts as better.";
  }
  if (!draft.funder.trim()) found.funder = "Connect a wallet, or type a name.";

  const reward = Number(draft.reward);
  if (!draft.reward.trim()) found.reward = "A bounty needs an amount.";
  else if (!Number.isInteger(reward) || reward <= 0) {
    found.reward = "A whole number of units, above zero. No fractions: money here is integers.";
  }

  if (!draft.checker.trim()) found.checker = "The verifier needs a checker to pin.";
  if (!/^[0-9a-f]{64}$/.test(draft.checkerSha256.trim())) {
    found.checkerSha256 =
      "64 lowercase hex characters — the sha256 of the checker file, which is what pins it.";
  }

  if (draft.useRatchet) {
    if (draft.verifierKind !== "evaluator") {
      found.useRatchet = "Only an evaluator can ratchet; a certificate has nothing to score.";
    }
    for (const field of ["baseline", "target", "minImprovement"] as const) {
      if (!draft[field].trim() || !Number.isInteger(Number(draft[field]))) {
        found[field] = "A whole number is required.";
      }
    }
    if (Number(draft.minImprovement) <= 0) {
      found.minImprovement =
        "Above zero. This is the smallest move that pays, and it is the only " +
        "thing standing between the pool and epsilon-farming.";
    }
    if (draft.baseline.trim() && draft.target.trim() && draft.baseline === draft.target) {
      found.target = "A span of zero can never be improved across.";
    }
  }
  return found;
}

/**
 * Turn a validated draft into the objective record a node reads.
 *
 * Optional fields are *omitted* rather than nulled, which is not a style
 * choice: an objective's id covers its content, and `null` where the canonical
 * form expects absence is a different record with a different id. See the
 * module docs in `src/records.rs`.
 */
export function toRecord(draft: Draft, createdAt: string): Record<string, unknown> {
  const verifier: Record<string, unknown> = {
    kind: draft.verifierKind,
    checker: draft.checker.trim(),
    checker_sha256: draft.checkerSha256.trim(),
  };
  if (draft.entrypoint.trim()) verifier.entrypoint = draft.entrypoint.trim();

  const record: Record<string, unknown> = {
    goal: draft.goal.trim(),
    statement: draft.statement.trim(),
    verifier,
    reward: Number(draft.reward),
    funder: draft.funder.trim(),
    created_at: createdAt,
  };
  if (draft.deadline.trim()) record.deadline = draft.deadline.trim();
  if (draft.requireSignedSubmitter) record.require_signed_submitter = true;
  if (draft.useRatchet) {
    record.ratchet = {
      baseline: Number(draft.baseline),
      target: Number(draft.target),
      direction: draft.direction,
      min_improvement: Number(draft.minImprovement),
      // `post_objective` refuses a ratchet whose reward disagrees with the
      // objective's, so it is derived here rather than asked for twice and
      // then reconciled.
      reward: Number(draft.reward),
    };
  }
  return record;
}

/** What `POST /objective/prepare` answers with. */
export type Prepared = {
  /** The bytes to sign, hex. Relayed to the wallet unread. */
  payload_hex: string;
  /** The same bytes as text, so a funder can read what they are authorizing. */
  payload: string;
  digest: string;
  funder: string;
  /** False for a nickname funder, which needs no signature. */
  signature_required: boolean;
};

async function readError(response: Response): Promise<string> {
  try {
    const body = await response.json();
    if (body && typeof body.error === "string") return body.error;
  } catch {
    // A node answers JSON; anything else is a proxy or a wrong port, and the
    // status line is the more useful thing to report.
  }
  return `the node answered ${response.status}`;
}

export class SubmissionRefused extends Error {}
export class NodeUnreachableForWrites extends Error {}

/**
 * Ask the node for the exact bytes this draft's funder must sign.
 *
 * A failure to *reach* the node is reported as a different error from a
 * refusal by it, because the two want different things from the reader: one is
 * "your node is not where this page thinks it is", the other is "your record
 * is wrong, here is which field".
 */
export async function prepare(
  record: Record<string, unknown>,
  base: string = NODE_URL,
): Promise<Prepared> {
  let response: Response;
  try {
    response = await fetch(`${base}/objective/prepare`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(record),
      cache: "no-store",
    });
  } catch (cause) {
    throw new NodeUnreachableForWrites(
      `Could not reach ${base || "this origin"} to canonicalize the objective. ` +
        "Submission is same-origin only: open this page from the node itself " +
        "(`cairn run --serve 0.0.0.0:8080`, then /ui/) rather than from a dev server.",
      { cause },
    );
  }
  if (!response.ok) throw new SubmissionRefused(await readError(response));
  const body = await response.json();
  return expectFields<Prepared>(
    body,
    ["payload_hex", "payload", "digest", "funder", "signature_required"],
    "/objective/prepare",
  );
}

/** A queue receipt. Not an admission — see the module docs. */
export type Queued = { queued: string; kind: string; note: string };

export async function submit(
  record: Record<string, unknown>,
  base: string = NODE_URL,
): Promise<Queued> {
  let response: Response;
  try {
    response = await fetch(`${base}/submit?kind=objective`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(record),
      cache: "no-store",
    });
  } catch (cause) {
    throw new NodeUnreachableForWrites(
      `Could not reach ${base || "this origin"} to submit. Submission is ` +
        "same-origin only: open this page from the node itself.",
      { cause },
    );
  }
  if (!response.ok) throw new SubmissionRefused(await readError(response));
  const body = await response.json();
  return expectFields<Queued>(body, ["queued", "kind", "note"], "/submit");
}

/**
 * Is this page in a position to write to the node it reads?
 *
 * True only when the page was served from the same origin it would submit to.
 * `NODE_URL` empty means same-origin, which is the embedded `/ui/` case; a
 * configured absolute URL means a dev server pointed at a node elsewhere, and
 * that browser will preflight the POST and be refused.
 *
 * Said up front rather than discovered on submit, because a preflight failure
 * surfaces as an opaque `TypeError: Failed to fetch` that looks exactly like a
 * node being down.
 */
export function reachableForWrites(base: string = NODE_URL): boolean {
  if (!base) return true;
  if (typeof window === "undefined") return false;
  try {
    return new URL(base, window.location.href).origin === window.location.origin;
  } catch {
    return false;
  }
}

/**
 * The command that posts this objective from a terminal instead.
 *
 * The escape hatch for the two cases the page cannot serve: a funder whose key
 * lives in a file rather than a wallet, and anyone reading this from a dev
 * server that cannot write. Shown next to the form rather than hidden in docs,
 * because a page that can only sometimes do the job should say what to do the
 * rest of the time.
 */
export function postCommand(identity: boolean): string {
  return identity
    ? "cairn post objective.json --identity ~/.cairn/identity.json"
    : "cairn post objective.json";
}
