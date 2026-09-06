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
 *
 * # The verifier spec is per kind, and the published schema does not say so
 *
 * `spec/objective.schema.json` requires only `verifier.kind`; every other
 * field is checked by the verifier itself, which answers INVALID_SPEC to a
 * malformed one *after* the objective is already funded and in the log. So
 * the shape has to be right at composition time, and this module is where the
 * per-kind shape lives, mirrored from `src/verifiers/mod.rs`:
 *
 * - `certificate`: `checker`, `checker_sha256`, `entrypoint`
 * - `evaluator`: `evaluator`, `evaluator_sha256`, `entrypoint`, `threshold`,
 *   `direction`
 * - `statistical`: `statistic: {path, sha256}`, `entrypoint`, `threshold`,
 *   `direction`
 * - `lean`: `statement`, optional `preamble` and `timeout_seconds`
 * - `replay`: `command` (argv), `reproducible_fields`, optional `cwd`
 */

import { NODE_URL } from "./objectives";
import { expectFields } from "./shape";

/** What the form collects. Strings throughout: it is a form. */
export type Draft = {
  goal: string;
  statement: string;
  funder: string;
  reward: string;
  deadline: string;
  verifierKind: string;
  /**
   * The pinned program, for the kinds that have one. Its record field is
   * `checker`, `evaluator` or `statistic.path` depending on the kind; the form
   * asks once and `toRecord` spells it.
   */
  program: string;
  programSha256: string;
  entrypoint: string;
  /** Scored kinds only: the score at which a candidate passes. */
  threshold: string;
  /** Scored kinds and the ratchet: which way is better. One answer for both,
   *  because a ratchet that climbed while its evaluator minimised would pay
   *  for getting worse. */
  direction: string;
  /** Lean only. */
  leanStatement: string;
  leanPreamble: string;
  timeoutSeconds: string;
  /** Replay only. `replayCommand` is one argv element per line. */
  replayCommand: string;
  replayFields: string;
  replayCwd: string;
  /** Ratchet fields, used only when `verifierKind` is "evaluator". */
  useRatchet: boolean;
  baseline: string;
  target: string;
  minImprovement: string;
  requireSignedSubmitter: boolean;
  /**
   * JSON text for the optional `artifact_schema`. Carried as text rather than
   * modelled, because it is documentation the funder writes freely and the
   * only thing this form can usefully do is keep it byte-for-byte.
   */
  artifactSchema: string;
  /**
   * JSON text for any verifier fields this form has no control for —
   * `stepper`, `timeout_seconds` on a certificate, `seed`. Merged into the
   * verifier so a loaded `objective.json` round-trips instead of silently
   * losing the fields that made it that objective.
   */
  verifierExtras: string;
};

export const EMPTY_DRAFT: Draft = {
  goal: "",
  statement: "",
  funder: "",
  reward: "",
  deadline: "",
  verifierKind: "certificate",
  program: "",
  programSha256: "",
  entrypoint: "check",
  threshold: "",
  direction: "maximize",
  leanStatement: "",
  leanPreamble: "",
  timeoutSeconds: "",
  replayCommand: "",
  replayFields: "",
  replayCwd: "",
  useRatchet: false,
  baseline: "",
  target: "",
  minImprovement: "1",
  requireSignedSubmitter: false,
  artifactSchema: "",
  verifierExtras: "",
};

/** The verifier kinds this build can dispatch. Mirrors `verifiers::Kind::ALL`. */
export const VERIFIER_KINDS = [
  {
    kind: "certificate",
    title: "Certificate",
    blurb: "Pass or fail. One checker says yes, and the bounty settles once.",
    program: "checker",
  },
  {
    kind: "evaluator",
    title: "Evaluator",
    blurb:
      "A score. Pays along an improvement curve, so publishing early beats sitting on a result.",
    program: "evaluator",
  },
  {
    kind: "lean",
    title: "Lean",
    blurb: "A machine-checked proof. The checker is the Lean toolchain.",
    program: null,
  },
  {
    kind: "replay",
    title: "Replay",
    blurb: "Re-run a command in a jail and compare the fields it declares reproducible.",
    program: null,
  },
  {
    kind: "statistical",
    title: "Statistical",
    blurb: "A sampled check with a declared threshold and seed.",
    program: "statistic",
  },
] as const;

export type KindInfo = (typeof VERIFIER_KINDS)[number];

export function kindInfo(kind: string): KindInfo {
  return VERIFIER_KINDS.find((k) => k.kind === kind) ?? VERIFIER_KINDS[0];
}

/** Does this kind produce a score, and therefore take a threshold and a direction? */
export function isScored(kind: string): boolean {
  return kind === "evaluator" || kind === "statistical";
}

/** Why a draft cannot be posted yet, keyed by field. Empty means it can. */
export type Problems = Partial<Record<keyof Draft, string>>;

const SHA256 = /^[0-9a-f]{64}$/;

function parseJsonText(text: string): unknown | undefined {
  if (!text.trim()) return undefined;
  return JSON.parse(text);
}

function lines(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

function commaList(text: string): string[] {
  return text
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

/**
 * Local validation, ahead of the node's.
 *
 * Deliberately a *subset* of what the node enforces and never a superset: this
 * exists to catch an empty field while the funder is still typing, not to be a
 * second opinion about admissibility. The node decides, and anything this
 * misses it will still refuse — except the per-kind verifier shape, which the
 * node checks only when a verdict is first needed, and which this therefore
 * has to get right on its own.
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

  const kind = draft.verifierKind;
  const info = kindInfo(kind);
  if (info.program) {
    if (!draft.program.trim()) found.program = `The verifier needs a ${info.program} to pin.`;
    if (!SHA256.test(draft.programSha256.trim())) {
      found.programSha256 =
        "64 lowercase hex characters — the sha256 of the file, which is what pins it.";
    }
    if (!draft.entrypoint.trim()) found.entrypoint = "The function the verifier calls.";
  }
  if (isScored(kind)) {
    if (!draft.threshold.trim() || Number.isNaN(Number(draft.threshold))) {
      found.threshold = "The score at which a candidate passes. A number.";
    }
  }
  if (kind === "lean") {
    if (!draft.leanStatement.trim()) {
      found.leanStatement = "The theorem to prove, as Lean source.";
    }
    if (draft.timeoutSeconds.trim() && !(Number(draft.timeoutSeconds) > 0)) {
      found.timeoutSeconds = "A positive number of seconds, or blank for the default.";
    }
  }
  if (kind === "replay") {
    if (lines(draft.replayCommand).length === 0) {
      found.replayCommand = "The command to re-run, one argument per line.";
    }
    if (commaList(draft.replayFields).length === 0) {
      found.replayFields =
        "At least one field. An objective that declares nothing reproducible has not " +
        "said what reproducing it would mean.";
    }
  }

  if (draft.useRatchet) {
    if (kind !== "evaluator") {
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

  for (const field of ["artifactSchema", "verifierExtras"] as const) {
    try {
      const parsed = parseJsonText(draft[field]);
      if (
        parsed !== undefined &&
        (typeof parsed !== "object" || parsed === null || Array.isArray(parsed))
      ) {
        found[field] = "A JSON object, or blank.";
      }
    } catch {
      found[field] = "Not valid JSON.";
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
  const kind = draft.verifierKind;
  const info = kindInfo(kind);
  const verifier: Record<string, unknown> = { kind };

  // Extras first, so a field the form *does* control overwrites a stale copy
  // of it in the loaded extras rather than the other way round.
  const extras = parseJsonText(draft.verifierExtras);
  if (extras && typeof extras === "object") Object.assign(verifier, extras);

  if (info.program === "statistic") {
    verifier.statistic = { path: draft.program.trim(), sha256: draft.programSha256.trim() };
  } else if (info.program) {
    verifier[info.program] = draft.program.trim();
    verifier[`${info.program}_sha256`] = draft.programSha256.trim();
  }
  if (info.program) verifier.entrypoint = draft.entrypoint.trim();
  if (isScored(kind)) {
    verifier.threshold = Number(draft.threshold);
    verifier.direction = draft.direction;
  }
  if (kind === "lean") {
    verifier.statement = draft.leanStatement;
    if (draft.leanPreamble.trim()) verifier.preamble = draft.leanPreamble;
    if (draft.timeoutSeconds.trim()) verifier.timeout_seconds = Number(draft.timeoutSeconds);
  }
  if (kind === "replay") {
    verifier.command = lines(draft.replayCommand);
    verifier.reproducible_fields = commaList(draft.replayFields);
    if (draft.replayCwd.trim()) verifier.cwd = draft.replayCwd.trim();
  }

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
  const schema = parseJsonText(draft.artifactSchema);
  if (schema !== undefined) record.artifact_schema = schema;
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

/** What loading an `objective.json` produced, and what it could not carry. */
export type Loaded = {
  draft: Draft;
  /** Top-level fields the form has no control for. Named so the funder knows
   *  the loaded record and the posted one will differ, rather than finding
   *  out from an id that does not match. */
  dropped: string[];
};

/**
 * The inverse of `toRecord`, for a file `cairn scaffold` wrote.
 *
 * The point is the checker hash. It is the one field a person retypes wrong,
 * and it is the pin — so the honest source for it is the file the scaffold
 * already computed it into, not a text box. Everything the form models is
 * lifted out; verifier fields it does not model go into `verifierExtras`
 * verbatim so they survive the round trip; top-level fields it cannot carry
 * (`funding_signature`, a confidentiality class) are reported.
 */
export function fromRecord(value: unknown): Loaded {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("an objective is a JSON object");
  }
  const record = value as Record<string, unknown>;
  const verifier =
    typeof record.verifier === "object" && record.verifier !== null
      ? (record.verifier as Record<string, unknown>)
      : {};
  const kind = str(verifier.kind) || "certificate";
  const info = kindInfo(kind);
  const draft: Draft = { ...EMPTY_DRAFT, verifierKind: kind };

  draft.goal = str(record.goal);
  draft.statement = str(record.statement);
  draft.funder = str(record.funder);
  draft.reward = num(record.reward);
  draft.deadline = str(record.deadline);
  draft.requireSignedSubmitter = record.require_signed_submitter === true;
  if (record.artifact_schema !== undefined && record.artifact_schema !== null) {
    draft.artifactSchema = JSON.stringify(record.artifact_schema, null, 2);
  }

  const taken = new Set<string>(["kind"]);
  if (info.program === "statistic") {
    const statistic =
      typeof verifier.statistic === "object" && verifier.statistic !== null
        ? (verifier.statistic as Record<string, unknown>)
        : {};
    draft.program = str(statistic.path);
    draft.programSha256 = str(statistic.sha256);
    taken.add("statistic");
  } else if (info.program) {
    draft.program = str(verifier[info.program]);
    draft.programSha256 = str(verifier[`${info.program}_sha256`]);
    taken.add(info.program).add(`${info.program}_sha256`);
  }
  if (info.program) {
    draft.entrypoint = str(verifier.entrypoint) || EMPTY_DRAFT.entrypoint;
    taken.add("entrypoint");
  }
  if (isScored(kind)) {
    draft.threshold = num(verifier.threshold);
    draft.direction = str(verifier.direction) || EMPTY_DRAFT.direction;
    taken.add("threshold").add("direction");
  }
  if (kind === "lean") {
    draft.leanStatement = str(verifier.statement);
    draft.leanPreamble = str(verifier.preamble);
    draft.timeoutSeconds = num(verifier.timeout_seconds);
    taken.add("statement").add("preamble").add("timeout_seconds");
  }
  if (kind === "replay") {
    draft.replayCommand = strList(verifier.command).join("\n");
    draft.replayFields = strList(verifier.reproducible_fields).join(", ");
    draft.replayCwd = str(verifier.cwd);
    taken.add("command").add("reproducible_fields").add("cwd");
  }
  const extras: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(verifier)) if (!taken.has(key)) extras[key] = val;
  if (Object.keys(extras).length > 0) draft.verifierExtras = JSON.stringify(extras, null, 2);

  if (typeof record.ratchet === "object" && record.ratchet !== null) {
    const ratchet = record.ratchet as Record<string, unknown>;
    draft.useRatchet = true;
    draft.baseline = num(ratchet.baseline);
    draft.target = num(ratchet.target);
    draft.minImprovement = num(ratchet.min_improvement) || EMPTY_DRAFT.minImprovement;
    if (str(ratchet.direction)) draft.direction = str(ratchet.direction);
  }

  const carried = new Set([
    "goal",
    "statement",
    "funder",
    "reward",
    "deadline",
    "require_signed_submitter",
    "artifact_schema",
    "verifier",
    "ratchet",
    "type",
    // Re-stamped by the form: it is inside the id, and a loaded value would
    // make the posted objective claim to predate its posting.
    "created_at",
  ]);
  const dropped = Object.keys(record).filter((key) => !carried.has(key)).sort();
  return { draft, dropped };
}

function str(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function num(value: unknown): string {
  return typeof value === "number" && Number.isFinite(value) ? String(value) : "";
}

function strList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

/**
 * The sha256 of a file, spelled the way `checker_sha256` wants it.
 *
 * WebCrypto, not a hand-written digest: this is not a consensus rule, it is
 * the same `shasum -a 256` a funder would otherwise run in a terminal, and the
 * node checks the pinned file against the declared hash itself before it
 * trusts either. Unavailable on an insecure origin, where the caller falls
 * back to telling the funder the command.
 */
export async function sha256Hex(bytes: ArrayBuffer): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new Error(
      "this page is on an insecure origin, where the browser withholds WebCrypto; " +
        "run `shasum -a 256 <file>` and paste the result",
    );
  }
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
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
