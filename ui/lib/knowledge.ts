/**
 * How well verified each result is: `GET /knowledge` (`src/knowledge.rs`),
 * read as a short ladder of evidence a person can follow.
 *
 * The node already computes a claim's **standing** -- accepted, corroborated,
 * contested, superseded, withdrawn, refuted, unverified -- and a **confidence**
 * under a policy the reader picks. A bare percentage invites the question the
 * page could not answer: *why* 72%? So each result also gets the evidence
 * behind it as four independent checks, every one a fact the log or this node
 * can show:
 *
 * 1. **Checked** -- the challenge's pinned checker accepted it. The machine
 *    verdict; nothing below counts without it.
 * 2. **Re-checkable here** -- this node holds the checker's code, so anyone
 *    with the log can run the check again. A hash proves the bytes are the
 *    ones pinned; it does not conjure them.
 * 3. **Backed by a bond** -- a validator re-ran the check and staked on the
 *    verdict, and nobody has shown them wrong.
 * 4. **Replicated** -- an independent party reproduced the result in a claim
 *    of its own that its checker accepted.
 *
 * Nothing here is computed from scratch: every field is the node's, and the
 * confidence is the node's number under its named policy. What this file adds
 * is the reading, and it is display only -- no payment reads any of it, which
 * is the rule `src/knowledge.rs` is built around.
 */

import { expectFields } from "./shape";

export type Standing =
  | "accepted"
  | "corroborated"
  | "contested"
  | "superseded"
  | "withdrawn"
  | "refuted"
  | "unverified";

export type KnowledgeRow = {
  claim_id: string;
  objective_id: string;
  submitter: string;
  created_at: string;
  standing: Standing | string;
  /** The last verdict: `accept`, `reject`, `unavailable`, or null for none. */
  verdict: string | null;
  /** `yes`, `not-here`, or `unknown`. */
  reproducible: string;
  corroborations: number;
  refutations: number;
  disputes: number;
  superseded_by: string[];
  retracted_by: string | null;
  confidence_per_mille: number;
  /** Absent on a node older than the field. */
  attestations?: { accept: number; reject: number; slashed: number };
};

export type KnowledgeIndex = {
  claims: KnowledgeRow[];
  total: number;
  shown: number;
  by_standing: Record<string, number>;
  policy: { name: string; parameters: Record<string, number> };
  as_of_epoch: number;
  note: string;
};

export type Policy = "default" | "demanding";

/** `GET /knowledge`, or `null` from a node older than the route. */
export async function fetchKnowledge(base: string, policy: Policy = "default"): Promise<KnowledgeIndex | null> {
  const query = policy === "default" ? "" : `?policy=${policy}`;
  const response = await fetch(`${base}/knowledge${query}`, { cache: "no-store" });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error(`${base || "this node"}/knowledge answered ${response.status}`);
  return expectFields<KnowledgeIndex>(
    await response.json(),
    ["claims", "total", "by_standing", "policy"],
    `${base || "this node"}/knowledge`,
  );
}

export type Check = {
  key: "checked" | "recheckable" | "bonded" | "replicated";
  label: string;
  done: boolean;
  /** Why it is or is not done, in a sentence. */
  why: string;
};

export type Verification = {
  /** How many of the four checks hold. Zero when the checker did not accept. */
  level: number;
  checks: Check[];
  /** The standing, in words, for a badge. */
  label: string;
  tone: "accent" | "warn" | "bad" | "neutral";
  /** 0..100, the node's confidence under its policy, floored. */
  percent: number;
};

const STANDING_LABEL: Record<Standing, string> = {
  accepted: "Verified",
  corroborated: "Replicated",
  contested: "Contested",
  superseded: "Superseded",
  withdrawn: "Withdrawn by its author",
  refuted: "Rejected by its checker",
  unverified: "Not checked yet",
};

function standingTone(standing: string): Verification["tone"] {
  switch (standing) {
    case "accepted":
    case "corroborated":
      return "accent";
    case "contested":
    case "superseded":
    case "unverified":
      return "warn";
    case "refuted":
    case "withdrawn":
      return "bad";
    default:
      return "neutral";
  }
}

/** The ladder for one result. */
export function verification(row: KnowledgeRow): Verification {
  const checked = row.verdict === "accept";
  const attested = row.attestations;
  const bonded = !!attested && attested.accept > 0 && attested.slashed === 0;
  const checks: Check[] = [
    {
      key: "checked",
      label: "Checked",
      done: checked,
      why: checked
        ? "The challenge's pinned checker accepted it."
        : row.verdict === "reject"
          ? "The pinned checker rejected it."
          : row.verdict === "unavailable"
            ? "The checker could not run when it arrived; that says nothing about the result."
            : "No verdict has been recorded yet.",
    },
    {
      key: "recheckable",
      label: "Re-checkable here",
      done: checked && row.reproducible === "yes",
      why:
        row.reproducible === "yes"
          ? "This node holds the checker's code, so the verdict can be re-run from the log."
          : row.reproducible === "not-here"
            ? "This node is missing the checker's code; another node may have it."
            : "This node did not determine whether it can re-run the check.",
    },
    {
      key: "bonded",
      label: "Backed by a bond",
      done: checked && bonded,
      why: !attested
        ? "This node does not report bonded checks."
        : attested.slashed > 0
          ? `${attested.slashed} bonded check${attested.slashed === 1 ? " was" : "s were"} shown wrong and slashed.`
          : attested.accept > 0
            ? `${attested.accept} validator${attested.accept === 1 ? "" : "s"} re-ran the check and staked on it.`
            : "No validator has staked on this verdict.",
    },
    {
      key: "replicated",
      label: "Replicated",
      done: checked && row.corroborations > 0,
      why:
        row.corroborations > 0
          ? `${row.corroborations} independent part${row.corroborations === 1 ? "y" : "ies"} reproduced it.`
          : "Nobody has independently reproduced it yet.",
    },
  ];
  const level = checked ? checks.filter((c) => c.done).length : 0;
  const standing = row.standing as Standing;
  return {
    level,
    checks,
    label: STANDING_LABEL[standing] ?? row.standing,
    tone: standingTone(row.standing),
    percent: Math.max(0, Math.min(100, Math.floor(row.confidence_per_mille / 10))),
  };
}

/** What would lower a result's confidence, said once under its ladder. */
export function caveats(row: KnowledgeRow): string[] {
  const out: string[] = [];
  if (row.refutations > 0) {
    out.push(`${row.refutations} verified claim${row.refutations === 1 ? "" : "s"} say${row.refutations === 1 ? "s" : ""} it is wrong`);
  }
  if (row.disputes > 0) {
    out.push(`${row.disputes} could not reproduce it`);
  }
  if (row.superseded_by.length > 0) {
    out.push(`superseded by ${row.superseded_by.length} later result${row.superseded_by.length === 1 ? "" : "s"}`);
  }
  if (row.retracted_by) out.push("its author retracted it");
  return out;
}
