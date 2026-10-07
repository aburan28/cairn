/**
 * Readers for `GET /knowledge` and `GET /knowledge/{claim_id}`.
 *
 * Mirrors `src/serve.rs::knowledge_index` and `knowledge_of`, which publish
 * `src/knowledge.rs`'s derivation: each claim's standing, who with standing
 * said what about it, and a confidence number under the named policy. The
 * policy travels beside every number because there is no network-agreed
 * confidence — a second reader with `?policy=demanding` gets different
 * numbers from identical bytes, and neither is wrong.
 *
 * Nothing here moves money and nothing here settles anything. Standing is
 * derived, not written; a page that used it to re-order payouts would be
 * the popularity contest `docs/knowledge.md` refuses to build.
 */

import { NODE_URL } from "./site";
import { expectFields } from "./shape";
import { RouteMissing, NodeUnreachable } from "./network";

export type Standing =
  | "refuted"
  | "unverified"
  | "withdrawn"
  | "superseded"
  | "contested"
  | "corroborated"
  | "accepted";

export type KnowledgeRow = {
  claim_id: string;
  standing: Standing;
  verdict: string | null;
  reproducible: string;
  corroborations: number;
  refutations: number;
  disputes: number;
  superseded_by: string[];
  retracted_by: string | null;
  confidence_per_mille: number;
  objective_id: string;
  submitter: string;
  created_at: string;
};

export type KnowledgeIndex = {
  claims: KnowledgeRow[];
  total: number;
  shown: number;
  by_standing: Record<string, number>;
  policy: { name: string; parameters: Record<string, unknown> };
  as_of_epoch: number;
  note: string;
};

export type Assertion = {
  by: string;
  relation: string;
  grounded: boolean;
  class: number;
};

export type AttestationRow = {
  attestation_id: string;
  attestor: string;
  status: string;
  created_at: string;
  slashed: boolean;
};

export type KnowledgeClaim = {
  claim_id: string;
  objective_id: string;
  submitter: string;
  state: Omit<KnowledgeRow, "objective_id" | "submitter" | "created_at"> & {
    assertions: Assertion[];
  };
  attestations: {
    accept: number;
    reject: number;
    slashed: number;
    bond_each: number;
    attestations: AttestationRow[];
  };
  policy: { name: string; parameters: Record<string, unknown> };
  as_of_epoch: number;
  note: string;
};

async function read<T extends object>(base: string, route: string, fields: readonly string[]): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${base}${route}`, { cache: "no-store" });
  } catch (cause) {
    throw new NodeUnreachable(
      `No node answered at ${base || "this origin"}. Start one with \`cairn run\`, or set ` +
        `NEXT_PUBLIC_CAIRN_NODE to where yours is listening.`,
      { cause },
    );
  }
  if (response.status === 404) {
    throw new RouteMissing(
      `${base || "this node"} answered 404 for ${route}. That route is newer than the node ` +
        `you are reading; this page needs a node built after it was added.`,
    );
  }
  if (!response.ok) {
    throw new NodeUnreachable(`${base}${route} answered ${response.status}.`);
  }
  return expectFields<T>(await response.json(), fields, `${base || "this node"}${route}`);
}

export function fetchKnowledgeIndex(
  base: string = NODE_URL,
  policy: "default" | "demanding" = "default",
): Promise<KnowledgeIndex> {
  const query = policy === "demanding" ? "?policy=demanding" : "";
  return read<KnowledgeIndex>(base, `/knowledge${query}`, ["claims", "total", "by_standing"]);
}

export function fetchKnowledgeClaim(
  claimId: string,
  base: string = NODE_URL,
  policy: "default" | "demanding" = "default",
): Promise<KnowledgeClaim> {
  const query = policy === "demanding" ? "?policy=demanding" : "";
  return read<KnowledgeClaim>(base, `/knowledge/${claimId}${query}`, ["claim_id", "state"]);
}

// -- display ---------------------------------------------------------------

/** How a standing reads as a badge: the machine's word is final, the rest is shades of said-about. */
export function standingTone(standing: string): "accent" | "warn" | "bad" | "neutral" {
  switch (standing) {
    case "corroborated":
    case "accepted":
      return "accent";
    case "contested":
    case "superseded":
      return "warn";
    case "refuted":
    case "withdrawn":
      return "bad";
    default:
      return "neutral";
  }
}

/** One line for a standing, for readers who have not read `docs/knowledge.md`. */
export function standingHelp(standing: string): string {
  switch (standing) {
    case "refuted":
      return "the pinned verifier rejected it — the end of the discussion";
    case "unverified":
      return "no settling verdict; the checker never confirmed it";
    case "withdrawn":
      return "its own author took it back";
    case "superseded":
      return "a later verified claim replaced, corrected, or narrowed it";
    case "contested":
      return "verified claims dispute it and nothing has resolved it";
    case "corroborated":
      return "verified and independently reproduced at least once";
    case "accepted":
      return "verified, and nothing further has been said";
    default:
      return standing;
  }
}

/** `600` per mille as `60%`. Thresholds belong on the per-mille value; this is display only. */
export function confidencePercent(perMille: number): number {
  if (!Number.isFinite(perMille)) return 0;
  return Math.max(0, Math.min(100, Math.floor(perMille / 10)));
}

/** A claim's corroboration story in one line, for a table cell. */
export function evidenceLine(row: Pick<KnowledgeRow, "corroborations" | "refutations" | "disputes">): string {
  const parts: string[] = [];
  if (row.corroborations > 0)
    parts.push(`${row.corroborations} corroborat${row.corroborations === 1 ? "ion" : "ions"}`);
  if (row.refutations > 0) parts.push(`${row.refutations} refutation${row.refutations === 1 ? "" : "s"}`);
  if (row.disputes > 0) parts.push(`${row.disputes} dispute${row.disputes === 1 ? "" : "s"}`);
  return parts.length > 0 ? parts.join(" · ") : "nothing said yet";
}
