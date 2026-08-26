/**
 * A reader for the raw log.
 *
 * Mirrors `GET /log` (see `src/serve.rs::log`), which answers
 * `application/x-ndjson` — one JSON record per line — rather than a JSON
 * array, because the log is append-only and a server streaming it should
 * never have to hold the whole thing in memory to wrap it in `[...]`. This
 * file is the only place that format is parsed; everything downstream gets
 * plain records.
 *
 * Nothing here re-derives anything the node did not already publish: no
 * hash is recomputed, no chain is walked. Where this file joins one record
 * to another (`buildMoves`, below) it only ever compares fields the node
 * already wrote against each other, the same move `overspent` in
 * `objectives.ts` and `firstBrokenLink` in `chain.ts` already make.
 */

import { expectFields } from "./shape";

/** One entry, exactly as the log stores it. `payload` is record-kind-specific
 *  and untyped here on purpose — this file's job is parsing NDJSON, not
 *  knowing every record shape the protocol will ever add. */
export type LogRecord = {
  seq: number;
  kind: string;
  hash: string;
  /** The previous record's `hash`, or null for the first record in the log. */
  prev: string | null;
  ts: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  payload: any;
};

export const NODE_URL = process.env.NEXT_PUBLIC_CAIRN_NODE ?? "";

export class NodeUnreachable extends Error {}

/** The records a log held, and every line of it that was not one. */
export type ParsedLog = {
  records: LogRecord[];
  /** One entry per line that did not parse as a record, naming the line.
   *  Never thrown: a log with one bad line still has every other line, and
   *  a page that blanks itself over one has hidden the rest — including the
   *  fact that something is wrong with the file `cairn audit` reads. */
  problems: string[];
};

/**
 * Parse NDJSON into records, one line at a time.
 *
 * Per line, and guarded per line, rather than one `JSON.parse` over the
 * whole body: a single malformed line used to throw out of the loop and
 * leave the page with an error where the log should be. What a reader
 * needs from a corrupt line is *which* line, and the ones around it still
 * rendered — the audit tool reads the same file, and a page that says
 * "line 17 is not a record" sends somebody straight to it.
 *
 * "Not a record" covers a line that parses but lacks the fields every
 * entry carries: `seq`, `kind`, `hash`, `payload`. `prev` is `null` at
 * genesis, so it is deliberately not on that list — `expectFields` checks
 * for `undefined`, but a reader should not have to know that to trust it.
 */
export function parseLog(text: string): ParsedLog {
  const records: LogRecord[] = [];
  const problems: string[] = [];
  const lines = text.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim()) continue;
    try {
      records.push(
        expectFields<LogRecord>(
          JSON.parse(line),
          ["seq", "kind", "hash", "payload"],
          `line ${index + 1}`,
        ),
      );
    } catch (cause) {
      const why = cause instanceof Error ? cause.message : String(cause);
      problems.push(`line ${index + 1}: ${why}`);
    }
  }
  return { records, problems };
}

/**
 * Fetch and parse the log.
 *
 * `cache: "no-store"` for the reason every other reader here gives: this is
 * append-only, so a cached answer can only ever be a stale prefix, and a
 * stale prefix is the one thing a records explorer must not show silently.
 */
export async function fetchLog(base: string = NODE_URL): Promise<ParsedLog> {
  let response: Response;
  try {
    response = await fetch(`${base}/log`, { cache: "no-store" });
  } catch (cause) {
    throw new NodeUnreachable(
      `No node answered at ${base}. Start one with \`make serve\`, or set ` +
        `NEXT_PUBLIC_CAIRN_NODE to where yours is listening.`,
      { cause },
    );
  }
  if (!response.ok) {
    throw new NodeUnreachable(`${base}/log answered ${response.status}.`);
  }
  return parseLog(await response.text());
}

/** How many records of each kind, in the order each kind first appears —
 *  stable across reloads of the same log, unlike an alphabetical sort, so
 *  the filter row does not reshuffle every time somebody opens the page. */
export function kindCounts(records: LogRecord[]): Array<[string, number]> {
  const order: string[] = [];
  const counts = new Map<string, number>();
  for (const record of records) {
    if (!counts.has(record.kind)) order.push(record.kind);
    counts.set(record.kind, (counts.get(record.kind) ?? 0) + 1);
  }
  return order.map((kind) => [kind, counts.get(kind) ?? 0]);
}

/** A hash or key, short enough to scan a column of them. */
export function short(value: string): string {
  const bare = value.startsWith("sha256:") ? value.slice(7) : value;
  return bare.length <= 12 ? bare : `${bare.slice(0, 8)}…${bare.slice(-4)}`;
}

/**
 * One line describing what a record says, for the table's `says` column.
 *
 * This is the page's own reading of the payload, not a field the node wrote —
 * which is why it stays out of the exported JSON and lives only in the
 * rendered row. Unrecognised kinds fall back to a trimmed dump of the payload
 * rather than an empty cell, because a future record kind should still be
 * legible here without this file needing to know about it first.
 */
export function summarize(record: LogRecord): string {
  const p = record.payload ?? {};
  switch (record.kind) {
    case "objective":
      return `${p.goal ?? "?"} · ${p.verifier?.kind ?? "?"} · ${
        typeof p.reward === "number" ? p.reward.toLocaleString("en-US") : "?"
      } by ${p.funder ?? "?"}`;
    case "commitment":
      return `by ${p.submitter ?? "?"}`;
    case "claim": {
      const cites = Array.isArray(p.cites) && p.cites.length > 0
        ? ` · cites ${short(p.cites[0])}${p.cites.length > 1 ? ` +${p.cites.length - 1}` : ""}`
        : "";
      return `by ${p.submitter ?? "?"}${cites}`;
    }
    case "verdict":
      return `${p.verdict?.status ?? "?"}${p.verdict?.detail ? `: ${p.verdict.detail}` : ""}`;
    case "settlement":
      return `${p.submitter ?? "?"} ← ${
        typeof p.reward === "number" ? p.reward.toLocaleString("en-US") : "?"
      }`;
    case "frontier":
      return `${p.score ?? "?"} · ${p.holder ?? "?"} · paid ${
        typeof p.paid_cumulative === "number"
          ? p.paid_cumulative.toLocaleString("en-US")
          : "?"
      } so far`;
    case "batch": {
      const n = Array.isArray(p.claims) ? p.claims.length : 0;
      return `epoch ${p.epoch ?? "?"} · ${n} claim${n === 1 ? "" : "s"}`;
    }
    case "peer":
      return `${p.identity ? short(p.identity) : "?"} answers at ${p.addr ?? "?"}`;
    default: {
      const flat = JSON.stringify(p);
      return flat.length > 96 ? `${flat.slice(0, 96)}…` : flat;
    }
  }
}

/**
 * A pretty-printed record, for the expanded row.
 *
 * `JSON.stringify` with two-space indent rather than anything fancier: this
 * is meant to look like the line the node actually wrote, not like a UI
 * component's opinion of it.
 */
export function pretty(record: LogRecord): string {
  return JSON.stringify(record, null, 2);
}

/** Whether a value is a plausible objective id for `payload.objective_id`. */
function matchesObjective(payload: unknown, objectiveId: string): boolean {
  return (
    typeof payload === "object" &&
    payload !== null &&
    (payload as { objective_id?: unknown }).objective_id === objectiveId
  );
}

/** One step in an objective's frontier, as the log recorded it. */
export type FrontierMove = {
  seq: number;
  ts: string;
  score: number;
  holder: string;
  claimId: string;
  /** This move's own payout, computed as this record's `paid_cumulative`
   *  minus the previous frontier record's — arithmetic on two numbers the
   *  node published, not a new one. */
  paidThisMove: number;
  paidCumulative: number;
  /** The `settlement` record naming the same `claim_id`, if the log has
   *  reached that far — joined by value, not by re-hashing anything. */
  settlementReward: number | null;
  /** Whether this move's own payout matches what `settlement` records for
   *  the same claim. A mismatch means this node published two records that
   *  disagree about one payment, which is worth surfacing rather than
   *  picking one silently — the same instinct as `overspent` in
   *  `objectives.ts`. */
  consistent: boolean;
};

/**
 * The successive frontier states for one objective, oldest first.
 *
 * Built entirely from `frontier` and `settlement` records already in the
 * log, matched by `objective_id` and `claim_id` — values the node wrote, not
 * anything this file derives. This is deliberately *not* built by walking a
 * claim's `cites` array back to the claim it named: that would mean
 * resolving `claim_id` to the claim record that produced it, and a claim's
 * `claim_id` is a canonical hash of its payload rather than the record's own
 * chained `hash` field. Recomputing that hash in the browser would be a
 * second implementation of a rule this project keeps in exactly one place —
 * `src/canonical.rs` — so this reads the frontier records' own sequence
 * instead, which already *is* the order improvements were admitted in.
 */
export function buildMoves(records: LogRecord[], objectiveId: string): FrontierMove[] {
  const frontiers = records
    .filter((r) => r.kind === "frontier" && matchesObjective(r.payload, objectiveId))
    .sort((a, b) => a.seq - b.seq);

  const settlementByClaim = new Map<string, number>();
  for (const r of records) {
    if (r.kind === "settlement" && matchesObjective(r.payload, objectiveId)) {
      settlementByClaim.set(r.payload.claim_id, r.payload.reward);
    }
  }

  const moves: FrontierMove[] = [];
  let previousPaid = 0;
  for (const record of frontiers) {
    const p = record.payload;
    const paidThisMove = p.paid_cumulative - previousPaid;
    const settlementReward = settlementByClaim.get(p.claim_id) ?? null;
    moves.push({
      seq: record.seq,
      ts: record.ts,
      score: p.score,
      holder: p.holder,
      claimId: p.claim_id,
      paidThisMove,
      paidCumulative: p.paid_cumulative,
      settlementReward,
      consistent: settlementReward === null || settlementReward === paidThisMove,
    });
    previousPaid = p.paid_cumulative;
  }
  return moves;
}
