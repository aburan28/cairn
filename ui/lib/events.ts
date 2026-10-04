/**
 * The log, read as things that happened.
 *
 * `/log` is the file `cairn audit` reads: one JSON record per line, in the
 * order the node admitted them. That is the right thing to *store* and the
 * wrong thing to *show* -- a page that expands a row into a pretty-printed
 * payload is asking a person to be a JSON parser. This file turns each record
 * into a sentence, an actor, an amount and the objective it belongs to, and
 * leaves the record itself one click away for anyone who wants the bytes.
 *
 * It is a reading, not a re-derivation. Every field shown is one the node
 * wrote; nothing here hashes, settles, or decides. In particular an
 * `objective` entry's payload carries no id -- the id is a canonical hash of
 * the record, and computing it in TypeScript would be the third
 * implementation of a consensus rule that AGENTS.md forbids -- so the caller
 * passes the objectives the node already listed and they are matched by the
 * fields the node published (`objectiveIdOf`, below).
 */

import type { LogRecord } from "./log";

export type EventTone = "neutral" | "good" | "bad" | "warn";

export type LogEvent = {
  seq: number;
  ts: string;
  kind: string;
  /** Who did it, as the record names them: a submitter, funder, holder… */
  actor: string | null;
  /** What they did, as a phrase that follows the actor ("committed to a claim"). */
  action: string;
  /** A short qualifier: a score, a verdict's detail, an epoch. */
  detail: string | null;
  /** Money this record moved or staked, in integer units. */
  amount: number | null;
  /** What `amount` is: "bounty", "paid", "bond"… */
  amountLabel: string | null;
  objectiveId: string | null;
  claimId: string | null;
  tone: EventTone;
  /** The payload's scalar fields, labelled, for the expanded row. */
  fields: Array<[string, string]>;
};

/** What the page knows about the objectives, from `GET /objectives`. */
export type ObjectiveIndex = {
  ids: Set<string>;
  /** `goal`, `funder` and `statement` joined -- the fields both the list and
   *  the record carry, so an `objective` entry can be matched to its id. */
  byContent: Map<string, string>;
};

function contentKey(goal: unknown, funder: unknown, statement: unknown): string {
  return `${String(goal ?? "")}\u0000${String(funder ?? "")}\u0000${String(statement ?? "")}`;
}

export function indexObjectives(
  objectives: Array<{ id: string; goal: string; funder: string; statement: string }>,
): ObjectiveIndex {
  const byContent = new Map<string, string>();
  for (const o of objectives) byContent.set(contentKey(o.goal, o.funder, o.statement), o.id);
  return { ids: new Set(objectives.map((o) => o.id)), byContent };
}

/** The id the node listed for an `objective` entry, if it listed one. */
export function objectiveIdOf(record: LogRecord, index: ObjectiveIndex | null): string | null {
  if (record.kind !== "objective" || !index) return null;
  const p = record.payload ?? {};
  return index.byContent.get(contentKey(p.goal, p.funder, p.statement)) ?? null;
}

function str(value: unknown): string | null {
  return typeof value === "string" && value ? value : null;
}

function num(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/** The first field present, in the order given. */
function pick(payload: Record<string, unknown>, keys: string[]): string | null {
  for (const key of keys) {
    const v = str(payload[key]);
    if (v) return v;
  }
  return null;
}

const ACTOR_KEYS = [
  "submitter",
  "holder",
  "funder",
  "attestor",
  "challenger",
  "identity",
  "worker",
];

const AMOUNT_KEYS: Array<[string, string]> = [
  ["reward", "paid"],
  ["amount", "amount"],
  ["bond", "bond"],
  ["per_epoch", "per epoch"],
  ["units", "units"],
];

/** Integer amounts, grouped when shown; an epoch or a seat is not money. */
const MONEY_KEYS = new Set([
  "reward",
  "amount",
  "bond",
  "per_epoch",
  "units",
  "paid_cumulative",
  "pool_remaining",
]);

/** `availability_settlement` → `availability settlement`. */
function words(kind: string): string {
  return kind.replace(/_/g, " ");
}

function scalarFields(payload: unknown): Array<[string, string]> {
  if (typeof payload !== "object" || payload === null) return [];
  const out: Array<[string, string]> = [];
  for (const [key, value] of Object.entries(payload as Record<string, unknown>)) {
    if (key === "type" || key === "signature") continue;
    if (typeof value === "number" && MONEY_KEYS.has(key)) {
      out.push([key.replace(/_/g, " "), value.toLocaleString("en-US")]);
    } else if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      out.push([key.replace(/_/g, " "), String(value)]);
    } else if (Array.isArray(value) && value.every((v) => typeof v === "string")) {
      if (value.length) out.push([key.replace(/_/g, " "), value.join(", ")]);
    }
  }
  return out;
}

/**
 * One record as an event.
 *
 * Unknown kinds still render: the actor and amount come from the fields most
 * records use for them, and the action is the kind's own name. A record kind
 * added next month is then a plain sentence here rather than a blank row.
 */
export function toEvent(record: LogRecord, index: ObjectiveIndex | null = null): LogEvent {
  const p: Record<string, unknown> = (record.payload ?? {}) as Record<string, unknown>;
  const base: LogEvent = {
    seq: record.seq,
    ts: record.ts,
    kind: record.kind,
    actor: pick(p, ACTOR_KEYS),
    action: words(record.kind),
    detail: null,
    amount: null,
    amountLabel: null,
    objectiveId: str(p.objective_id),
    claimId: str(p.claim_id),
    tone: "neutral",
    fields: scalarFields(p),
  };
  for (const [key, label] of AMOUNT_KEYS) {
    const v = num(p[key]);
    if (v !== null) {
      base.amount = v;
      base.amountLabel = label;
      break;
    }
  }

  switch (record.kind) {
    case "objective":
      return {
        ...base,
        actor: str(p.funder),
        action: "posted a challenge",
        detail: str(p.goal)?.replace(/^GOAL[-_:]/i, "") ?? null,
        amountLabel: base.amount !== null ? "bounty" : null,
        objectiveId: objectiveIdOf(record, index),
      };
    case "commitment":
      return {
        ...base,
        action: "committed to an answer",
        detail: "sealed until the epoch turns",
      };
    case "claim": {
      const cites = Array.isArray(p.cites) ? p.cites.length : 0;
      return {
        ...base,
        action: "revealed an answer",
        detail: cites ? `cites ${cites} earlier claim${cites === 1 ? "" : "s"}` : null,
      };
    }
    case "verdict": {
      const v = (p.verdict ?? {}) as Record<string, unknown>;
      const status = str(v.status) ?? "?";
      const action =
        status === "accept"
          ? "accepted an answer"
          : status === "reject"
            ? "rejected an answer"
            : status === "unavailable"
              ? "could not check an answer"
              : `returned ${status}`;
      return {
        ...base,
        actor: "checker",
        action,
        detail: str(v.detail),
        tone: status === "accept" ? "good" : status === "reject" ? "bad" : "warn",
      };
    }
    case "settlement":
      return { ...base, action: "was paid", amountLabel: "paid", tone: "good" };
    case "frontier":
      return {
        ...base,
        action: "took the lead",
        detail: num(p.score) !== null ? `score ${p.score}` : null,
        amount: num(p.paid_cumulative),
        amountLabel: num(p.paid_cumulative) !== null ? "paid so far" : null,
        tone: "good",
      };
    case "batch": {
      const n = Array.isArray(p.claims) ? p.claims.length : 0;
      return {
        ...base,
        actor: null,
        action: `Epoch ${p.epoch ?? "?"} closed`,
        detail: `${n} answer${n === 1 ? "" : "s"} settled in beacon order`,
      };
    }
    case "beacon":
      return { ...base, actor: null, action: "Epoch beacon published" };
    case "peer":
      return { ...base, action: "announced an address", detail: str(p.addr) };
    case "undertaking":
      return { ...base, action: "bonded to keep a copy of the log", amountLabel: "bond" };
    case "availability":
      return {
        ...base,
        action: "proved it still holds the log",
        detail: num(p.epoch) !== null ? `epoch ${p.epoch}` : null,
        tone: "good",
      };
    case "availability_pool":
      return { ...base, action: "funded log availability", amountLabel: "per epoch" };
    case "availability_settlement":
      return { ...base, action: base.actor ? "was paid for availability" : "Availability paid out", tone: "good" };
    case "issuance":
      return { ...base, action: "was issued units", amountLabel: "units" };
    case "committee_share":
      return {
        ...base,
        action: "posted a key share",
        detail: num(p.seat) !== null ? `seat ${p.seat}` : null,
      };
    case "attestation": {
      const status = str(p.status);
      return {
        ...base,
        action: status ? `attested: ${status}` : "attested a verdict",
        tone: status === "reject" ? "bad" : "neutral",
      };
    }
    case "challenge":
      return { ...base, action: "disputed a verdict", amountLabel: "bond", tone: "warn" };
    case "bisection":
      return { ...base, action: base.actor ? "narrowed a dispute" : "Dispute narrowed" };
    case "challenge_settlement":
      return { ...base, action: base.actor ? "had a dispute resolved" : "Dispute resolved", tone: "warn" };
    case "verification_slash":
      return { ...base, action: base.actor ? "was slashed" : "A verifier was slashed", tone: "bad" };
    default:
      return base;
  }
}

/**
 * The claim each claim id belongs to, from the records that name both.
 * Verdicts, settlements and frontiers carry `objective_id` beside `claim_id`;
 * attestations and disputes carry only the claim, and this is how they find
 * their objective without hashing a claim in the browser.
 */
export function claimObjectives(records: LogRecord[]): Map<string, string> {
  const out = new Map<string, string>();
  for (const r of records) {
    const claim = str(r.payload?.claim_id);
    const objective = str(r.payload?.objective_id);
    if (claim && objective) out.set(claim, objective);
  }
  return out;
}

/** Every event that concerns one objective, oldest first. */
export function eventsFor(
  records: LogRecord[],
  objectiveId: string,
  index: ObjectiveIndex | null,
): LogEvent[] {
  const claims = claimObjectives(records);
  const out: LogEvent[] = [];
  for (const record of records) {
    const event = toEvent(record, index);
    const owner =
      event.objectiveId ?? (event.claimId ? (claims.get(event.claimId) ?? null) : null);
    if (owner === objectiveId) out.push({ ...event, objectiveId: owner });
  }
  return out;
}

/** One person's part in an objective, as the log records it. */
export type Participant = {
  name: string;
  committed: number;
  revealed: number;
  accepted: number;
  rejected: number;
  paid: number;
  leads: boolean;
  lastSeen: string;
};

/**
 * Who has worked on an objective, from its events: everyone who committed,
 * revealed, was judged or was paid. Most recently active first.
 *
 * Verdicts name no submitter. The node appends a claim's verdict as the very
 * next entry after the claim (`append(CLAIM, …)` then `append(VERDICT, …)` in
 * `src/node.rs`, under one write lock), so a verdict is credited to the
 * revealer of the claim immediately before it. A settlement or frontier that
 * names the claim id wins over that when there is one. Anything else is left
 * uncredited rather than guessed.
 */
export function participants(events: LogEvent[]): Participant[] {
  const people = new Map<string, Participant>();
  const byClaim = new Map<string, string>();
  for (const e of events) {
    if ((e.kind === "settlement" || e.kind === "frontier") && e.actor && e.claimId) {
      byClaim.set(e.claimId, e.actor);
    }
  }
  const touch = (name: string, ts: string): Participant => {
    let p = people.get(name);
    if (!p) {
      p = { name, committed: 0, revealed: 0, accepted: 0, rejected: 0, paid: 0, leads: false, lastSeen: ts };
      people.set(name, p);
    }
    if (ts > p.lastSeen) p.lastSeen = ts;
    return p;
  };
  let leader: string | null = null;
  let previous: LogEvent | null = null;
  for (const e of events) {
    if (e.kind === "commitment" && e.actor) touch(e.actor, e.ts).committed += 1;
    else if (e.kind === "claim" && e.actor) touch(e.actor, e.ts).revealed += 1;
    else if (e.kind === "settlement" && e.actor) touch(e.actor, e.ts).paid += e.amount ?? 0;
    else if (e.kind === "frontier" && e.actor) {
      touch(e.actor, e.ts);
      leader = e.actor;
    } else if (e.kind === "verdict" && e.claimId) {
      const adjacent =
        previous && previous.kind === "claim" && previous.seq === e.seq - 1 ? previous.actor : null;
      const who = byClaim.get(e.claimId) ?? adjacent;
      if (who) {
        const p = touch(who, e.ts);
        if (e.tone === "good") p.accepted += 1;
        else if (e.tone === "bad") p.rejected += 1;
      }
    }
    previous = e;
  }
  if (leader) {
    const p = people.get(leader);
    if (p) p.leads = true;
  }
  return [...people.values()].sort((a, b) => b.lastSeen.localeCompare(a.lastSeen));
}

/** `3 min ago`, from an RFC 3339 stamp, against `now`. */
export function ago(ts: string, now: number = Date.now()): string {
  const at = Date.parse(ts);
  if (!Number.isFinite(at)) return ts;
  const s = Math.max(0, (now - at) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86_400) return `${Math.round(s / 3600)} h ago`;
  if (s < 30 * 86_400) return `${Math.round(s / 86_400)} d ago`;
  return ts.slice(0, 10);
}
