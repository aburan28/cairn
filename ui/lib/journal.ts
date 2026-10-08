/**
 * The node's own event feed, `GET /events` (`src/journal.rs`), and the
 * timeline the Log page draws from it and the records together.
 *
 * Two different things, and the page keeps them visibly apart. A record is
 * what the log admitted -- the thing `cairn audit` reads and every payment is
 * derived from. A node event is what this process saw happen: a peer reached,
 * records synced, a machine starting, an agent attaching. It is held in
 * memory, gone on restart, and nobody checks it. The timeline interleaves
 * them by time because "what happened" is one question for a person, and
 * marks every row with which kind it is because the answer to "can I rely on
 * this" differs.
 */

import type { LogRecord } from "./log";
import { expectFields } from "./shape";

export type NodeEventKind =
  | "node"
  | "peer"
  | "worker"
  | "host"
  | "lease"
  | "fleet"
  | "submission"
  | "agent";

export type NodeEvent = {
  seq: number;
  /** RFC 3339, `+00:00`, by the node's clock. Display only. */
  at: string;
  kind: NodeEventKind | string;
  tone: "neutral" | "good" | "warn" | "bad";
  text: string;
  /** A peer id, objective id, or machine name; for a link or a search. */
  subject: string | null;
};

export type EventsPage = {
  events: NodeEvent[];
  /** The newest `seq` the node has; ask for `after=last` next time. */
  last: number;
  /** Events asked for and not returned: fallen off the ring, or unpaged. */
  dropped: number;
  capacity: number;
  /** When this process's journal began. A smaller `last` than before after
   *  this changes is a restart, not a rewind. */
  started_at: string;
  note: string;
};

/** What a kind is called on the page. */
export const KIND_LABEL: Record<NodeEventKind, string> = {
  node: "This node",
  peer: "Other nodes",
  worker: "Machines",
  host: "Machines",
  lease: "Tasks",
  fleet: "Fleet",
  submission: "Proposals",
  agent: "Agents",
};

/**
 * The feed after `after`, or `null` from a node older than the route -- an
 * ordinary state the page says once rather than an error.
 */
export async function fetchEvents(base: string, after = 0): Promise<EventsPage | null> {
  const response = await fetch(`${base}/events?after=${after}`, { cache: "no-store" });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error(`${base || "this node"}/events answered ${response.status}`);
  return expectFields<EventsPage>(
    await response.json(),
    ["events", "last", "started_at"],
    `${base || "this node"}/events`,
  );
}

/**
 * Add a fresh page to what the page already holds, newest kept, bounded.
 * A page whose journal started later than the one held is a restarted node:
 * its seqs start again from 1, so what was held is from a process that no
 * longer exists and is dropped rather than interleaved with the new one.
 */
export function absorb(
  held: { events: NodeEvent[]; started_at: string | null },
  page: EventsPage,
  cap = 500,
): { events: NodeEvent[]; started_at: string } {
  const restarted = held.started_at !== null && held.started_at !== page.started_at;
  const base = restarted ? [] : held.events;
  const seen = new Set(base.map((e) => e.seq));
  const merged = [...base, ...page.events.filter((e) => !seen.has(e.seq))];
  merged.sort((a, b) => a.seq - b.seq);
  return { events: merged.slice(-cap), started_at: page.started_at };
}

export type TimelineItem =
  | { type: "record"; at: number; record: LogRecord }
  | { type: "event"; at: number; event: NodeEvent };

function when(stamp: string): number {
  const at = Date.parse(stamp);
  return Number.isFinite(at) ? at : 0;
}

/**
 * Records and node events in one list, newest first.
 *
 * By timestamp, with ties broken so the order is stable: records by `seq`,
 * events by `seq`, and at the same second an event before a record -- the
 * node sees a peer before it imports what the peer sent.
 */
export function timeline(records: LogRecord[], events: NodeEvent[]): TimelineItem[] {
  const items: TimelineItem[] = [
    ...records.map((record) => ({ type: "record" as const, at: when(record.ts), record })),
    ...events.map((event) => ({ type: "event" as const, at: when(event.at), event })),
  ];
  items.sort((a, b) => {
    if (a.at !== b.at) return b.at - a.at;
    if (a.type !== b.type) return a.type === "record" ? -1 : 1;
    const seq = (item: TimelineItem) => (item.type === "record" ? item.record.seq : item.event.seq);
    return seq(b) - seq(a);
  });
  return items;
}
