"use client";

import { useCallback, useMemo, useRef, useState } from "react";
import { type LogRecord, fetchLog, kindCounts } from "@/lib/log";
import { type ObjectiveIndex, indexObjectives, toEvent } from "@/lib/events";
import { KIND_LABEL, type NodeEvent, absorb, fetchEvents, timeline } from "@/lib/journal";
import { objectiveTitle } from "@/lib/title";
import { loadObjectives } from "@/lib/site";
import { useEvery, useNode } from "@/components/hooks";
import { EventRow, NodeEventRow } from "@/components/events";
import { Card, EmptyState, LiveStamp, Note, PageHeader, Skeleton } from "@/components/ui";

/** Rows drawn at once. A long log is thousands of records; the rest are a click away. */
const PAGE = 200;

type View = "all" | "records" | "events";

/**
 * Everything that happened, newest first: the records the log admitted, and
 * what this node saw happen around them.
 *
 * The records are the file `cairn audit` reads and every other page derives
 * its numbers from; each is a sentence (`lib/events.ts`), its fields and its
 * exact bytes one click away. The node events are `GET /events`: a peer
 * reached, records synced from it, a machine starting, an agent attaching --
 * the part of "what happened" the log never held, and that an operator used
 * to read on stderr if at all. They are drawn as rings rather than dots and
 * labelled with what they are about, because they are this process's memory
 * and not the log's.
 *
 * The URL box that used to sit in the header is gone: this is the reader the
 * node serves, and it reads that node.
 */
export default function Page() {
  const base = useNode();
  const [records, setRecords] = useState<LogRecord[] | null>(null);
  const [problems, setProblems] = useState<string[]>([]);
  const [events, setEvents] = useState<{ events: NodeEvent[]; started_at: string | null }>({
    events: [],
    started_at: null,
  });
  const [eventsMissing, setEventsMissing] = useState(false);
  const [index, setIndex] = useState<ObjectiveIndex | null>(null);
  const [titles, setTitles] = useState<Map<string, string>>(new Map());
  const [error, setError] = useState<string | null>(null);
  const [readAt, setReadAt] = useState<Date | null>(null);
  const [view, setView] = useState<View>("all");
  const [kind, setKind] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [shown, setShown] = useState(PAGE);
  const lastSeq = useRef(0);

  const loadRecords = useCallback(async () => {
    if (base === null) return;
    try {
      const [log, feed] = await Promise.all([fetchLog(base), loadObjectives(base).catch(() => null)]);
      setRecords(log.records);
      setProblems(log.problems);
      // Titles only from a live answer: the snapshot's objectives are a
      // different log's, and naming this node's records after them would be
      // wrong in exactly the cases where the ids happened to collide.
      const live = feed?.live ? feed.objectives : [];
      setIndex(indexObjectives(live));
      setTitles(new Map(live.map((o) => [o.id, objectiveTitle(o)] as const)));
      setReadAt(new Date());
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, [base]);

  const loadEvents = useCallback(async () => {
    if (base === null) return;
    try {
      const page = await fetchEvents(base, lastSeq.current);
      if (page === null) {
        setEventsMissing(true);
        return;
      }
      // A restarted node numbers from 1 again; `absorb` notices by the start
      // time and the next ask starts from the new process's beginning.
      setEvents((held) => {
        const next = absorb(held, page);
        lastSeq.current = next.events.length ? next.events[next.events.length - 1].seq : 0;
        return next;
      });
    } catch {
      // The records are the page; a feed that did not answer this once is
      // asked again on the next tick.
    }
  }, [base]);

  // The log is the big read, and only grows: once a minute. The events are
  // a cursor over a small ring, so they can be asked for often.
  useEvery(loadRecords, 60, base !== null);
  useEvery(loadEvents, 10, base !== null);

  const items = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const recordsShown =
      view === "events"
        ? []
        : (records ?? []).filter((record) => {
            if (view === "records" && kind && record.kind !== kind) return false;
            if (!needle) return true;
            // The whole record, because the useful search here is "find the
            // line mentioning this id" and an id can appear in any field.
            return (
              record.hash.includes(needle) ||
              record.kind.toLowerCase().includes(needle) ||
              JSON.stringify(record.payload).toLowerCase().includes(needle)
            );
          });
    const eventsShown =
      view === "records"
        ? []
        : events.events.filter((event) => {
            if (view === "events" && kind && (KIND_LABEL[event.kind as keyof typeof KIND_LABEL] ?? event.kind) !== kind) {
              return false;
            }
            if (!needle) return true;
            return event.text.toLowerCase().includes(needle) || (event.subject ?? "").toLowerCase().includes(needle);
          });
    return timeline(recordsShown, eventsShown);
  }, [records, events, view, kind, query]);

  const recordKinds = useMemo(() => (records ? kindCounts(records) : []), [records]);
  const eventKinds = useMemo(() => {
    const counts = new Map<string, number>();
    for (const event of events.events) {
      const label = KIND_LABEL[event.kind as keyof typeof KIND_LABEL] ?? event.kind;
      counts.set(label, (counts.get(label) ?? 0) + 1);
    }
    return [...counts.entries()];
  }, [events]);
  const now = readAt?.getTime() ?? Date.now();

  const choose = (next: View) => {
    setView(next);
    setKind(null);
    setShown(PAGE);
  };

  return (
    <>
      <PageHeader
        title="Log"
        subtitle="Every record this node holds, and everything it saw happen around them — other nodes connecting, records syncing, machines and agents arriving. Newest first."
        actions={<LiveStamp at={readAt} error={records ? error : null} />}
      />

      <div className="flex flex-col gap-4">
        {error && !records && (
          <Note title="Could not read the log" tone="bad">
            {error}
          </Note>
        )}

        {/* Reported, not thrown: one bad line used to blank the whole page,
            which hid every good line and the fact that one was bad. */}
        {problems.length > 0 && (
          <Note title={`${problems.length} line${problems.length === 1 ? "" : "s"} could not be read as a record`} tone="bad">
            The rows below are the records this reader could parse. The unreadable entries are listed here for review.
            <ul className="mt-1.5 flex flex-col gap-0.5">
              {problems.map((problem) => (
                <li key={problem} className="mono text-[11.5px] text-ink-3">
                  {problem}
                </li>
              ))}
            </ul>
          </Note>
        )}

        {records === null && !error && <Skeleton className="h-64 w-full" />}

        {records !== null && (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <div className="segmented" role="group" aria-label="What to show">
                <button type="button" aria-pressed={view === "all"} onClick={() => choose("all")}>
                  Everything
                </button>
                <button type="button" aria-pressed={view === "records"} onClick={() => choose("records")}>
                  Records <span className="mono text-ink-3">{records.length}</span>
                </button>
                <button type="button" aria-pressed={view === "events"} onClick={() => choose("events")}>
                  Node events <span className="mono text-ink-3">{events.events.length}</span>
                </button>
              </div>
              <input
                className="field ml-auto max-w-64"
                value={query}
                onChange={(event) => {
                  setQuery(event.target.value);
                  setShown(PAGE);
                }}
                placeholder="search…"
                aria-label="Search the log"
              />
            </div>

            {view !== "all" && (view === "records" ? recordKinds.length : eventKinds.length) > 1 && (
              <div className="flex flex-wrap gap-1.5">
                {(view === "records" ? recordKinds : eventKinds).map(([name, count]) => (
                  <button
                    type="button"
                    key={name}
                    className={`btn btn-sm ${kind === name ? "btn-primary" : ""}`}
                    onClick={() => {
                      setKind(kind === name ? null : name);
                      setShown(PAGE);
                    }}
                  >
                    {name.replace(/_/g, " ")} <span className="mono">{count}</span>
                  </button>
                ))}
              </div>
            )}

            {view === "events" && eventsMissing ? (
              <EmptyState title="This node is older than its event feed">
                A node built with <span className="mono">GET /events</span> lists the other nodes it reached, the
                records it synced, and the machines and agents that arrived.
              </EmptyState>
            ) : items.length === 0 ? (
              <EmptyState title={query ? "Nothing matches." : view === "events" ? "Nothing has happened yet." : "This node's log is empty."}>
                {view === "events" && !query
                  ? "Other nodes connecting, machines and agents arriving and records syncing appear here as they happen."
                  : null}
              </EmptyState>
            ) : (
              <Card className="overflow-hidden">
                <ul className="divide-edge-y">
                  {items.slice(0, shown).map((item) => {
                    if (item.type === "event") {
                      return <NodeEventRow key={`e${item.event.seq}`} event={item.event} now={now} />;
                    }
                    const event = toEvent(item.record, index);
                    return (
                      <EventRow
                        key={`r${item.record.seq}`}
                        event={event}
                        record={item.record}
                        objectiveTitle={event.objectiveId ? titles.get(event.objectiveId) : null}
                        now={now}
                      />
                    );
                  })}
                </ul>
                {items.length > shown && (
                  <div className="border-t border-edge px-4 py-2.5 text-center">
                    <button type="button" className="btn btn-sm" onClick={() => setShown(shown + PAGE)}>
                      Show {Math.min(PAGE, items.length - shown)} more of {items.length - shown}
                    </button>
                  </div>
                )}
              </Card>
            )}

            <p className="text-[12px] text-ink-3">
              A filled dot is a record in the log, re-derivable by anyone who has it. A ring is something this node saw
              and holds in memory only: nobody checks it, and it is gone when the node restarts.
            </p>
          </>
        )}
      </div>
    </>
  );
}
