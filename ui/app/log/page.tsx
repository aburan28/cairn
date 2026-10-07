"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { type LogRecord, NODE_URL, fetchLog, kindCounts } from "@/lib/log";
import { type ObjectiveIndex, indexObjectives, toEvent } from "@/lib/events";
import { type Session, fetchSessions, reachTone } from "@/lib/network";
import { objectiveTitle } from "@/lib/title";
import { Badge, Box, Card, EmptyState, Hash, NodeSource, Note, PageHeader } from "@/components/ui";
import { EventRow } from "@/components/events";
import { loadObjectives, resolveNode } from "@/lib/site";
import { formatAge } from "@/lib/progress";

/**
 * Every record this node holds, as a feed of what happened.
 *
 * This is the file `cairn audit` reads and every other page here derives its
 * numbers from. It used to render as a table whose rows expanded into the
 * pretty-printed payload, which made a person read JSON to learn that alice
 * was paid. Each record is now a sentence (`lib/events.ts`), newest first,
 * naming the challenge it belongs to; expanding one shows its fields
 * labelled, and the exact record the node wrote is one further click.
 * Filtering and search still run over the records themselves.
 */
export default function Page() {
  const [base, setBase] = useState(NODE_URL);
  const [records, setRecords] = useState<LogRecord[] | null>(null);
  const [problems, setProblems] = useState<string[]>([]);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [sessionsAvailable, setSessionsAvailable] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [index, setIndex] = useState<ObjectiveIndex | null>(null);
  const [titles, setTitles] = useState<Map<string, string>>(new Map());
  const [now, setNow] = useState(() => Date.now());

  const load = useCallback(async (url: string) => {
    setLoading(true);
    setError(null);
    try {
      const [next, feed, roster] = await Promise.all([
        fetchLog(url),
        loadObjectives(url).catch(() => null),
        fetchSessions(url).catch(() => null),
      ]);
      setRecords(next.records);
      setProblems(next.problems);
      setSessions(roster?.available ? roster.peers : []);
      setSessionsAvailable(roster ? roster.available : null);
      setFilter(null);
      // Titles only from a live answer: the snapshot's objectives are a
      // different log's, and naming this node's records after them would be
      // wrong in exactly the cases where the ids happened to collide.
      const live = feed?.live ? feed.objectives : [];
      setIndex(indexObjectives(live));
      setTitles(new Map(live.map((o) => [o.id, objectiveTitle(o)] as const)));
      setNow(Date.now());
    } catch (cause) {
      setRecords(null);
      setProblems([]);
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // Ask which node to read before reading it. Same-origin when one answers --
    // the daemon serves this page at /ui/, so that is the common case and it
    // costs one /health -- and otherwise the first seed from the published list
    // that is up. On the public site there is no same-origin node at all, and
    // before this the box showed github.io and every request 404'd into the
    // snapshot.
    //
    // Shown *and* used, which is the part worth being careful about: the box
    // has to name the origin the numbers below came from, or a reader comparing
    // two nodes is comparing one node against a label. Empty stays empty for
    // fetching -- relative requests survive a tunnel or a proxy on an unknown
    // path -- and becomes this page's own origin for display, because nobody
    // can retype "" after clearing the box.
    void resolveNode().then((url) => {
      setBase(url || window.location.origin);
      void load(url);
    });
  }, [load]);

  const counts = useMemo(() => (records ? kindCounts(records) : []), [records]);
  const visible = useMemo(() => {
    if (!records) return [];
    const needle = query.trim().toLowerCase();
    return [...records].reverse().filter((record) => {
      if (filter && record.kind !== filter) return false;
      if (!needle) return true;
      // The whole record, because the useful search here is "find the line
      // mentioning this id" and an id can appear in any field of any kind.
      return (
        record.hash.includes(needle) ||
        record.kind.toLowerCase().includes(needle) ||
        JSON.stringify(record.payload).toLowerCase().includes(needle)
      );
    });
  }, [records, filter, query]);

  return (
    <>
      <PageHeader
        title="Log"
        subtitle="Every record this node holds, newest first. Click an event for its details and the record as written."
        actions={
          <NodeSource
            value={base}
            onChange={setBase}
            onRead={() => void load(base === window.location.origin ? "" : base)}
            loading={loading}
          />
        }
      />


      <div className="flex flex-col gap-4">
        {error && (
          <Note title="could not read the log" tone="bad">
            {error}
          </Note>
        )}

        {/* Reported, not thrown: one bad line used to blank the whole page,
            which hid every good line and the fact that one was bad. */}
        {problems.length > 0 && (
          <Note
            title={`${problems.length} line${problems.length === 1 ? "" : "s"} could not be read as a record`}
            tone="bad"
          >
            The rows below are the lines that could.{" "}
            <code className="mono">cairn audit</code> reads the same file; run it to see
            what it makes of them.
            <ul className="mt-1.5 flex flex-col gap-0.5">
              {problems.map((problem) => (
                <li key={problem} className="mono text-[11.5px] text-ink-3">
                  {problem}
                </li>
              ))}
            </ul>
          </Note>
        )}

        <NetworkActivity peers={sessions} available={sessionsAvailable} />

        {records && records.length === 0 && problems.length === 0 && (
          <EmptyState title="This node's log is empty." />
        )}

        {records && records.length > 0 && (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                className={`btn btn-sm ${filter === null ? "btn-primary" : ""}`}
                onClick={() => setFilter(null)}
              >
                all <span className="mono">{records.length}</span>
              </button>
              {counts.map(([kind, count]) => (
                <button
                  type="button"
                  key={kind}
                  className={`btn btn-sm ${filter === kind ? "btn-primary" : ""}`}
                  onClick={() => setFilter(filter === kind ? null : kind)}
                >
                  {kind.replace(/_/g, " ")} <span className="mono">{count}</span>
                </button>
              ))}
              <input
                className="field ml-auto max-w-64"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="search every field…"
                aria-label="Search the log"
              />
            </div>

            <Card className="overflow-hidden">
              <ul className="divide-edge-y">
                {visible.map((record) => {
                  const event = toEvent(record, index);
                  return (
                    <EventRow
                      key={record.seq}
                      event={event}
                      record={record}
                      objectiveTitle={event.objectiveId ? titles.get(event.objectiveId) : null}
                      now={now}
                    />
                  );
                })}
              </ul>
              {visible.length === 0 && (
                <p className="px-4 py-8 text-center text-[13px] text-ink-3">
                  Nothing matches.
                </p>
              )}
            </Card>

            <p className="text-[12px] text-ink-3">
              The sentences are this page&rsquo;s reading of each record, not fields the node
              wrote. The record itself is under each event.
            </p>
          </>
        )}
      </div>
    </>
  );
}

/**
 * Connections this run, beside the log — never inside it.
 *
 * The feed above is the file `cairn audit` reads, and mixing in anything the
 * node did not write would break that. But "connected to a peer" is still
 * something an operator wants to see next to the records, so the sessions
 * the node holds in memory sit here, labelled as memory: they vanish on
 * restart and prove nothing to anyone else.
 */
function NetworkActivity({ peers, available }: { peers: Session[]; available: boolean | null }) {
  if (available === false) return null;
  if (available === null) return null;
  const ordered = [...peers].sort((a, b) => {
    const rank = (s: Session["status"]) =>
      s === "reached" ? 0 : s === "recent" ? 1 : s === "lost" ? 2 : 3;
    return rank(a.status) - rank(b.status);
  });
  return (
    <Box
      title="Network activity"
      aside={<span className="text-[11px] font-normal text-warn">this run only, not in the log</span>}
    >
      {ordered.length === 0 ? (
        <p className="text-[12.5px] text-ink-3">
          No peer session yet this run. Connections appear here as they happen; what was
          settled is in the feed below.{" "}
          <Link href="/network" className="text-accent hover:underline">
            Full network view →
          </Link>
        </p>
      ) : (
        <ul className="flex flex-col gap-2">
          {ordered.slice(0, 8).map((peer) => (
            <li key={peer.peer_id} className="flex flex-wrap items-baseline gap-x-2 gap-y-1 text-[12.5px]">
              <Badge tone={reachTone(peer.status)}>{peer.status}</Badge>
              <Hash value={peer.peer_id} chars={8} />
              <span className="text-ink-3">
                {peer.age_seconds !== null ? (
                  <>
                    last session {formatAge(peer.age_seconds)} ago {peer.last_direction}
                    {peer.entries_after !== null && <> · log at {peer.entries_after} entries after</>}
                  </>
                ) : peer.last_error ? (
                  <>never connected · {peer.last_error}</>
                ) : (
                  <>never connected</>
                )}
              </span>
            </li>
          ))}
        </ul>
      )}
      {ordered.length > 8 && (
        <p className="mt-2 text-[12px] text-ink-3">
          and {ordered.length - 8} more —{" "}
          <Link href="/network" className="text-accent hover:underline">
            all connections
          </Link>
          .
        </p>
      )}
    </Box>
  );
}
