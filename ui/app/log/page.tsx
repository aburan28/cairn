"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  type LogRecord,
  NODE_URL,
  fetchLog,
  kindCounts,
  pretty,
  summarize,
} from "@/lib/log";
import { Badge, Card, EmptyState, Hash, Note } from "@/components/ui";

/**
 * Every record this node holds, in the order it admitted them.
 *
 * This is the file `cairn audit` reads and every other page here derives its
 * numbers from — the one thing on the site you have to fetch rather than
 * compute. Filtering, search and the `says` column happen in the browser; the
 * record shown on expansion is exactly the line the node wrote.
 */
export default function Page() {
  const [base, setBase] = useState(NODE_URL);
  const [records, setRecords] = useState<LogRecord[] | null>(null);
  const [problems, setProblems] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState<number | null>(null);

  const load = useCallback(async (url: string) => {
    setLoading(true);
    setError(null);
    try {
      const next = await fetchLog(url);
      setRecords(next.records);
      setProblems(next.problems);
      setFilter(null);
      setExpanded(null);
    } catch (cause) {
      setRecords(null);
      setProblems([]);
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // Show *which* origin, rather than the empty string NODE_URL now holds.
    // Empty is right for fetching -- it keeps every request relative, so the
    // page works behind a tunnel or a proxy on an unknown path -- and wrong for
    // displaying, because nobody can retype "" after they clear the box.
    setBase(NODE_URL || window.location.origin);
    void load(NODE_URL);
  }, [load]);

  const counts = useMemo(() => (records ? kindCounts(records) : []), [records]);
  const visible = useMemo(() => {
    if (!records) return [];
    const needle = query.trim().toLowerCase();
    return records.filter((record) => {
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
      <header className="mb-6 max-w-[62rem]">
        <h1 className="text-[26px] font-semibold">Log</h1>
        <p className="prose-block mt-2">
          Every record this node holds, in the order it admitted them. This is the
          file <code className="mono">cairn audit</code> reads, and the one thing here
          you have to fetch — everything else on this site is derived from it. Click a
          row for the record as written.
        </p>
      </header>

      <Card className="card-pad mb-4">
        <label className="label" htmlFor="node">
          Node
        </label>
        <div className="flex flex-wrap gap-2">
          <input
            id="node"
            className="field field-mono flex-1"
            value={base}
            onChange={(event) => setBase(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") void load(base);
            }}
            spellCheck={false}
          />
          <button className="btn" onClick={() => void load(base)} disabled={loading}>
            {loading ? "reading…" : "Read"}
          </button>
        </div>
      </Card>

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
                  {kind} <span className="mono">{count}</span>
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
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-left text-[12.5px]">
                  <thead>
                    <tr className="border-b border-edge bg-surface-2">
                      <th className="px-3 py-2 font-medium text-ink-2">seq</th>
                      <th className="px-3 py-2 font-medium text-ink-2">kind</th>
                      <th className="px-3 py-2 font-medium text-ink-2">id</th>
                      <th className="px-3 py-2 font-medium text-ink-2">says</th>
                    </tr>
                  </thead>
                  <tbody className="divide-edge-y">
                    {visible.map((record) => (
                      <Row
                        key={record.seq}
                        record={record}
                        expanded={expanded === record.seq}
                        onToggle={() =>
                          setExpanded(expanded === record.seq ? null : record.seq)
                        }
                      />
                    ))}
                  </tbody>
                </table>
              </div>
              {visible.length === 0 && (
                <p className="px-4 py-8 text-center text-[13px] text-ink-3">
                  No record matches.
                </p>
              )}
            </Card>

            <p className="text-[12px] text-ink-3">
              &ldquo;says&rdquo; is this page&rsquo;s own one-line reading of the
              payload, not a field the node wrote. The record itself is what expands.
            </p>
          </>
        )}
      </div>
    </>
  );
}

function Row({
  record,
  expanded,
  onToggle,
}: {
  record: LogRecord;
  expanded: boolean;
  onToggle: () => void;
}) {
  return (
    <>
      <tr
        onClick={onToggle}
        aria-expanded={expanded}
        className={`contain-rows cursor-pointer transition-colors hover:bg-surface-2 ${
          expanded ? "bg-surface-2" : ""
        }`}
      >
        <td className="mono px-3 py-1.5 text-ink-3">{record.seq}</td>
        <td className="px-3 py-1.5">
          <Badge>{record.kind}</Badge>
        </td>
        <td className="px-3 py-1.5">
          <Hash value={record.hash} chars={8} />
        </td>
        <td className="px-3 py-1.5 text-ink-2">{summarize(record)}</td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={4} className="bg-surface-2 px-3 py-2">
            <pre className="code max-h-96 overflow-auto">{pretty(record)}</pre>
          </td>
        </tr>
      )}
    </>
  );
}
