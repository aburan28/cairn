"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  type LogRecord,
  NODE_URL,
  fetchLog,
  kindCounts,
  pretty,
  short,
  summarize,
} from "@/lib/log";

/**
 * Every record this node holds, in the order it admitted them.
 *
 * This is the file `cairn audit` reads and every other page here derives
 * its numbers from — the one thing on the site you have to fetch rather
 * than compute. Filtering and the `says` column happen in the browser; the
 * record shown on expansion is exactly the line the node wrote.
 */
export default function Page() {
  const [base, setBase] = useState(NODE_URL);
  const [records, setRecords] = useState<LogRecord[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);

  const load = useCallback(async (url: string) => {
    setLoading(true);
    setError(null);
    try {
      const next = await fetchLog(url);
      setRecords(next);
      setFilter(null);
      setExpanded(null);
    } catch (cause) {
      setRecords(null);
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
  const visible = useMemo(
    () => (records ? (filter ? records.filter((r) => r.kind === filter) : records) : []),
    [records, filter],
  );

  return (
    <main>
      <h1>log</h1>
      <p className="lede">
        Every record this node holds, in the order it admitted them. This is
        the file <code>cairn audit</code> reads, and the one thing here you
        have to fetch — everything else on this site is derived from it.
        Click a row for the record as written.
      </p>

      <div className="row">
        <input
          className="input"
          value={base}
          onChange={(event) => setBase(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") void load(base);
          }}
          aria-label="Node URL"
          spellCheck={false}
        />
        <button className="button" onClick={() => void load(base)} disabled={loading}>
          {loading ? "reading…" : "read"}
        </button>
      </div>

      {error && (
        <div className="panel bad">
          <b>could not read the log</b>
          {error}
        </div>
      )}

      {records && records.length === 0 && (
        <p className="empty">This node&apos;s log is empty.</p>
      )}

      {records && records.length > 0 && (
        <>
          <div className="tags" style={{ marginBottom: "1rem" }}>
            <button
              type="button"
              className={filter === null ? "tag open" : "tag"}
              onClick={() => setFilter(null)}
            >
              all {records.length}
            </button>
            {counts.map(([kind, count]) => (
              <button
                type="button"
                key={kind}
                className={filter === kind ? "tag open" : "tag"}
                onClick={() => setFilter(filter === kind ? null : kind)}
              >
                {kind} {count}
              </button>
            ))}
          </div>

          <div className="tableWrap">
            <table className="grid">
              <thead>
                <tr>
                  <th>seq</th>
                  <th>kind</th>
                  <th>id</th>
                  <th>says</th>
                </tr>
              </thead>
              <tbody>
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
          <p className="meta dim">
            &ldquo;says&rdquo; is this page&apos;s own one-line reading of the
            payload, not a field the node wrote. The record itself is what
            expands.
          </p>
        </>
      )}
    </main>
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
        style={{ cursor: "pointer", background: expanded ? "var(--panel)" : undefined }}
      >
        <td className="dim">{record.seq}</td>
        <td>
          <span className="tag">{record.kind}</span>
        </td>
        <td>
          <code className="dim" title={record.hash}>
            {short(record.hash)}
          </code>
        </td>
        <td>{summarize(record)}</td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={4} style={{ background: "var(--panel)" }}>
            <pre>{pretty(record)}</pre>
          </td>
        </tr>
      )}
    </>
  );
}
