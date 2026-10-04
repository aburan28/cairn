"use client";

/**
 * The log as a feed: one line per thing that happened, in words.
 *
 * Shared by `/log`, a challenge's Activity, and the Overview's Following box,
 * so the three cannot drift into three readings of the same record. The
 * record itself stays one click away -- the expanded row shows its fields
 * labelled, and the exact JSON the node wrote behind a further toggle,
 * because "what did the node actually store" is still a question this site
 * must answer, just not the first one.
 */

import Link from "next/link";
import { useState } from "react";
import { type LogEvent, ago } from "@/lib/events";
import type { LogRecord } from "@/lib/log";
import { Hash } from "@/components/ui";

const DOT: Record<LogEvent["tone"], string> = {
  neutral: "bg-ink-3",
  good: "bg-accent",
  bad: "bg-bad",
  warn: "bg-warn",
};

export function EventRow({
  event,
  record,
  objectiveTitle,
  now,
}: {
  event: LogEvent;
  /** The record as written, for the raw view. Omit to hide it. */
  record?: LogRecord;
  /** A title for the event's objective, to name it inline. Omit on a page
   *  that is already about one objective. */
  objectiveTitle?: string | null;
  now: number;
}) {
  const [open, setOpen] = useState(false);
  const [raw, setRaw] = useState(false);
  // A sentence that starts with its actor reads "alice was paid"; the ones
  // with no actor ("Epoch 7 closed") carry their own subject.
  const sentence = (
    <>
      {event.actor && (
        <span className="mono font-semibold text-ink" title={event.actor}>
          {shortActor(event.actor)}
        </span>
      )}{" "}
      <span className="text-ink">{event.action}</span>
      {event.detail && <span className="text-ink-3"> · {event.detail}</span>}
      {objectiveTitle && event.objectiveId && (
        <>
          <span className="text-ink-3"> on </span>
          <Link
            href={`/challenge?id=${encodeURIComponent(event.objectiveId)}`}
            className="text-ink-2 underline decoration-edge-strong underline-offset-2 hover:text-ink"
            onClick={(e) => e.stopPropagation()}
          >
            {objectiveTitle}
          </Link>
        </>
      )}
    </>
  );

  return (
    <li className="contain-rows">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        className="flex w-full cursor-pointer items-start gap-3 px-4 py-2.5 text-left transition-colors hover:bg-surface-2"
      >
        <span className={`mt-[7px] h-2 w-2 shrink-0 rounded-full ${DOT[event.tone]}`} aria-hidden />
        <span className="min-w-0 flex-1 text-[13px] leading-relaxed [overflow-wrap:anywhere]">
          {sentence}
        </span>
        {event.amount !== null && (
          <span className="shrink-0 text-right">
            <span className="mono block text-[13px] text-ink">
              {event.amount.toLocaleString("en-US")}
            </span>
            {event.amountLabel && (
              <span className="block text-[10.5px] text-ink-3">{event.amountLabel}</span>
            )}
          </span>
        )}
        <span
          className="w-20 shrink-0 text-right text-[11.5px] whitespace-nowrap text-ink-3"
          title={event.ts}
        >
          {ago(event.ts, now)}
        </span>
      </button>
      {open && (
        <div className="border-t border-edge bg-surface-2 px-4 py-3 pl-9">
          <dl className="kv text-[12px]">
            <dt>entry</dt>
            <dd className="mono">#{event.seq}</dd>
            <dt>kind</dt>
            <dd className="mono">{event.kind}</dd>
            <dt>time</dt>
            <dd className="mono">{event.ts}</dd>
            {event.fields.map(([label, value]) => (
              <FieldRow key={label} label={label} value={value} />
            ))}
          </dl>
          {record && (
            <div className="mt-3">
              <button
                type="button"
                className="text-[12px] text-ink-3 underline underline-offset-2 hover:text-ink"
                onClick={() => setRaw(!raw)}
              >
                {raw ? "Hide the record as written" : "Show the record as written"}
              </button>
              {raw && (
                <pre className="code mt-2 max-h-96 overflow-auto text-[11.5px]">
                  {JSON.stringify(record, null, 2)}
                </pre>
              )}
            </div>
          )}
        </div>
      )}
    </li>
  );
}

function FieldRow({ label, value }: { label: string; value: string }) {
  const hashy = /^sha256:[0-9a-f]{16,}$/.test(value) || /^[0-9a-f]{40,}$/.test(value);
  return (
    <>
      <dt>{label}</dt>
      <dd className={hashy ? "" : "mono [overflow-wrap:anywhere]"}>
        {hashy ? <Hash value={value} chars={10} /> : value}
      </dd>
    </>
  );
}

/** A 64-hex key reads as `a1b2c3d4…ef01`; a pseudonym reads as itself. */
export function shortActor(actor: string): string {
  return /^[0-9a-f]{40,}$/i.test(actor) ? `${actor.slice(0, 8)}…${actor.slice(-4)}` : actor;
}
