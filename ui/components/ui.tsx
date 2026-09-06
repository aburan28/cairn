"use client";

/**
 * The small pieces every page here is built from.
 *
 * Hand-written rather than imported, for the reason the stylesheet gives at
 * length: `build.rs` puts this app inside every `cairn` binary, and a headless
 * component library would add runtime JavaScript to a set of controls that
 * amount to a button, a copyable hash and a progress bar. Tailwind earns its
 * place because it compiles away; a component runtime would not.
 *
 * The pieces that *are* here exist because the same mistake was being made in
 * several files at once — a truncated hash with no way to get the whole of it,
 * a loading state that shifted the layout, an error rendered as bare text.
 */

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

type Tone = "neutral" | "accent" | "warn" | "bad" | "info";

const TONE: Record<Tone, string> = {
  neutral: "badge",
  accent: "badge badge-accent",
  warn: "badge badge-warn",
  bad: "badge badge-bad",
  info: "badge badge-info",
};

export function Badge({
  tone = "neutral",
  children,
  title,
}: {
  tone?: Tone;
  children: React.ReactNode;
  title?: string;
}) {
  return (
    <span className={TONE[tone]} title={title}>
      {children}
    </span>
  );
}

export function Card({
  children,
  className = "",
  as: Tag = "div",
}: {
  children: React.ReactNode;
  className?: string;
  as?: "div" | "section" | "li" | "article";
}) {
  return <Tag className={`card ${className}`}>{children}</Tag>;
}

/**
 * A titled aside. `tone` carries the same meaning as everywhere else, and the
 * left rule is what makes a warning distinguishable from a note at a glance
 * rather than only on reading it.
 */
export function Note({
  title,
  tone = "accent",
  children,
}: {
  title?: string;
  tone?: "accent" | "warn" | "bad";
  children: React.ReactNode;
}) {
  const extra = tone === "bad" ? "note-bad" : tone === "warn" ? "note-warn" : "";
  return (
    <div className={`note ${extra}`} role={tone === "bad" ? "alert" : undefined}>
      {title && (
        <div
          className={`note-title ${tone === "bad" ? "text-bad" : tone === "warn" ? "text-warn" : ""}`}
        >
          {title}
        </div>
      )}
      <div className="text-[13px] leading-relaxed text-ink-2">{children}</div>
    </div>
  );
}

/**
 * One number, with where it came from.
 *
 * The provenance line is not decoration. Every figure on this site is either
 * from a live node or from the settled log that ships in the repository, and a
 * page that showed the number without saying which would be making a claim it
 * had not checked.
 */
export function Stat({
  label,
  value,
  from,
  hint,
}: {
  label: string;
  value: string;
  from?: string;
  hint?: string;
}) {
  return (
    <div className="card card-pad min-w-0 flex-1">
      <div className="text-[11px] font-medium tracking-[0.06em] text-ink-3 uppercase">
        {label}
      </div>
      <div className="mono mt-1 text-[22px] leading-none font-semibold" title={hint}>
        {value}
      </div>
      {from && <div className="mt-2 truncate text-[11px] text-ink-3">{from}</div>}
    </div>
  );
}

/**
 * A hash, id or key: shortened for reading, complete on copy.
 *
 * Truncation without a way back to the whole string is the single most
 * annoying thing a page like this can do — the reason to look at an id is
 * almost always to compare it with one somewhere else.
 */
export function Hash({
  value,
  href,
  chars = 10,
  label,
}: {
  value: string;
  href?: string;
  chars?: number;
  label?: string;
}) {
  const bare = value.replace(/^sha256:/, "");
  const shown = bare.length > chars * 2 ? `${bare.slice(0, chars)}…${bare.slice(-4)}` : bare;
  const body = (
    <span className="mono text-[12px]" title={value}>
      {shown}
    </span>
  );
  return (
    <span className="inline-flex max-w-full items-center gap-1">
      {label && <span className="text-[11px] text-ink-3">{label}</span>}
      {href ? (
        <Link href={href} className="text-accent hover:underline">
          {body}
        </Link>
      ) : (
        body
      )}
      <CopyButton value={value} />
    </span>
  );
}

/**
 * Copy to clipboard, with the confirmation the action otherwise lacks.
 *
 * `navigator.clipboard` is unavailable on an insecure origin, which is the
 * common case here — an operator on `http://10.0.0.4:8080`. So the failure
 * path selects the text instead of silently doing nothing.
 */
export function CopyButton({ value, className = "" }: { value: string; className?: string }) {
  const [done, setDone] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => void (timer.current && clearTimeout(timer.current)), []);

  return (
    <button
      type="button"
      aria-label={done ? "copied" : "copy"}
      title={done ? "copied" : "copy"}
      className={`inline-flex h-5 w-5 shrink-0 cursor-pointer items-center justify-center rounded
                  text-ink-3 transition-colors hover:bg-surface-2 hover:text-ink ${className}`}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
        } catch {
          // No clipboard on this origin. Say so rather than pretending.
          window.prompt("Copy this:", value);
          return;
        }
        setDone(true);
        if (timer.current) clearTimeout(timer.current);
        timer.current = setTimeout(() => setDone(false), 1400);
      }}
    >
      {done ? <CheckIcon /> : <CopyIcon />}
    </button>
  );
}

/**
 * A ratchet's travel from baseline to target.
 *
 * Two quantities, not one: how far the frontier has moved, and how much of the
 * pool that has already cost. They are not the same number — telescoping pays
 * along the curve — and showing only the first would suggest a pool is intact
 * when it is half spent.
 */
export function Progress({
  value,
  label,
  tone = "accent",
}: {
  value: number;
  label?: string;
  tone?: "accent" | "warn";
}) {
  const pct = Math.max(0, Math.min(1, Number.isFinite(value) ? value : 0));
  return (
    <div>
      {label && (
        <div className="mb-1 flex items-baseline justify-between gap-2 text-[11px] text-ink-3">
          <span>{label}</span>
          <span className="mono">{(pct * 100).toFixed(0)}%</span>
        </div>
      )}
      <div
        className="h-1.5 w-full overflow-hidden rounded-full bg-surface-3"
        role="progressbar"
        aria-valuenow={Math.round(pct * 100)}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={label}
      >
        <div
          className={`h-full rounded-full transition-[width] duration-500 ease-[var(--ease-out-quint)] ${
            tone === "warn" ? "bg-warn" : "bg-accent"
          }`}
          style={{ width: `${pct * 100}%` }}
        />
      </div>
    </div>
  );
}

export function EmptyState({
  title,
  children,
  action,
}: {
  title: string;
  children?: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <div className="card flex flex-col items-center gap-2 px-6 py-12 text-center">
      <div className="text-[14px] font-medium text-ink">{title}</div>
      {children && <div className="max-w-[46ch] text-[13px] text-ink-2">{children}</div>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

/**
 * A placeholder the same height as the thing it stands in for.
 *
 * Loading states that collapse and then push the page down when data arrives
 * are worse than a spinner, because the reader has already started reading.
 */
export function Skeleton({ className = "h-4 w-24" }: { className?: string }) {
  return <div className={`skeleton ${className}`} aria-hidden />;
}

export function SectionHeading({
  children,
  count,
  aside,
}: {
  children: React.ReactNode;
  count?: number;
  aside?: React.ReactNode;
}) {
  return (
    <div className="mb-3 flex items-baseline justify-between gap-3">
      <h2 className="text-[13px] font-semibold tracking-[0.06em] text-ink-2 uppercase">
        {children}
        {count !== undefined && <span className="mono ml-2 text-ink-3">{count}</span>}
      </h2>
      {aside}
    </div>
  );
}

// -- icons ------------------------------------------------------------------
//
// Inline SVG, because an icon font is a font and this app loads none. Each is
// the smallest path that reads at 14px.

function CopyIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden>
      <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" stroke="currentColor" />
      <path d="M10.5 3.5V3a1.5 1.5 0 0 0-1.5-1.5H4A1.5 1.5 0 0 0 2.5 3v5A1.5 1.5 0 0 0 4 9.5h.5" stroke="currentColor" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden>
      <path d="m3.5 8.5 3 3 6-7" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
