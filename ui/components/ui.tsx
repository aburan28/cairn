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

type Tone = "neutral" | "accent" | "warn" | "bad";

const TONE: Record<Tone, string> = {
  neutral: "badge",
  accent: "badge badge-accent",
  warn: "badge badge-warn",
  bad: "badge badge-bad",
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

/**
 * An enrolled fleet member: the node verified this row's request against a
 * key its operator invited (`cairn fleet join`). A name with no badge said
 * whatever it liked; this one proved it.
 */
export function MemberBadge({ member }: { member?: boolean }) {
  if (!member) return null;
  return (
    <span
      className="badge badge-accent ml-1.5 align-middle"
      title="An enrolled fleet member: this node checked the request's signature against a machine its operator invited"
    >
      member
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
  tone = "neutral",
}: {
  label: string;
  value: string;
  from?: string;
  hint?: string;
  tone?: "neutral" | "accent" | "warn" | "bad";
}) {
  return (
    <div className={`tile tile-${tone} flex-1`}>
      <div className="text-[11.5px] font-medium text-ink-2">{label}</div>
      <div
        className="tile-value mono mt-1 truncate text-[22px] leading-tight font-semibold"
        title={hint ?? value}
      >
        {value}
      </div>
      {from && <div className="mt-1 truncate text-[11px] text-ink-3">{from}</div>}
    </div>
  );
}

/**
 * A page's title, one line saying what it is for, and its controls.
 *
 * One line, not a paragraph. The explanations that used to open every page
 * are true and are still on `/how-it-works`; repeated above every readout
 * they pushed the data below the fold of a laptop window.
 */
export function PageHeader({
  title,
  subtitle,
  meta,
  actions,
  crumb,
}: {
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  meta?: React.ReactNode;
  actions?: React.ReactNode;
  crumb?: { href: string; label: string };
}) {
  return (
    <header className="mb-5 flex flex-wrap items-start gap-x-6 gap-y-3">
      <div className="min-w-0 flex-1">
        {crumb && (
          <Link
            href={crumb.href}
            className="mb-1 inline-flex items-center gap-1 text-[12px] text-ink-3 hover:text-ink"
          >
            ← {crumb.label}
          </Link>
        )}
        <h1 className="text-[22px] leading-tight font-semibold [overflow-wrap:anywhere]">
          {title}
        </h1>
        {subtitle && <p className="mt-1 max-w-[80ch] text-[13px] text-ink-2">{subtitle}</p>}
        {meta && (
          <div className="mt-2 flex flex-wrap items-center gap-2 text-[12.5px] text-ink-2">
            {meta}
          </div>
        )}
      </div>
      {actions && (
        <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto">{actions}</div>
      )}
    </header>
  );
}

/**
 * Which node this page reads, retargetable without a redeploy: comparing one
 * node's answer against a peer's is the whole value of the box. It sits in the
 * page header's corner, not in a full-width card above the data.
 */
export function NodePicker({
  value,
  onChange,
  onRead,
  loading,
}: {
  value: string;
  onChange: (next: string) => void;
  onRead: () => void;
  loading: boolean;
}) {
  return (
    <form
      className="flex w-full items-center gap-1.5 sm:w-auto"
      onSubmit={(event) => {
        event.preventDefault();
        onRead();
      }}
    >
      <label htmlFor="node" className="text-[12px] text-ink-3">
        Node
      </label>
      <input
        id="node"
        className="field field-mono min-w-0 flex-1 py-1.5 sm:w-64 sm:flex-none"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        spellCheck={false}
        title="Read another node without a redeploy"
      />
      <button className="btn btn-sm py-1.5" type="submit" disabled={loading}>
        {loading ? "Reading…" : "Read"}
      </button>
    </form>
  );
}

/**
 * Which node this page reads, in one quiet line.
 *
 * Most readers never retarget: the node that served the page is the node to
 * read. `NodePicker` puts a URL box and a Read button in the header of every
 * page, which is the right control for comparing two nodes and visual noise
 * for everyone else. This shows the provenance as text — "this node", or the
 * origin — with the retarget box folded behind a Change button. Same
 * capability, none of the chrome. Pages whose whole point is comparison
 * (objectives, network) keep the full picker.
 */
export function NodeSource({
  value,
  onChange,
  onRead,
  loading,
}: {
  value: string;
  onChange: (next: string) => void;
  onRead: () => void;
  loading: boolean;
}) {
  const [open, setOpen] = useState(false);
  const display =
    value === "" || (typeof window !== "undefined" && value === window.location.origin)
      ? "this node"
      : value;
  if (!open) {
    return (
      <p className="text-[12px] text-ink-3">
        Reading from <span className="mono text-ink-2">{display}</span>{" "}
        <button
          type="button"
          className="cursor-pointer text-accent hover:underline"
          onClick={() => setOpen(true)}
        >
          Change
        </button>
      </p>
    );
  }
  return (
    <form
      className="flex items-center gap-1.5"
      onSubmit={(event) => {
        event.preventDefault();
        onRead();
        setOpen(false);
      }}
    >
      <label htmlFor="node" className="text-[12px] text-ink-3">
        Node
      </label>
      <input
        id="node"
        className="field field-mono min-w-0 flex-1 py-1.5 sm:w-64 sm:flex-none"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        spellCheck={false}
        // biome-ignore lint/a11y/noAutofocus: opened by an explicit click, so focus belongs here.
        autoFocus
      />
      <button className="btn btn-sm py-1.5" type="submit" disabled={loading}>
        {loading ? "Reading…" : "Read"}
      </button>
      <button type="button" className="btn btn-sm btn-ghost py-1.5" onClick={() => setOpen(false)}>
        Cancel
      </button>
    </form>
  );
}

/** A titled box of facts. See `.box` in the stylesheet. */
export function Box({
  title,
  aside,
  children,
  className = "",
  flush = false,
}: {
  title?: React.ReactNode;
  aside?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  /** No body padding: for a table or tabs that draw their own. */
  flush?: boolean;
}) {
  return (
    <section className={`box ${className}`}>
      {title && (
        <div className="box-head">
          <span className="min-w-0 flex-1 truncate">{title}</span>
          {aside}
        </div>
      )}
      {flush ? children : <div className="box-body">{children}</div>}
    </section>
  );
}

/** Open or settled, the node's word for it, as a pill. */
export function StatusPill({ settled }: { settled: boolean }) {
  return (
    <span className={`pill ${settled ? "pill-settled" : "pill-open"}`}>
      {settled ? "Settled" : "Open"}
    </span>
  );
}

/**
 * A hash, id or key: shortened for reading, complete on copy.
 *
 * Truncation without a way back to the whole string is the single most
 * annoying thing a page like this can do — the reason to look at an id is
 * almost always to compare it with one somewhere else.
 *
 * `null` is a value with nothing to compare: a fresh node's checkpoint signs
 * an empty log, so its root and head are null, and that rendered as a crash
 * (`value.replace` on `null`) on every new node's landing page. An absent
 * value is an em-dash with no copy button, not an empty string that looks
 * like a hash got lost.
 */
export function Hash({
  value,
  href,
  chars = 10,
  label,
}: {
  value: string | null | undefined;
  href?: string;
  chars?: number;
  label?: string;
}) {
  if (value == null) {
    return (
      <span className="inline-flex max-w-full items-center gap-1">
        {label && <span className="text-[11px] text-ink-3">{label}</span>}
        <span className="mono whitespace-nowrap text-[12px] text-ink-3">—</span>
      </span>
    );
  }
  const bare = value.replace(/^sha256:/, "");
  const shown = bare.length > chars * 2 ? `${bare.slice(0, chars)}…${bare.slice(-4)}` : bare;
  // `whitespace-nowrap`, because what this renders is already elided: at most
  // `chars + 1 + 4` characters, and the ellipsis is the abbreviation. Breaking
  // it again produces `62aa6232…` over one line and `2e9f` over the next, which
  // is what the log table did in every column narrow enough to provoke it -- a
  // second, worse abbreviation of something already abbreviated. An auto-layout
  // table now sizes the column to hold the whole token, and puts the squeeze on
  // the prose column beside it, which is the one that can afford it. Narrower
  // than every column's minimum and the table outgrows its `overflow-x-auto`
  // wrapper and scrolls, which is what that wrapper is for.
  const body = (
    <span className="mono whitespace-nowrap text-[12px]" title={value}>
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
