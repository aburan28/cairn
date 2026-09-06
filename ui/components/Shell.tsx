"use client";

/**
 * The chrome around every page: navigation, the theme switch, a live read on
 * whether a node is answering, and a command palette.
 *
 * One shell for the public site and for the reader a node embeds at `/ui/`,
 * which is the same "one app, not two" decision the nav has always encoded —
 * an operator who followed a link to their own node gets the explanation too,
 * and the explanation cannot drift from the reader because there is only one
 * of each.
 */

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { NODE_URL } from "@/lib/objectives";
import { REPO, repoLink } from "@/lib/site";

export const ROUTES = [
  { href: "/", label: "Overview", hint: "What cairn is, and this node's numbers" },
  { href: "/objectives", label: "Objectives", hint: "What this node will pay for" },
  { href: "/submit", label: "Post a challenge", hint: "Fund a question, signed by a wallet" },
  { href: "/chain", label: "Chain", hint: "Epoch links, and whether you have forked" },
  { href: "/log", label: "Log", hint: "Every record, as the node stores it" },
  { href: "/peers", label: "Peers", hint: "Who this node reconciles with" },
  { href: "/how-it-works", label: "How it works", hint: "The protocol, in order" },
  { href: "/docs", label: "Docs", hint: "The design notes" },
] as const;

/** The links in the top bar. The rest live in the palette. */
const PRIMARY = ["/objectives", "/chain", "/log", "/peers", "/how-it-works", "/docs"];

export function Shell({ children }: { children: React.ReactNode }) {
  const [paletteOpen, setPaletteOpen] = useState(false);
  const pathname = usePathname();

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen((open) => !open);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <>
      {/* Before the nav in the DOM so it is the first thing a keyboard or
          screen reader reaches, which is the only thing that makes it useful. */}
      <a
        href="#content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50
                   focus:rounded-lg focus:border focus:border-edge focus:bg-surface focus:px-3 focus:py-2"
      >
        Skip to content
      </a>

      <header className="sticky top-0 z-30 border-b border-edge bg-canvas/85 backdrop-blur-md">
        <div className="mx-auto flex h-14 max-w-[78rem] items-center gap-3 px-4 sm:px-6">
          <Link
            href="/"
            className="flex shrink-0 items-center gap-2 text-[14px] font-semibold tracking-tight"
          >
            <Mark />
            cairn
          </Link>

          <nav aria-label="Primary" className="ml-2 hidden items-center gap-0.5 lg:flex">
            {ROUTES.filter((route) => PRIMARY.includes(route.href)).map((route) => {
              const active =
                pathname === route.href || pathname === `${route.href}/`;
              return (
                <Link
                  key={route.href}
                  href={route.href}
                  aria-current={active ? "page" : undefined}
                  className={`rounded-md px-2.5 py-1.5 text-[13px] transition-colors ${
                    active
                      ? "bg-surface-2 font-medium text-ink"
                      : "text-ink-2 hover:bg-surface-2 hover:text-ink"
                  }`}
                >
                  {route.label}
                </Link>
              );
            })}
          </nav>

          <div className="ml-auto flex items-center gap-2">
            <NodeStatus />
            <button
              type="button"
              onClick={() => setPaletteOpen(true)}
              className="btn btn-sm hidden text-ink-2 sm:inline-flex"
              aria-label="Open the command palette"
            >
              <SearchIcon />
              <span className="hidden md:inline">Search</span>
              <span className="kbd ml-1 hidden md:inline">⌘K</span>
            </button>
            <ThemeToggle />
            <Link href="/submit" className="btn btn-sm btn-primary">
              Post a challenge
            </Link>
          </div>
        </div>

        {/* The same links, wrapped, for narrow screens. A drawer would hide
            six items behind a tap for no gain at this count. */}
        <nav
          aria-label="Primary, compact"
          className="flex gap-1 overflow-x-auto border-t border-edge px-4 py-1.5 lg:hidden"
        >
          {ROUTES.map((route) => {
            const active = pathname === route.href || pathname === `${route.href}/`;
            return (
              <Link
                key={route.href}
                href={route.href}
                aria-current={active ? "page" : undefined}
                className={`rounded-md px-2 py-1 text-[12.5px] whitespace-nowrap ${
                  active ? "bg-surface-2 font-medium text-ink" : "text-ink-2"
                }`}
              >
                {route.label}
              </Link>
            );
          })}
        </nav>
      </header>

      <main id="content" className="mx-auto max-w-[78rem] px-4 py-8 sm:px-6 sm:py-10">
        {children}
      </main>

      <Footer />
      {paletteOpen && <CommandPalette onClose={() => setPaletteOpen(false)} />}
    </>
  );
}

/**
 * Is a node answering, and which one?
 *
 * `/health` rather than `/objectives`: it is the cheapest endpoint and the
 * question here is only whether anything is listening. A page that needs the
 * data says so itself, with its own provenance line.
 *
 * The label matters more than it looks. This app is served from two places —
 * a node, and GitHub Pages — and on the second there is no node at all. A
 * visitor who does not know that reads every fallback figure as live.
 */
function NodeStatus() {
  const [state, setState] = useState<"checking" | "live" | "down">("checking");
  const target = NODE_URL || "this origin";

  useEffect(() => {
    let cancelled = false;
    const check = async () => {
      try {
        const response = await fetch(`${NODE_URL}/health`, { cache: "no-store" });
        if (!cancelled) setState(response.ok ? "live" : "down");
      } catch {
        if (!cancelled) setState("down");
      }
    };
    void check();
    // Slow on purpose. This is a status light, not a heartbeat, and a node on
    // the other end of an SSH tunnel should not be polled every second.
    const timer = setInterval(check, 30_000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  const tone =
    state === "live" ? "bg-accent" : state === "down" ? "bg-ink-3" : "bg-warn animate-pulse";
  const text = state === "live" ? "node live" : state === "down" ? "no node" : "checking";

  return (
    <span
      className="hidden items-center gap-1.5 rounded-md border border-edge bg-surface px-2 py-1
                 text-[11.5px] text-ink-2 sm:inline-flex"
      title={
        state === "live"
          ? `A node answered at ${target}.`
          : state === "down"
            ? `Nothing answered at ${target}. Pages fall back to the settled log that ships in the repository, and say so.`
            : `Asking ${target}…`
      }
    >
      <span className={`h-1.5 w-1.5 rounded-full ${tone}`} />
      {text}
    </span>
  );
}

/**
 * Light, dark, or whatever the system says.
 *
 * Persisted in `localStorage` and applied by the inline script in `layout.tsx`
 * before first paint — a toggle that flashes the wrong theme on every
 * navigation is worse than no toggle. Reads are wrapped because a browser set
 * to block site data throws on access rather than returning null.
 */
function ThemeToggle() {
  const [theme, setTheme] = useState<"light" | "dark" | "system">("system");

  useEffect(() => {
    try {
      const stored = localStorage.getItem("cairn-theme");
      if (stored === "light" || stored === "dark") setTheme(stored);
    } catch {
      /* site data blocked; the system default is a fine answer */
    }
  }, []);

  const apply = useCallback((next: "light" | "dark" | "system") => {
    setTheme(next);
    const root = document.documentElement;
    if (next === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", next);
    try {
      if (next === "system") localStorage.removeItem("cairn-theme");
      else localStorage.setItem("cairn-theme", next);
    } catch {
      /* the choice still applies to this page */
    }
  }, []);

  const next = theme === "dark" ? "light" : theme === "light" ? "system" : "dark";
  const labels = { light: "Light", dark: "Dark", system: "System" } as const;

  return (
    <button
      type="button"
      onClick={() => apply(next)}
      className="btn btn-sm btn-ghost"
      aria-label={`Theme: ${labels[theme]}. Switch to ${labels[next]}.`}
      title={`Theme: ${labels[theme]} — click for ${labels[next]}`}
    >
      {theme === "dark" ? <MoonIcon /> : theme === "light" ? <SunIcon /> : <AutoIcon />}
    </button>
  );
}

/**
 * ⌘K.
 *
 * Every route, filtered. Small, but this app is a set of pages an operator
 * moves between constantly while comparing two nodes, and the alternative is
 * a nav bar that grows until nothing in it is findable.
 */
function CommandPalette({ onClose }: { onClose: () => void }) {
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const router = useRouter();

  const matches = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return [...ROUTES];
    return ROUTES.filter(
      (route) =>
        route.label.toLowerCase().includes(needle) ||
        route.hint.toLowerCase().includes(needle) ||
        route.href.includes(needle),
    );
  }, [query]);

  useEffect(() => {
    input.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  useEffect(() => setCursor(0), [query]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-canvas/70 px-4 pt-[12vh] backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className="card w-full max-w-lg overflow-hidden shadow-2xl">
        <input
          ref={input}
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "ArrowDown") {
              event.preventDefault();
              setCursor((c) => Math.min(c + 1, matches.length - 1));
            } else if (event.key === "ArrowUp") {
              event.preventDefault();
              setCursor((c) => Math.max(c - 1, 0));
            } else if (event.key === "Enter" && matches[cursor]) {
              // The router, not `location.assign`: this app is exported at
              // `/ui` inside a node binary and at the repository name on
              // Pages, and only the router knows which prefix it is under.
              router.push(matches[cursor].href);
              onClose();
            }
          }}
          placeholder="Jump to…"
          className="w-full border-b border-edge bg-transparent px-4 py-3 text-[14px]
                     text-ink placeholder:text-ink-3 focus:outline-none"
        />
        <ul className="max-h-80 overflow-y-auto py-1">
          {matches.length === 0 && (
            <li className="px-4 py-6 text-center text-[13px] text-ink-3">Nothing matches.</li>
          )}
          {matches.map((route, index) => (
            <li key={route.href}>
              <Link
                href={route.href}
                onClick={onClose}
                onMouseEnter={() => setCursor(index)}
                className={`flex items-baseline gap-3 px-4 py-2 ${
                  index === cursor ? "bg-surface-2" : ""
                }`}
              >
                <span className="text-[13px] font-medium text-ink">{route.label}</span>
                <span className="truncate text-[12px] text-ink-3">{route.hint}</span>
              </Link>
            </li>
          ))}
        </ul>
        <div className="flex items-center gap-3 border-t border-edge bg-surface-2 px-4 py-2 text-[11px] text-ink-3">
          <span>
            <span className="kbd">↑</span> <span className="kbd">↓</span> to move
          </span>
          <span>
            <span className="kbd">↵</span> to open
          </span>
          <span>
            <span className="kbd">esc</span> to close
          </span>
        </div>
      </div>
    </div>
  );
}

function Footer() {
  return (
    <footer className="mt-16 border-t border-edge bg-surface">
      <div className="mx-auto max-w-[78rem] px-4 py-8 sm:px-6">
        <div className="flex flex-wrap gap-x-5 gap-y-2 text-[13px]">
          <a className="text-accent hover:underline" href={REPO}>
            source
          </a>
          <a className="text-accent hover:underline" href={`${REPO}/releases/latest`}>
            releases
          </a>
          <Link className="text-accent hover:underline" href="/docs">
            docs
          </Link>
          <a className="text-accent hover:underline" href={repoLink("docs/threat-model.md")}>
            threat model
          </a>
          <a className="text-accent hover:underline" href={repoLink("LICENSE")}>
            Apache-2.0
          </a>
        </div>
        <p className="mt-4 max-w-[70ch] text-[12.5px] leading-relaxed text-ink-3">
          Stage 0 — one operator, no token, no consensus. What it does provide is the
          property that matters: anyone can independently re-derive every result the
          network has settled, from nothing but a copy of the log.
        </p>
        <p className="mt-2 max-w-[70ch] text-[12.5px] leading-relaxed text-ink-3">
          This page loads no font, script, or image from anywhere but where it was
          served. The only host it talks to is the node you point it at — which you
          can confirm by watching the network tab stay empty.
        </p>
      </div>
    </footer>
  );
}

// -- icons ------------------------------------------------------------------

function Mark() {
  // A cairn: stones stacked, each one smaller, each resting on the last.
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden>
      <rect x="2.5" y="11.5" width="11" height="2.5" rx="1" fill="currentColor" />
      <rect x="4" y="7.5" width="8" height="2.8" rx="1" fill="currentColor" opacity="0.75" />
      <rect x="5.5" y="3.8" width="5" height="2.8" rx="1" fill="currentColor" opacity="0.5" />
    </svg>
  );
}

function SearchIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden>
      <circle cx="7" cy="7" r="4.5" stroke="currentColor" />
      <path d="m10.5 10.5 3 3" stroke="currentColor" strokeLinecap="round" />
    </svg>
  );
}

function SunIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden>
      <circle cx="8" cy="8" r="3" stroke="currentColor" />
      <path
        d="M8 1v1.5M8 13.5V15M15 8h-1.5M2.5 8H1m10.9-4.9-1 1m-5.8 5.8-1 1m7.8 0-1-1M4.1 4.1l1 1"
        stroke="currentColor"
        strokeLinecap="round"
      />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden>
      <path
        d="M13 9.5A5.5 5.5 0 0 1 6.5 3a5.5 5.5 0 1 0 6.5 6.5Z"
        stroke="currentColor"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function AutoIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden>
      <circle cx="8" cy="8" r="5.5" stroke="currentColor" />
      <path d="M8 2.5v11A5.5 5.5 0 0 0 8 2.5Z" fill="currentColor" />
    </svg>
  );
}
