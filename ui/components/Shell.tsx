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

export const ROUTES = [
  { href: "/", label: "Overview", hint: "What cairn is, and this node's numbers" },
  { href: "/objectives", label: "Objectives", hint: "What this node will pay for" },
  { href: "/task", label: "Task progress", hint: "A divided search: what is settled, who is working it, how far along" },
  { href: "/submit", label: "Post a challenge", hint: "Fund a question, signed by a wallet" },
  { href: "/chain", label: "Chain", hint: "Epoch links, and whether you have forked" },
  { href: "/log", label: "Log", hint: "Every record, as the node stores it" },
  { href: "/peers", label: "Peers", hint: "Who this node reconciles with" },
  { href: "/how-it-works", label: "How it works", hint: "The protocol, in order" },
  { href: "/docs", label: "Docs", hint: "The design notes" },
] as const;

/**
 * The sidebar, in three groups: what this node holds, what you can do to it,
 * and the explanation. `match` lists the routes that belong under an entry
 * without being it -- one objective, and its move history, are both
 * "Objectives".
 */
const NAV: {
  group: string;
  siteOnly?: boolean;
  items: { href: string; label: string; icon: React.ReactNode; match?: string[] }[];
}[] = [
  {
    group: "Node",
    items: [
      { href: "/", label: "Overview", icon: <IconHome /> },
      {
        href: "/objectives",
        label: "Objectives",
        icon: <IconTarget />,
        match: ["/challenge", "/frontier", "/task"],
      },
      { href: "/chain", label: "Chain", icon: <IconChain /> },
      { href: "/log", label: "Log", icon: <IconList /> },
      { href: "/peers", label: "Peers", icon: <IconPeers /> },
    ],
  },
  {
    group: "Fund",
    items: [{ href: "/submit", label: "Post a challenge", icon: <IconPlus /> }],
  },
  {
    group: "Learn",
    items: [
      { href: "/how-it-works", label: "How it works", icon: <IconBook /> },
      { href: "/docs", label: "Docs", icon: <IconDoc /> },
    ],
  },
];

function isActive(pathname: string, href: string, match: string[] = []): boolean {
  const path = pathname.replace(/\/$/, "") || "/";
  if (href === "/") return path === "/";
  return [href, ...match].some((root) => path === root || path.startsWith(`${root}/`));
}

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

      <div className="lg:flex">
        {/* Wide screens: one sidebar, the whole height of the window. */}
        <aside
          className="sticky top-0 hidden h-dvh w-56 shrink-0 flex-col border-r border-edge
                     bg-surface/60 lg:flex"
        >
          <Link
            href="/"
            className="flex h-14 shrink-0 items-center gap-2 px-5 text-[14px] font-semibold tracking-tight"
          >
            <Mark />
            cairn
          </Link>
          <nav aria-label="Primary" className="flex-1 overflow-y-auto px-3 pb-4">
            {NAV.map((section) => (
              <div key={section.group}>
                <div className="sidebar-group">{section.group}</div>
                {section.items.map((item) => (
                  <Link
                    key={item.href}
                    href={item.href}
                    aria-current={isActive(pathname, item.href, item.match) ? "page" : undefined}
                    className="sidebar-link"
                  >
                    <span className="text-ink-3">{item.icon}</span>
                    {item.label}
                  </Link>
                ))}
              </div>
            ))}
          </nav>
          <div className="flex flex-col gap-2 border-t border-edge px-3 py-3">
            <button
              type="button"
              onClick={() => setPaletteOpen(true)}
              className="sidebar-link w-full cursor-pointer"
              aria-label="Open the command palette"
            >
              <span className="text-ink-3">
                <SearchIcon />
              </span>
              Jump to…
              <span className="kbd ml-auto">⌘K</span>
            </button>
            <div className="flex items-center justify-between gap-2 px-1">
              <NodeStatus />
              <ThemeToggle />
            </div>
          </div>
        </aside>

        <div className="flex min-h-dvh min-w-0 flex-1 flex-col">
          {/* Narrow screens: the old top bar, links wrapped under it. */}
          <header className="shell-header sticky top-0 z-30 border-b border-edge bg-canvas/85 backdrop-blur-md lg:hidden">
            <div className="shell-gutter flex h-12 items-center gap-3">
              <Link
                href="/"
                className="flex shrink-0 items-center gap-2 text-[14px] font-semibold tracking-tight"
              >
                <Mark />
                cairn
              </Link>
              <div className="ml-auto flex items-center gap-2">
                <NodeStatus />
                <button
                  type="button"
                  onClick={() => setPaletteOpen(true)}
                  className="btn btn-sm btn-ghost"
                  aria-label="Open the command palette"
                >
                  <SearchIcon />
                </button>
                <ThemeToggle />
              </div>
            </div>
            <nav
              aria-label="Primary, compact"
              className="shell-gutter flex gap-1 overflow-x-auto border-t border-edge py-1.5"
            >
              {NAV.flatMap((section) => section.items).map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  aria-current={isActive(pathname, item.href, item.match) ? "page" : undefined}
                  className={`rounded-md px-2 py-1 text-[12.5px] whitespace-nowrap ${
                    isActive(pathname, item.href, item.match)
                      ? "bg-surface-2 font-medium text-ink"
                      : "text-ink-2"
                  }`}
                >
                  {item.label}
                </Link>
              ))}
            </nav>
          </header>

          <main
            id="content"
            className="shell-gutter w-full max-w-[90rem] flex-1 py-6 lg:px-8 lg:py-7"
          >
            {children}
          </main>

          <Footer />
        </div>
      </div>
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
      className="inline-flex items-center gap-1.5 rounded-md border border-edge bg-surface px-2 py-1
                 text-[11.5px] text-ink-2"
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
    <footer className="shell-footer site-only border-t border-edge">
      <div className="shell-gutter flex max-w-[90rem] flex-wrap items-center gap-x-5 gap-y-2 py-5 text-[12.5px] lg:px-8">
        <span
          className="text-ink-2"
          title="The full accounting, attack by attack, is docs/threat-model.md in the repository."
        >
          threat model: <span className="mono">docs/threat-model.md</span>
        </span>
        <span className="text-ink-2" title="LICENSE in the repository.">
          Apache-2.0
        </span>
        <span
          className="text-ink-3 sm:ml-auto"
          title="This page loads no font, script, or image from anywhere but where it was served. The only host it talks to is the node you point it at."
        >
          Stage 0: anyone can re-derive every settled result from a copy of the log.
        </span>
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

// Sidebar icons: 16px, one stroke, the same weight as the ones above.

function Icon({ children }: { children: React.ReactNode }) {
  return (
    <svg
      width="15"
      height="15"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.3"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      {children}
    </svg>
  );
}

function IconHome() {
  return (
    <Icon>
      <path d="M2.5 7 8 2.5 13.5 7v6a.5.5 0 0 1-.5.5h-3v-4h-4v4H3a.5.5 0 0 1-.5-.5Z" />
    </Icon>
  );
}

function IconTarget() {
  return (
    <Icon>
      <circle cx="8" cy="8" r="5.5" />
      <circle cx="8" cy="8" r="2.5" />
    </Icon>
  );
}

function IconChain() {
  return (
    <Icon>
      <path d="M6.5 9.5 9.5 6.5M7 4.5l1-1a2.5 2.5 0 0 1 3.5 3.5l-1 1M9 11.5l-1 1A2.5 2.5 0 0 1 4.5 9l1-1" />
    </Icon>
  );
}

function IconList() {
  return (
    <Icon>
      <path d="M5.5 4h8M5.5 8h8M5.5 12h8M2.5 4h.01M2.5 8h.01M2.5 12h.01" />
    </Icon>
  );
}

function IconPeers() {
  return (
    <Icon>
      <circle cx="6" cy="5.5" r="2" />
      <path d="M2.5 13a3.5 3.5 0 0 1 7 0M10.5 3.8a2 2 0 0 1 0 3.4M11.5 9.6A3.5 3.5 0 0 1 13.5 13" />
    </Icon>
  );
}

function IconPlus() {
  return (
    <Icon>
      <circle cx="8" cy="8" r="5.5" />
      <path d="M8 5.5v5M5.5 8h5" />
    </Icon>
  );
}

function IconBook() {
  return (
    <Icon>
      <path d="M2.5 3.5h4A1.5 1.5 0 0 1 8 5v8a1 1 0 0 0-1-1H2.5ZM13.5 3.5h-4A1.5 1.5 0 0 0 8 5v8a1 1 0 0 1 1-1h4.5Z" />
    </Icon>
  );
}

function IconDoc() {
  return (
    <Icon>
      <path d="M4 1.5h5l3 3v10H4ZM9 1.5v3h3M6 8h4M6 10.5h4" />
    </Icon>
  );
}
