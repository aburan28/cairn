"use client";

import { useEffect, useState } from "react";
import { Command } from "@/components/ui";
import { networkSetup } from "@/lib/deployment";

/**
 * "Get this node online", as a dismissible pop-up on the reader's landing page.
 *
 * The serving node's deployment marker selects internal/WireGuard recovery
 * for private installations. An unmarked public site keeps its existing recipe.
 *
 * Dismissal is per-browser, in `localStorage` and nowhere else: the node never
 * learns who dismissed it, for the same reason the follow list does not leave
 * the browser (see lib/follow.ts). Rendered only when the page is served by
 * a node (same-origin), because on the public site the visitor may not be an
 * operator at all.
 */
const DISMISSED_KEY = "cairn-get-online-dismissed";

export function GetOnline() {
  const [open, setOpen] = useState(false);
  const [guide, setGuide] = useState(() => networkSetup(null));

  useEffect(() => {
    setGuide(networkSetup(document.querySelector('meta[name="cairn-network"]')?.getAttribute("content")));
    // Throws on access in some private modes, exactly like the theme read in
    // Shell.tsx; a browser that cannot remember still gets the panel once.
    let stored: string | null = null;
    try {
      stored = window.localStorage.getItem(DISMISSED_KEY);
    } catch {
      stored = null;
    }
    setOpen(stored !== "1");
  }, []);

  if (!open) return null;

  const close = () => {
    setOpen(false);
    try {
      window.localStorage.setItem(DISMISSED_KEY, "1");
    } catch {
      // Forgettable: the panel simply comes back next visit.
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-end justify-center bg-black/40 p-4 sm:items-center"
      role="dialog"
      aria-modal="true"
      aria-label="Get this node online"
      onClick={(event) => {
        if (event.target === event.currentTarget) close();
      }}
    >
      <section className="box w-full max-w-xl bg-surface">
        <div className="box-head">
          <span className="min-w-0 flex-1 truncate">Get this node online</span>
          <button type="button" className="btn btn-sm btn-ghost" onClick={close} aria-label="Close">
            ✕
          </button>
        </div>
        <div className="box-body">
          <p className="text-[13px] leading-relaxed text-ink-2">
            {guide.description}
          </p>
          <div className="mt-3 flex flex-col gap-3">
            {guide.commands.map((command) => (
              <div key={command.text}>
                <div className="mb-1 text-[11.5px] text-ink-3">{command.label}</div>
                <Command text={command.text} />
              </div>
            ))}
          </div>
          <p className="mt-3 text-[11.5px] leading-relaxed text-ink-3">
            {guide.footer}
          </p>
        </div>
      </section>
    </div>
  );
}

/**
 * The persistent entry point: a one-line link that re-opens the panel after it
 * has been dismissed, for the operator who closed it last week.
 */
export function GetOnlineLink({ className = "" }: { className?: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        type="button"
        className={`text-accent hover:underline ${className}`}
        onClick={() => setOpen(true)}
      >
        Get this node online →
      </button>
      {open && <GetOnline />}
    </>
  );
}
