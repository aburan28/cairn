"use client";

import { useEffect, useState } from "react";
import { Command, Disclosure } from "@/components/ui";
import { useModalDialog } from "@/components/hooks";
import type { SetupGuide } from "@/lib/deployment";
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

export function GetOnline({
  forceOpen = false,
  onClose,
}: { forceOpen?: boolean; onClose?: () => void } = {}) {
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
    // A remembered dismissal hides the automatic prompt, never an explicit
    // recovery request from the persistent trigger.
    setOpen(forceOpen || stored !== "1");
  }, [forceOpen]);

  if (!open) return null;

  const close = () => {
    setOpen(false);
    try {
      window.localStorage.setItem(DISMISSED_KEY, "1");
    } catch {
      // Forgettable: the panel simply comes back next visit.
    }
    onClose?.();
  };

  return <OnlineDialog guide={guide} onClose={close} />;
}

function OnlineDialog({ guide, onClose }: { guide: SetupGuide; onClose: () => void }) {
  const dialog = useModalDialog();
  return (
    <dialog ref={dialog}
      className="fixed inset-0 m-0 h-dvh max-h-none w-full max-w-none bg-transparent p-4 text-ink open:flex open:items-end open:justify-center sm:open:items-center backdrop:bg-black/40"
      role="dialog"
      aria-modal="true"
      aria-label="Get this node online"
      onCancel={(event) => { event.preventDefault(); onClose(); }}
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section className="box max-h-[85dvh] w-full max-w-xl overflow-y-auto bg-surface">
        <div className="box-head">
          <span className="min-w-0 flex-1 truncate">Get this node online</span>
          <button type="button" className="btn btn-sm btn-ghost" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>
        <div className="box-body">
          <p className="text-[13px] leading-relaxed text-ink-2">
            {guide.summary}
          </p>
          <Disclosure summary="Advanced network setup">
            <p className="text-[13px] leading-relaxed text-ink-2">{guide.description}</p>
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
          </Disclosure>
        </div>
      </section>
    </dialog>
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
      {open && <GetOnline forceOpen onClose={() => setOpen(false)} />}
    </>
  );
}
