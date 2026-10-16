"use client";

import { useEffect, useState } from "react";
import { Command } from "@/components/ui";

/**
 * "Get this node online", as a dismissible pop-up on the reader's landing page.
 *
 * The recipe is Tailscale (see docs/publishing.md): serve the HTTP half on the
 * tailnet, funnel it for strangers, and let tailnet peers dial the p2p port
 * directly. A node is only useful once other machines can reach it, and the
 * commands are the entire setup — there is nothing to configure past running
 * them, which is why they are here as copyable rows rather than behind a link
 * alone.
 *
 * Dismissal is per-browser, in `localStorage` and nowhere else: the node never
 * learns who dismissed it, for the same reason the follow list does not leave
 * the browser (see lib/follow.ts). Rendered only when the page is served by
 * a node (same-origin), because on the public site the visitor may not be an
 * operator at all.
 */
const DISMISSED_KEY = "cairn-get-online-dismissed";

const COMMANDS: Array<{ label: string; text: string }> = [
  {
    label: "1 · run the node (p2p on the wildcard, HTTP on loopback)",
    text: "cairn run --listen 0.0.0.0:9000 --serve 127.0.0.1:8080",
  },
  {
    label: "2 · sign in once",
    text: "tailscale up",
  },
  {
    label: "3 · HTTPS for the tailnet",
    text: "tailscale serve --bg --https=8443 http://127.0.0.1:8080",
  },
  {
    label: "4 · and for the open internet",
    text: "tailscale funnel --https=8443 --bg http://127.0.0.1:8080",
  },
];

export function GetOnline() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
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
            Four commands over Tailscale: HTTPS on your tailnet, the open
            internet behind a funnel, and peers that dial the p2p port directly.
            Result — <span className="mono text-[12px]">https://&lt;your-magicdns-name&gt;:8443</span>{" "}
            for this reader and the API, your Tailscale IP and port{" "}
            <span className="mono text-[12px]">9000</span> for other nodes.
          </p>
          <div className="mt-3 flex flex-col gap-3">
            {COMMANDS.map((command) => (
              <div key={command.text}>
                <div className="mb-1 text-[11.5px] text-ink-3">{command.label}</div>
                <Command text={command.text} />
              </div>
            ))}
          </div>
          <p className="mt-3 text-[11.5px] leading-relaxed text-ink-3">
            Verify the public half with{" "}
            <span className="mono">tailscale funnel status</span>. Always use the{" "}
            <span className="mono">--https=</span> flag plus the full backend
            URL — a bare port number is read as the target and can clobber
            other routes. The full recipe, including what peers need, is{" "}
            <span className="mono">docs/publishing.md</span> in the
            repository.
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
