"use client";

/**
 * Optional Google sign-in in the chrome.
 *
 * A link to this node's `/auth/google`, not Google's script. The page has to
 * render with no route off the machine — see the note at the top of
 * `globals.css` — and a script tag to accounts.google.com would break that
 * for everyone, including the nodes that never configured sign-in. The
 * browser only talks to Google if the person follows the link, and only
 * after this node has said it is configured.
 *
 * Same-origin only. The session cookie is not readable from the public site.
 */

import { useEffect, useState } from "react";
import { loginHref, signInVisible, signedInLabel, type AuthStatus } from "@/lib/auth";
import { NODE_URL } from "@/lib/objectives";

export function GoogleSignIn() {
  const [status, setStatus] = useState<AuthStatus | null>(null);
  const sameOrigin = NODE_URL === "";

  useEffect(() => {
    if (!sameOrigin) return;
    let cancelled = false;
    // `/health` first, so the public site — which is this same build, and
    // has no node at its own origin — does not request `/auth` on every
    // view. A node answers `ok`; anything else is not a place to sign in.
    fetch("/health", { cache: "no-store" })
      .then((response) => (response.ok ? fetch("/auth", { cache: "no-store" }) : null))
      .then((response) => (response && response.ok ? response.json() : null))
      .then((body: AuthStatus | null) => {
        if (!cancelled) setStatus(body);
      })
      .catch(() => {
        if (!cancelled) setStatus(null);
      });
    return () => {
      cancelled = true;
    };
  }, [sameOrigin]);

  if (!sameOrigin || !status) return null;

  const label = signedInLabel(status);
  if (label) {
    return (
      <div className="flex items-center justify-between gap-2 px-1">
        <span
          className="truncate text-[11.5px] text-ink-2"
          title="Signed in with Google. This names the browser, not a cairn identity, and the node works without it."
        >
          {label}
        </span>
        <button
          type="button"
          className="btn btn-sm btn-ghost"
          onClick={() => {
            void fetch("/auth/logout", { method: "POST" }).then(() => {
              setStatus({ ...status, authenticated: false, account: null });
            });
          }}
        >
          Sign out
        </button>
      </div>
    );
  }

  if (!signInVisible(NODE_URL, status)) return null;

  return (
    // A plain anchor, not `next/link`. The reader is mounted at `/ui/`, and
    // Next would prefix that base path onto a route that lives at `/auth`.
    <a href={loginHref(status)} className="btn btn-sm">
      Sign in with Google
    </a>
  );
}
