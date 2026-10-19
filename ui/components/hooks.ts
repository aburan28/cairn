"use client";

/**
 * The two things every page that reads a node does: find out which node, once,
 * and read it again while somebody is looking.
 *
 * They were written out in full on every page -- a `resolveNode` effect, an
 * interval, a `visibilitychange` listener, a cleanup -- and had drifted: one
 * page re-read every 20 s, another never, a third kept polling a hidden tab.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { resolveNode } from "@/lib/site";

/**
 * The node to read: `""` for same-origin (the reader the node serves), a
 * seed's URL on the public site, `null` until decided. See `resolveNode`.
 */
export function useNode(): string | null {
  const [base, setBase] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    void resolveNode().then((url) => {
      if (live) setBase(url);
    });
    return () => {
      live = false;
    };
  }, []);
  return base;
}

/** Share discovery, stale-data retention, non-overlapping reads and cleanup.
 * A changed key discards the old answer; refreshing the same key keeps it. */
export function useNodeRead<T>(read: (base: string) => Promise<T>, { seconds = 20, key = "", enabled = true } = {}) {
  const base = useNode();
  const [value, setValue] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [failure, setFailure] = useState<unknown>(null);
  const [readAt, setReadAt] = useState<Date | null>(null);
  const [loading, setLoading] = useState(false);
  const latest = useRef(read);
  latest.current = read;
  const generation = useRef(0);
  const pending = useRef(false);
  useEffect(() => {
    generation.current += 1;
    pending.current = false;
    setValue(null); setError(null); setFailure(null); setReadAt(null);
    return () => { generation.current += 1; };
  }, [base, key]);
  const refresh = useCallback(async () => {
    if (base === null || !enabled || pending.current) return;
    const version = generation.current;
    pending.current = true;
    setLoading(true);
    try {
      const next = await latest.current(base);
      if (version !== generation.current) return;
      setValue(next); setReadAt(new Date()); setError(null); setFailure(null);
    } catch (cause) {
      if (version === generation.current) { setError(cause instanceof Error ? cause.message : String(cause)); setFailure(cause); }
    } finally {
      if (version === generation.current) { pending.current = false; setLoading(false); }
    }
  }, [base, enabled]);
  useEvery(refresh, seconds, enabled && base !== null, `${base}:${key}`);
  return { base, value, error, failure, readAt, loading, refresh };
}

/**
 * Run `read` now and every `seconds` while the tab is visible, and once more
 * the moment it becomes visible again. A node on the other end of an SSH
 * tunnel should not be asked anything by a tab nobody is looking at.
 * `read` is held in a ref, so a new closure each render does not restart the
 * clock; `enabled` false stops it. `key` is what the read depends on that the
 * person can change -- a policy, a slice count: a new key reads at once
 * rather than at the next tick, which would leave the old answer on screen
 * under the new choice for up to a whole interval.
 */
export function useEvery(read: () => void | Promise<void>, seconds: number, enabled = true, key?: unknown) {
  const latest = useRef(read);
  latest.current = read;
  useEffect(() => {
    if (!enabled) return;
    let timer: ReturnType<typeof setInterval> | null = null;
    const start = () => {
      if (timer) clearInterval(timer);
      timer = setInterval(() => void latest.current(), seconds * 1000);
    };
    const onVisibility = () => {
      if (document.visibilityState === "visible") {
        void latest.current();
        start();
      } else if (timer) {
        clearInterval(timer);
        timer = null;
      }
    };
    void latest.current();
    if (document.visibilityState === "visible") start();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      if (timer) clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [seconds, enabled, key]);
}

/** Native modal dialogs make the background inert and return focus to the
 * opener. Share the scroll lock too, so a touch gesture cannot move the page
 * beneath a contribution sheet or command palette. */
export function useModalDialog() {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = dialog.current;
    if (!element) return;
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const overflow = document.documentElement.style.overflow;
    element.showModal();
    document.documentElement.style.overflow = "hidden";
    // At either end Chromium can send Tab to browser chrome. Wrap inside
    // the panel so returning from a field is predictable in the native app
    // as well, where there is no address bar to receive that focus.
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Tab") return;
      const controls = [...element.querySelectorAll<HTMLElement>("a[href], button, input, select, textarea, summary, [tabindex]")]
        .filter((control) => control.tabIndex >= 0 && !control.matches(":disabled") && control.getClientRects().length > 0);
      const first = controls[0];
      const last = controls.at(-1);
      if (!first) {
        event.preventDefault();
        element.focus();
      } else if (event.shiftKey && (document.activeElement === first || document.activeElement === element)) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    element.addEventListener("keydown", onKey);
    return () => {
      element.removeEventListener("keydown", onKey);
      element.close();
      // React removes a dialog before passive cleanup runs; at that point
      // the browser's automatic focus restoration has already lost it.
      if (opener?.isConnected) opener.focus({ preventScroll: true });
      document.documentElement.style.overflow = overflow;
    };
  }, []);
  return dialog;
}
