"use client";

/**
 * The two things every page that reads a node does: find out which node, once,
 * and read it again while somebody is looking.
 *
 * They were written out in full on every page -- a `resolveNode` effect, an
 * interval, a `visibilitychange` listener, a cleanup -- and had drifted: one
 * page re-read every 20 s, another never, a third kept polling a hidden tab.
 */

import { useEffect, useRef, useState } from "react";
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

/**
 * Run `read` now and every `seconds` while the tab is visible, and once more
 * the moment it becomes visible again. A node on the other end of an SSH
 * tunnel should not be asked anything by a tab nobody is looking at.
 * `read` is held in a ref, so a new closure each render does not restart the
 * clock; `enabled` false stops it.
 */
export function useEvery(read: () => void | Promise<void>, seconds: number, enabled = true) {
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
    start();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      if (timer) clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [seconds, enabled]);
}
