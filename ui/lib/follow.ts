/**
 * Which challenges this reader follows.
 *
 * A preference of the person at this browser, not a fact about the network,
 * so it lives in `localStorage` and nowhere else: the node never learns who
 * follows what, and nothing that settles reads it. Following a challenge makes
 * its page refresh its activity on its own and lists it on the Overview.
 *
 * Every access is guarded. Storage throws in a private window, with site data
 * blocked, and in a WKWebView with no data store, and a page must render the
 * same with following simply unavailable.
 */

const KEY = "cairn.following";
const EVENT = "cairn:following";

export function following(): string[] {
  try {
    const raw = window.localStorage.getItem(KEY);
    const parsed: unknown = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === "string") : [];
  } catch {
    return [];
  }
}

export function isFollowing(id: string): boolean {
  return following().includes(id);
}

/** Follow or unfollow, and return the new state. */
export function setFollowing(id: string, on: boolean): boolean {
  const next = new Set(following());
  if (on) next.add(id);
  else next.delete(id);
  try {
    window.localStorage.setItem(KEY, JSON.stringify([...next]));
    window.dispatchEvent(new Event(EVENT));
    return on;
  } catch {
    return !on;
  }
}

/** Call `listener` when the followed set changes, in this tab or another. */
export function onFollowingChange(listener: () => void): () => void {
  const storage = (event: StorageEvent) => {
    if (event.key === KEY) listener();
  };
  window.addEventListener(EVENT, listener);
  window.addEventListener("storage", storage);
  return () => {
    window.removeEventListener(EVENT, listener);
    window.removeEventListener("storage", storage);
  };
}
