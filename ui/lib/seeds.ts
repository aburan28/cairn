/**
 * The published seed list, read from the site that published it.
 *
 * `launch/seeds.json`, copied into the export by `scripts/sync-seeds.mjs` and
 * served at `<basePath>/seeds.json`. Its purpose here is narrow: a visitor who
 * opens the public site has no node of their own, and until now the page fell
 * straight through to the log bundled in the repository. The list is how the
 * site finds a node that is actually running.
 *
 * # What the browser can and cannot check
 *
 * Nothing here verifies anything, and that is not a gap to be filled later.
 * The p2p half of a seed entry is authenticated by the *handshake* — a peer id
 * is `sha256` of a 261,120-byte McEliece key, and `cairn seeds resolve` checks
 * that on the command line, where the dial happens. A browser does not dial
 * peers and has no business downloading half a megabyte of key material to
 * check a signature it will never use.
 *
 * What the browser reads is `http`: an ordinary HTTPS endpoint serving
 * `GET /objectives` and friends. There is no key to check because there is no
 * identity being claimed — the answer authenticates itself the same way the
 * bundled log does, by being a hash-linked log with a signed checkpoint that
 * `cairn verify --from` re-derives. A seed that lies is caught by the reader,
 * not by this fetch. That is why every page labels where its numbers came from.
 *
 * # Why `https:` only
 *
 * The published site is HTTPS, so a browser blocks a plain-`http` subresource
 * outright — the request never leaves, and the failure is a console message a
 * visitor will not see. Filtering here means an operator who lists an
 * `http://` endpoint gets a seed that is skipped rather than a site that
 * appears broken. `cairn serve` terminates no TLS by design (its own module
 * docs say to put a reverse proxy in front), so an operator who wants the
 * public site to read their node has to front it with one.
 *
 * Local development over plain HTTP is unaffected: the rule is "no less secure
 * than the page doing the asking", so a page served over `http:` may read an
 * `http:` seed.
 */

import { expectFields } from "./shape";

export type Seed = {
  /** Filename-safe label; `cairn seeds resolve` writes `<name>.json`. */
  name: string;
  /** `host:port` for p2p. Null for an entry the site can read and nobody dials. */
  addr: string | null;
  /** The peer id — `sha256` of the transport key — or null while unpublished. */
  transport: string | null;
  /** An HTTPS base URL serving this node's log, or null. */
  http: string | null;
  operator?: string;
  note?: string;
};

export type SeedList = { version: number; seeds: Seed[]; note?: string };

/**
 * Where the export mounts. Inlined by `next.config.mjs` from the same constant
 * it passes to `basePath`, so this cannot disagree with where the page is.
 */
const BASE_PATH = process.env.NEXT_PUBLIC_BASE_PATH ?? "";

/** The list this site publishes, or an empty one. Never throws: a site with no
 *  seed list behaves exactly as it did before there was one. */
export async function loadSeeds(url: string = `${BASE_PATH}/seeds.json`): Promise<SeedList> {
  try {
    const response = await fetch(url, { cache: "no-store" });
    if (!response.ok) return { version: 0, seeds: [] };
    const body = expectFields<SeedList>(await response.json(), ["seeds"], url);
    return {
      version: typeof body.version === "number" ? body.version : 0,
      seeds: Array.isArray(body.seeds) ? body.seeds : [],
      note: body.note,
    };
  } catch {
    return { version: 0, seeds: [] };
  }
}

/**
 * The endpoints this page is allowed to read, in list order.
 *
 * `pageProtocol` is `window.location.protocol` at the call site, passed in
 * rather than read here so this stays a pure function the tests can drive
 * through both cases.
 */
export function readableEndpoints(list: SeedList, pageProtocol: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const seed of list.seeds) {
    const http = typeof seed?.http === "string" ? seed.http.trim() : "";
    if (!http) continue;
    // No trailing slash: every caller builds `${base}/objectives`, and
    // `https://seed.example//objectives` is a different path to a lot of
    // servers.
    const base = http.replace(/\/+$/, "");
    const isHttps = /^https:\/\//i.test(base);
    const isHttp = /^http:\/\//i.test(base);
    if (!isHttps && !(isHttp && pageProtocol === "http:")) continue;
    if (seen.has(base)) continue;
    seen.add(base);
    out.push(base);
  }
  return out;
}
