"use client";

import { useCallback, useEffect, useState } from "react";
import {
  type Chain,
  NODE_URL,
  fetchChain,
  firstBrokenLink,
  short,
} from "@/lib/chain";

/**
 * The knowledge chain of one node.
 *
 * A client component that reads a *live* node rather than a server component
 * rendering at build or request time. The value of this page is comparing one
 * node's head against a peer's, so which node it points at has to be
 * changeable without a redeploy — that is a browser-side concern.
 */
export default function Page() {
  const [base, setBase] = useState(NODE_URL);
  const [chain, setChain] = useState<Chain | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async (url: string) => {
    setLoading(true);
    setError(null);
    try {
      setChain(await fetchChain(url));
    } catch (cause) {
      setChain(null);
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load(NODE_URL);
  }, [load]);

  const broken = chain ? firstBrokenLink(chain.chain) : null;

  return (
    <main>
      <h1>knowledge chain</h1>
      <p className="lede">
        Each link is <code>H({"{prev, epoch, sorted claim ids}"})</code> —
        content only, so two nodes that settled the same claims in the same
        epochs compute the same head. The head is the anchor every later batch
        is ordered against. Nothing here is stored: the node derives it from its
        log.
      </p>

      <div className="row">
        <input
          value={base}
          onChange={(event) => setBase(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") void load(base);
          }}
          aria-label="Node URL"
          spellCheck={false}
        />
        <button onClick={() => void load(base)} disabled={loading}>
          {loading ? "reading…" : "read"}
        </button>
      </div>

      {error && (
        <div className="panel bad">
          <b>could not read a chain</b>
          {error}
        </div>
      )}

      {chain && (
        <>
          <div className="panel">
            <b>head — compare with a peer&apos;s; if they differ, you have forked</b>
            <code className="accent">{chain.head || "— empty chain"}</code>
          </div>

          {/* The one claim this page makes on its own behalf. The node says
              "here is a chain"; rendering it without checking would be taking
              that on faith, which is the thing this project does not do. */}
          {broken !== null && (
            <div className="panel bad">
              <b>this is not a chain</b>
              The link for epoch {broken} does not name the link before it. The
              node served something inconsistent — do not compare this head
              against anything.
            </div>
          )}

          {chain.chain.length === 0 ? (
            <p className="empty">
              No epoch has settled yet. The chain starts at the first batch.
            </p>
          ) : (
            <ol className="chain">
              {[...chain.chain].reverse().map((link) => (
                <li
                  key={link.epoch}
                  className={link.prev === "" ? "link genesis" : "link"}
                >
                  <div>
                    <span className="epoch">epoch {link.epoch}</span>{" "}
                    <code className="accent" title={link.link}>
                      {short(link.link)}
                    </code>
                  </div>
                  <div className="meta">
                    prev{" "}
                    {link.prev === "" ? (
                      <span className="dim">— genesis</span>
                    ) : (
                      <code title={link.prev}>{short(link.prev)}</code>
                    )}
                  </div>
                  {link.claims.length === 0 ? (
                    <div className="meta">no claims settled</div>
                  ) : (
                    <ul className="claims">
                      {link.claims.map((claim) => (
                        <li key={claim}>
                          <code className="dim" title={claim}>
                            {short(claim)}
                          </code>
                        </li>
                      ))}
                    </ul>
                  )}
                </li>
              ))}
            </ol>
          )}

          <p className="lede" style={{ marginTop: "2rem" }}>
            {chain.links} link(s), newest first. Verify none of it on trust:{" "}
            <code>proofwork --log &lt;log&gt; --root . audit</code> re-derives
            the chain and checks every batch against the anchor it recorded.
          </p>
        </>
      )}
    </main>
  );
}
