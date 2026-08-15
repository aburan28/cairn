"use client";

import { useCallback, useEffect, useState } from "react";
import {
  type Chain,
  NODE_URL,
  epochScales,
  fetchChain,
  firstBrokenLink,
  short,
  totalClaims,
} from "@/lib/chain";
import {
  type CheckpointResponse,
  coversHead,
  fetchCheckpoint,
} from "@/lib/checkpoint";

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
  const [checkpoint, setCheckpoint] = useState<CheckpointResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async (url: string) => {
    setLoading(true);
    setError(null);
    try {
      // Both, and the checkpoint never fails the page: a node with no
      // checkpoint is an ordinary state, so `fetchCheckpoint` resolves to null
      // rather than turning "nobody has signed this yet" into an error.
      const [next, signed] = await Promise.all([
        fetchChain(url),
        fetchCheckpoint(url),
      ]);
      setChain(next);
      setCheckpoint(signed);
    } catch (cause) {
      setChain(null);
      setCheckpoint(null);
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // Show *which* origin, rather than the empty string NODE_URL now holds.
    // Empty is right for fetching -- it keeps every request relative, so the
    // page works behind a tunnel or a proxy on an unknown path -- and wrong for
    // displaying, because nobody can retype "" after they clear the box.
    setBase(NODE_URL || window.location.origin);
    void load(NODE_URL);
  }, [load]);

  const broken = chain ? firstBrokenLink(chain.chain) : null;
  const scales = chain ? epochScales(chain.chain) : [];
  const claims = chain ? totalClaims(chain.chain) : 0;

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

          {checkpoint && (
            <div className="panel">
              <b>
                signed at height {checkpoint.checkpoint.height}
                {coversHead(checkpoint.checkpoint, chain.links) === "behind" &&
                  " — behind the head below, which is normal after further appends"}
              </b>
              <div className="meta">
                merkle root{" "}
                <code className="dim" title={checkpoint.checkpoint.root}>
                  {short(checkpoint.checkpoint.root)}
                </code>{" "}
                · issued {checkpoint.checkpoint.issued_at}
              </div>
              {/* Said plainly, because the alternative is a reader assuming the
                  green text means somebody checked. Verifying ML-DSA here would
                  put a third implementation of a consensus-critical primitive
                  in a third language. */}
              <div className="meta dim">
                This page does not verify that signature — it shows that one
                exists and what it covers. <code>cairn verify --from</code>{" "}
                is what checks it.
              </div>
            </div>
          )}

          {scales.length > 1 && (
            <div className="panel bad">
              <b>this chain was settled under more than one epoch length</b>
              Its epoch numbers span {scales.length} orders of magnitude, which
              happens when <code>CAIRN_EPOCH_SECONDS</code> changed between
              batches — the demo scripts set it to 1, the default is 600. The
              divisor is derived and never stored, so this is a heuristic and
              not a derivation. It matters because that value decides which
              epoch a record falls in, and therefore which reveals were legal:
              a log holding both was settled under two different rules.
            </div>
          )}

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
                    </code>{" "}
                    <span className="tag">
                      {link.claims.length}{" "}
                      {link.claims.length === 1 ? "claim" : "claims"}
                    </span>
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
            {chain.links} link(s) settling {claims} claim(s) in total, newest
            first. Verify none of it on trust:{" "}
            <code>cairn --log &lt;log&gt; --root . audit</code> re-derives
            the chain and checks every batch against the anchor it recorded.
          </p>
        </>
      )}
    </main>
  );
}
