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
import { resolveNode } from "@/lib/site";
import {
  type CheckpointResponse,
  coversHead,
  readCheckpoint,
} from "@/lib/checkpoint";
import { Badge, Card, EmptyState, Hash, Note, SectionHeading } from "@/components/ui";

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
  const [checkpointError, setCheckpointError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async (url: string) => {
    setLoading(true);
    setError(null);
    setCheckpointError(null);
    // Two requests, and each fails on its own. They shared one `Promise.all`
    // for a while, so a `/checkpoint` answer in the wrong shape blanked the
    // chain as well -- the one thing this page is for, withheld over a panel
    // it could have rendered without. `readCheckpoint` never throws: a node
    // with no checkpoint is an ordinary state and says so below, and a node
    // that answered wrongly gets its own red panel rather than the chain's.
    const [next, answer] = await Promise.all([
      fetchChain(url).then(
        (chain) => ({ chain, error: null }),
        (cause: unknown) => ({
          chain: null,
          error: cause instanceof Error ? cause.message : String(cause),
        }),
      ),
      readCheckpoint(url),
    ]);
    setChain(next.chain);
    setError(next.error);
    setCheckpoint(answer.kind === "signed" ? answer.value : null);
    setCheckpointError(answer.kind === "unreadable" ? answer.message : null);
    setLoading(false);
  }, []);

  useEffect(() => {
    // Ask which node to read before reading it. Same-origin when one answers --
    // the daemon serves this page at /ui/, so that is the common case and it
    // costs one /health -- and otherwise the first seed from the published list
    // that is up. On the public site there is no same-origin node at all, and
    // before this the box showed github.io and every request 404'd into the
    // snapshot.
    //
    // Shown *and* used, which is the part worth being careful about: the box
    // has to name the origin the numbers below came from, or a reader comparing
    // two nodes is comparing one node against a label. Empty stays empty for
    // fetching -- relative requests survive a tunnel or a proxy on an unknown
    // path -- and becomes this page's own origin for display, because nobody
    // can retype "" after clearing the box.
    void resolveNode().then((url) => {
      setBase(url || window.location.origin);
      void load(url);
    });
  }, [load]);

  const broken = chain ? firstBrokenLink(chain.chain) : null;
  const scales = chain ? epochScales(chain.chain) : [];
  const claims = chain ? totalClaims(chain.chain) : 0;
  const covers = chain && checkpoint ? coversHead(checkpoint.checkpoint, chain.height) : null;

  return (
    <>
      <header className="mb-6 max-w-[62rem]">
        <h1 className="text-[26px] font-semibold">Knowledge chain</h1>
        <p className="prose-block mt-2">
          Each link is <code className="mono">H({"{prev, epoch, sorted claim ids}"})</code> —
          content only, so two nodes that settled the same claims in the same epochs
          compute the same head. The head is the anchor every later batch is ordered
          against. Nothing here is stored: the node derives it from its log.
        </p>
      </header>

      <Card className="card-pad mb-4">
        <label className="label" htmlFor="node">
          Node
        </label>
        <div className="flex flex-wrap gap-2">
          <input
            id="node"
            className="field field-mono flex-1"
            value={base}
            onChange={(event) => setBase(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") void load(base);
            }}
            spellCheck={false}
          />
          <button className="btn" onClick={() => void load(base)} disabled={loading}>
            {loading ? "reading…" : "Read"}
          </button>
        </div>
      </Card>

      <div className="flex flex-col gap-4">
        {error && (
          <Note title="could not read a chain" tone="bad">
            {error}
          </Note>
        )}

        {/* Its own panel, and the chain below still renders: the node answered
            `/checkpoint` with something that is not a checkpoint, which is a
            bug on one side of the seam and not a reason to withhold the head. */}
        {checkpointError && (
          <Note title="could not read this node's checkpoint" tone="bad">
            {checkpointError}
          </Note>
        )}

        {chain && (
          <>
            <Card className="card-pad">
              <div className="note-title">
                head — compare with a peer&rsquo;s; if they differ, you have forked
              </div>
              <div className="mt-1 flex items-center gap-2">
                <code className="mono text-[13px] break-all text-accent">
                  {chain.head || "— empty chain"}
                </code>
                {chain.head && <Hash value={chain.head} chars={0} />}
              </div>
            </Card>

            {checkpoint && (
              <Note
                tone={covers === "ahead" ? "bad" : "accent"}
                title={
                  /* `chain.height` — the ledger's entry count — and not
                     `chain.links`. A checkpoint signs the entry count, and the
                     two were compared for a while; since a log holds at least
                     as many entries as batches, "behind" could never be seen. */
                  `signed at height ${checkpoint.checkpoint.height} of ${chain.height} entries` +
                  (covers === "at" ? " — covers every entry this node serves" : "") +
                  (covers === "behind"
                    ? " — behind the log, which is normal after further appends"
                    : "") +
                  (covers === "ahead"
                    ? " — more entries than this node now serves; the signed prefix is not this log"
                    : "")
                }
              >
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span className="flex items-center gap-1">
                    merkle root <Hash value={checkpoint.checkpoint.root} chars={8} />
                  </span>
                  <span className="flex items-center gap-1">
                    ledger head <Hash value={checkpoint.checkpoint.head} chars={8} />
                  </span>
                  <span className="text-ink-3">
                    {checkpoint.checkpoint.head === chain.ledger_head
                      ? "(this node's)"
                      : covers === "at"
                        ? "(differs from this node's, at the same height — not the same log)"
                        : ""}
                  </span>
                  <span className="mono text-ink-3">
                    issued {checkpoint.checkpoint.issued_at}
                  </span>
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-1">
                  signed by <Hash value={checkpoint.public_key} chars={8} />
                  <span className="text-ink-3">
                    — the ML-DSA key, in full on hover. Whether that is the key you were
                    told to expect is yours to check.
                  </span>
                </div>
                {/* Said plainly, because the alternative is a reader assuming
                    the green text means somebody checked. Verifying ML-DSA here
                    would put a third implementation of a consensus-critical
                    primitive in a third language. */}
                <p className="mt-1 text-ink-3">
                  This page does not verify that signature — it shows that one exists and
                  what it covers. <code className="mono">cairn verify --from</code> is what
                  checks it.
                </p>
              </Note>
            )}

            {scales.length > 1 && (
              <Note title="this chain was settled under more than one epoch length" tone="bad">
                Its epoch numbers span {scales.length} orders of magnitude, which happens
                when <code className="mono">CAIRN_EPOCH_SECONDS</code> changed between
                batches — the demo scripts set it to 1, the default is 600. The divisor is
                derived and never stored, so this is a heuristic and not a derivation. It
                matters because that value decides which epoch a record falls in, and
                therefore which reveals were legal: a log holding both was settled under
                two different rules.
              </Note>
            )}

            {/* The one claim this page makes on its own behalf. The node says
                "here is a chain"; rendering it without checking would be taking
                that on faith, which is the thing this project does not do. */}
            {broken !== null && (
              <Note title="this is not a chain" tone="bad">
                The link for epoch {broken} does not name the link before it. The node
                served something inconsistent — do not compare this head against anything.
              </Note>
            )}

            {chain.chain.length === 0 ? (
              <EmptyState title="No epoch has settled yet.">
                The chain starts at the first batch.
              </EmptyState>
            ) : (
              <section>
                <SectionHeading count={chain.chain.length}>Links, newest first</SectionHeading>
                <ol className="relative">
                  {[...chain.chain].reverse().map((link, index, all) => (
                    <li key={link.epoch} className="contain-rows relative pb-5 pl-7">
                      {/* The spine. Drawn per row rather than on the list so the
                          last row can stop it, and the genesis marker below can
                          be hollow — "this link names nothing before it" is the
                          one structural fact worth seeing rather than reading. */}
                      {index < all.length - 1 && (
                        <span
                          className="absolute top-2 bottom-0 left-[5px] w-px bg-edge"
                          aria-hidden
                        />
                      )}
                      <span
                        className={`absolute top-1.5 left-0 h-2.5 w-2.5 rounded-full ring-4 ring-canvas ${
                          link.prev === "" ? "border-2 border-accent bg-canvas" : "bg-accent"
                        }`}
                        aria-hidden
                      />
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-[13px] font-semibold">epoch {link.epoch}</span>
                        <Hash value={link.link} chars={10} />
                        <Badge>
                          {link.claims.length} {link.claims.length === 1 ? "claim" : "claims"}
                        </Badge>
                      </div>
                      <div className="mt-1 flex items-center gap-1 text-[12px] text-ink-2">
                        prev{" "}
                        {link.prev === "" ? (
                          <span className="text-ink-3">— genesis</span>
                        ) : (
                          <Hash value={link.prev} chars={10} />
                        )}
                      </div>
                      {link.claims.length === 0 ? (
                        <div className="mt-1 text-[12px] text-ink-3">no claims settled</div>
                      ) : (
                        <ul className="mt-1.5 flex flex-col gap-0.5">
                          {link.claims.map((claim) => (
                            <li key={claim}>
                              <Hash value={claim} chars={10} />
                            </li>
                          ))}
                        </ul>
                      )}
                    </li>
                  ))}
                </ol>
              </section>
            )}

            <p className="prose-block mt-4">
              {chain.links} link(s) settling {claims} claim(s) in total, newest first,
              derived from a log of {chain.height} entries. Verify none of it on trust:{" "}
              <code className="mono">cairn --log &lt;log&gt; --root . audit</code>{" "}
              re-derives the chain and checks every batch against the anchor it recorded.
            </p>
          </>
        )}
      </div>
    </>
  );
}
