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
import { Box, CopyButton, EmptyState, Hash, NodePicker, Note, PageHeader, Stat } from "@/components/ui";

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
      <PageHeader
        title="Knowledge chain"
        subtitle="Each link hashes the one before it and the claims settled in its epoch. Two nodes that settled the same claims compute the same head; where they differ is where they forked."
        actions={
          <NodePicker
            value={base}
            onChange={setBase}
            onRead={() => void load(base)}
            loading={loading}
          />
        }
      />


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
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <Stat label="Links" value={String(chain.links)} from="one per settled epoch" tone="accent" />
              <Stat label="Claims settled" value={String(claims)} tone="accent" />
              <Stat label="Log entries" value={String(chain.height)} />
              <Stat
                label="Checkpoint"
                value={checkpoint ? `height ${checkpoint.checkpoint.height}` : "none"}
                from={
                  covers === "at"
                    ? "covers every entry"
                    : covers === "behind"
                      ? "behind the log, normal after appends"
                      : covers === "ahead"
                        ? "ahead of this log: not this log"
                        : "never signed"
                }
                tone={covers === "ahead" ? "bad" : checkpoint ? "accent" : "neutral"}
              />
            </div>

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

            <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_22rem]">
              {chain.chain.length === 0 ? (
                <EmptyState title="No epoch has settled yet.">
                  The chain starts at the first batch.
                </EmptyState>
              ) : (
                <Box
                  className="self-start"
                  title={
                    <>
                      Links, newest first{" "}
                      <span className="mono ml-1 font-normal text-ink-3">{chain.chain.length}</span>
                    </>
                  }
                  flush
                >
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[36rem] border-collapse text-left text-[12.5px]">
                      <thead>
                        <tr className="border-b border-edge text-[11.5px] text-ink-3">
                          <th className="px-4 py-2 font-medium">Epoch</th>
                          <th className="px-3 py-2 font-medium">Link</th>
                          <th className="px-3 py-2 font-medium">Prev</th>
                          <th className="px-4 py-2 font-medium">Claims settled</th>
                        </tr>
                      </thead>
                      <tbody className="divide-edge-y">
                        {[...chain.chain].reverse().map((link) => (
                          <tr key={link.epoch} className="contain-rows align-top">
                            <td className="mono px-4 py-2.5 font-semibold text-ink">{link.epoch}</td>
                            <td className="px-3 py-2.5">
                              <Hash value={link.link} chars={8} />
                            </td>
                            <td className="px-3 py-2.5">
                              {/* "This link names nothing before it" is the one
                                  structural fact worth seeing, not reading. */}
                              {link.prev === "" ? (
                                <span className="pill pill-open">genesis</span>
                              ) : (
                                <Hash value={link.prev} chars={8} />
                              )}
                            </td>
                            <td className="px-4 py-2.5">
                              {link.claims.length === 0 ? (
                                <span className="text-ink-3">none</span>
                              ) : (
                                <ul className="flex flex-col gap-0.5">
                                  {link.claims.map((claim) => (
                                    <li key={claim}>
                                      <Hash value={claim} chars={8} />
                                    </li>
                                  ))}
                                </ul>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Box>
              )}

              <div className="flex min-w-0 flex-col gap-4">
                <Box
                  title="Head"
                  aside={
                    <span className="text-[11px] font-normal text-ink-3">
                      differs from a peer&rsquo;s? you forked
                    </span>
                  }
                >
                  <div className="flex items-start gap-1">
                    <code className="mono text-[12.5px] text-accent">
                      {chain.head || "— empty chain"}
                    </code>
                    {chain.head && <CopyButton value={chain.head} />}
                  </div>
                </Box>

                {checkpoint && (
                  <Box title="Checkpoint">
                    <dl className="kv">
                      {/* `chain.height` — the ledger's entry count — and not
                          `chain.links`. A checkpoint signs the entry count. */}
                      <dt>signed at</dt>
                      <dd className="mono">
                        {checkpoint.checkpoint.height} of {chain.height}
                      </dd>
                      <dt>merkle root</dt>
                      <dd>
                        <Hash value={checkpoint.checkpoint.root} chars={8} />
                      </dd>
                      <dt>ledger head</dt>
                      <dd>
                        <Hash value={checkpoint.checkpoint.head} chars={8} />
                        <div className="text-[11.5px] text-ink-3">
                          {checkpoint.checkpoint.head === chain.ledger_head
                            ? "this node's"
                            : covers === "at"
                              ? "differs from this node's at the same height: not the same log"
                              : "an earlier head of this log"}
                        </div>
                      </dd>
                      <dt>issued</dt>
                      <dd className="mono text-[12px]">
                        {checkpoint.checkpoint.issued_at.replace("T", " ").slice(0, 16)}
                      </dd>
                      <dt>signed by</dt>
                      <dd>
                        <Hash value={checkpoint.public_key} chars={8} />
                      </dd>
                    </dl>
                    {/* Said plainly, because the alternative is a reader
                        assuming the green text means somebody checked. Verifying
                        ML-DSA here would put a third implementation of a
                        consensus-critical primitive in a third language. */}
                    <p className="mt-3 text-[11.5px] leading-relaxed text-ink-3">
                      Shown, not verified: whether that is the key you expected is yours to
                      check, and <code className="mono">cairn verify --from</code> checks the
                      signature.
                    </p>
                  </Box>
                )}

                <p className="px-1 text-[11.5px] leading-relaxed text-ink-3">
                  Verify none of it on trust:{" "}
                  <code className="mono">cairn --log &lt;log&gt; --root . audit</code>{" "}
                  re-derives the chain and checks every batch against the anchor it recorded.
                </p>
              </div>
            </div>
          </>
        )}
      </div>
    </>
  );
}
