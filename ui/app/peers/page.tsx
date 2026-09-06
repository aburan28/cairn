"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { type Peer, NODE_URL, age, fetchPeers } from "@/lib/peers";
import { type Chain, fetchChain } from "@/lib/chain";
import { type CheckpointAnswer, readCheckpoint } from "@/lib/checkpoint";
import { Badge, Card, EmptyState, Hash, Note, SectionHeading, Stat } from "@/components/ui";

/**
 * The address book this node has been handed.
 *
 * Named "peers" and not "connected peers", because the second thing is not
 * available: live sessions live in the p2p service, which publishes nothing
 * over HTTP, and the HTTP server (`cairn serve`, or the `--serve` thread of
 * `cairn p2p` / `cairn run`) only reads a log file. The page says so rather
 * than letting a reader assume a list of addresses is a list of connections.
 */
export default function Page() {
  const [base, setBase] = useState(NODE_URL);
  const [peers, setPeers] = useState<Peer[] | null>(null);
  const [note, setNote] = useState("");
  const [chain, setChain] = useState<Chain | null>(null);
  const [checkpoint, setCheckpoint] = useState<CheckpointAnswer | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async (url: string) => {
    setLoading(true);
    setError(null);
    try {
      const body = await fetchPeers(url);
      setPeers(body.peers);
      setNote(body.note);
      // Neither blocks the page on failure: a node older than the epoch chain
      // has no `/chain`, and an unchecked node has no `/checkpoint` --
      // `readCheckpoint` never throws and names which of its states this is,
      // and `fetchChain` is wrapped here rather than imported for its throwing
      // behaviour, which the chain page wants and this one does not.
      const [nextChain, answer] = await Promise.all([
        fetchChain(url).catch(() => null),
        readCheckpoint(url),
      ]);
      setChain(nextChain);
      setCheckpoint(answer);
    } catch (cause) {
      setPeers(null);
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

  return (
    <>
      <header className="mb-6 max-w-[62rem]">
        <h1 className="text-[26px] font-semibold">Peers</h1>
        <p className="prose-block mt-2">
          Where identities have <em>announced</em> that they answer. Obtaining the log
          is obtaining the address book, which is why discovery needs no second file —
          but an announcement is not a connection, and nothing retracts one. Read this
          as &ldquo;who this node could try&rdquo;, never as &ldquo;who this node is
          talking to&rdquo;.
        </p>
      </header>

      {(chain || checkpoint?.kind === "signed") && (
        <div className="mb-4 grid grid-cols-2 gap-3 sm:max-w-md">
          {chain && <Stat label="chain links" value={String(chain.links)} />}
          {checkpoint?.kind === "signed" && (
            <Stat label="checkpoint" value={`height ${checkpoint.value.checkpoint.height}`} />
          )}
        </div>
      )}

      {/* Only the node's own "no checkpoint" earns this sentence. A
          `/checkpoint` that answered wrongly is said as that, and a 404 that is
          not the node's says nothing about a node at all. */}
      {checkpoint?.kind === "unsigned" && chain && (
        <p className="mb-4 text-[12.5px] text-ink-3">
          This node has never signed a checkpoint. See the{" "}
          <Link href="/chain" className="text-accent hover:underline">
            chain
          </Link>{" "}
          page for what a signature would cover, and this node&rsquo;s{" "}
          <Link href="/log" className="text-accent hover:underline">
            full log
          </Link>
          .
        </p>
      )}

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
        {checkpoint?.kind === "unreadable" && (
          <Note title="could not read this node's checkpoint" tone="bad">
            {checkpoint.message}
          </Note>
        )}

        {error && (
          <Note title="could not read peers" tone="bad">
            {error}
          </Note>
        )}

        {peers && peers.length === 0 && (
          <>
            <EmptyState title="This node's log names no peers." />
            {/* The likeliest reason by far, and worth saying, because an empty
                list reads as a broken page. Nothing writes a peer record
                automatically: the daemon syncs them when they arrive but never
                announces itself, so a log only has them if somebody ran the
                command. */}
            <Note title="that is the normal state, not a fault">
              No peer record is written automatically — the daemon reconciles them when
              they arrive but never announces itself. A node appears in an address book
              only once somebody runs{" "}
              <code className="mono">
                cairn peer --identity &lt;file&gt; --transport &lt;peer-id&gt; --addr
                &lt;host:port&gt;
              </code>
              .
            </Note>
          </>
        )}

        {peers && peers.length > 0 && (
          <section>
            <SectionHeading count={peers.length}>Announced</SectionHeading>
            <ul className="grid gap-3 md:grid-cols-2">
              {peers.map((peer) => (
                <Card as="li" key={peer.identity} className="card-pad flex flex-col gap-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="mono text-[13px] font-semibold">{peer.addr}</span>
                    <Badge>seq {peer.seq}</Badge>
                  </div>
                  <dl className="grid gap-2 text-[12.5px] sm:grid-cols-2">
                    <div>
                      <dt className="text-[11px] text-ink-3">identity (ed25519)</dt>
                      <dd className="mt-0.5">
                        <Hash value={peer.identity} chars={8} />
                      </dd>
                    </div>
                    <div>
                      <dt className="text-[11px] text-ink-3">transport id</dt>
                      <dd className="mt-0.5">
                        <Hash value={peer.transport} chars={8} />
                      </dd>
                    </div>
                    <div className="sm:col-span-2">
                      <dt className="text-[11px] text-ink-3">announced</dt>
                      {/* Both, deliberately: the age is what a reader wants and
                          the raw value is what the peer actually said.
                          Timestamps here are self-reported and advisory
                          (`src/time.rs`), so showing only a friendly age would
                          present a peer's own claim as though this node had
                          observed it. */}
                      <dd className="mt-0.5" title={peer.created_at}>
                        {age(peer.created_at) ?? peer.created_at}
                        <span className="mono ml-1.5 text-ink-3">{peer.created_at}</span>
                      </dd>
                    </div>
                  </dl>
                </Card>
              ))}
            </ul>
          </section>
        )}

        {note && <p className="prose-block mt-2">{note}</p>}
      </div>
    </>
  );
}
