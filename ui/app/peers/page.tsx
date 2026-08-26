"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import {
  type Peer,
  NODE_URL,
  age,
  fetchPeers,
  short,
} from "@/lib/peers";
import { type Chain, fetchChain } from "@/lib/chain";
import { type CheckpointResponse, fetchCheckpoint } from "@/lib/checkpoint";

/**
 * The address book this node has been handed.
 *
 * Named "peers" and not "connected peers", because the second thing is not
 * available: live sessions live in `cairn-p2p`, which serves no HTTP, and
 * `cairn-serve` only reads a log file. The page says so rather than letting
 * a reader assume a list of addresses is a list of connections.
 */
export default function Page() {
  const [base, setBase] = useState(NODE_URL);
  const [peers, setPeers] = useState<Peer[] | null>(null);
  const [note, setNote] = useState("");
  const [chain, setChain] = useState<Chain | null>(null);
  const [checkpoint, setCheckpoint] = useState<CheckpointResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async (url: string) => {
    setLoading(true);
    setError(null);
    try {
      const body = await fetchPeers(url);
      setPeers(body.peers);
      setNote(body.note);
      // Neither blocks the page on failure: a node older than the epoch
      // chain has no `/chain`, and an unchecked node has no `/checkpoint` --
      // both are ordinary states `fetchCheckpoint` already treats as such,
      // and `fetchChain` is wrapped the same way here rather than imported
      // for its throwing behaviour, which the chain page wants and this one
      // does not.
      const [nextChain, signed] = await Promise.all([
        fetchChain(url).catch(() => null),
        fetchCheckpoint(url),
      ]);
      setChain(nextChain);
      setCheckpoint(signed);
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
    <main>
      <h1>peers</h1>
      <p className="lede">
        Where identities have <em>announced</em> that they answer. Obtaining the
        log is obtaining the address book, which is why discovery needs no
        second file — but an announcement is not a connection, and nothing
        retracts one. Read this as “who this node could try”, never as “who this
        node is talking to”.
      </p>

      {(chain || checkpoint) && (
        <div className="row stats">
          {chain && <Stat label="chain links" value={String(chain.links)} />}
          {checkpoint && (
            <Stat
              label="checkpoint"
              value={`height ${checkpoint.checkpoint.height}`}
            />
          )}
        </div>
      )}
      {!checkpoint && chain && (
        <p className="meta dim" style={{ marginTop: "-0.75rem", marginBottom: "1.25rem" }}>
          This node has never signed a checkpoint. See the{" "}
          <Link href="/chain">chain</Link> page for what a signature would
          cover, and this node&apos;s <Link href="/log">full log</Link>.
        </p>
      )}

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
          <b>could not read peers</b>
          {error}
        </div>
      )}

      {peers && peers.length === 0 && (
        <>
          <p className="empty">This node&apos;s log names no peers.</p>
          {/* The likeliest reason by far, and worth saying, because an empty
              list reads as a broken page. Nothing writes a peer record
              automatically: the daemon syncs them when they arrive but never
              announces itself, so a log only has them if somebody ran the
              command. */}
          <div className="panel">
            <b>that is the normal state, not a fault</b>
            No peer record is written automatically — the daemon reconciles them
            when they arrive but never announces itself. A node appears in an
            address book only once somebody runs{" "}
            <code>
              cairn peer --identity &lt;file&gt; --transport &lt;peer-id&gt;
              --addr &lt;host:port&gt;
            </code>
            .
          </div>
        </>
      )}

      {peers && peers.length > 0 && (
        <>
          <h2>{peers.length} announced</h2>
          <ul className="cards">
            {peers.map((peer) => (
              <li className="card" key={peer.identity}>
                <div className="card-head">
                  <span className="goal">{peer.addr}</span>
                  <span className="tag">seq {peer.seq}</span>
                </div>
                <dl className="facts">
                  <div>
                    <dt>identity (ed25519)</dt>
                    <dd>
                      <code className="dim" title={peer.identity}>
                        {short(peer.identity)}
                      </code>
                    </dd>
                  </div>
                  <div>
                    <dt>transport id</dt>
                    <dd>
                      <code className="dim" title={peer.transport}>
                        {short(peer.transport)}
                      </code>
                    </dd>
                  </div>
                  <div>
                    <dt>announced</dt>
                    {/* Both, deliberately: the age is what a reader wants and
                        the raw value is what the peer actually said. Timestamps
                        here are self-reported and advisory (`src/time.rs`), so
                        showing only a friendly age would present a peer's own
                        claim as though this node had observed it. */}
                    <dd title={peer.created_at}>
                      {age(peer.created_at) ?? peer.created_at}
                      <span className="dim"> · {peer.created_at}</span>
                    </dd>
                  </div>
                </dl>
              </li>
            ))}
          </ul>
        </>
      )}

      {note && (
        <p className="lede" style={{ marginTop: "2rem" }}>
          {note}
        </p>
      )}
    </main>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="stat">
      <div className="statValue">{value}</div>
      <div className="statLabel">{label}</div>
    </div>
  );
}
