"use client";

import { useCallback, useEffect, useState } from "react";
import {
  type Peer,
  NODE_URL,
  age,
  fetchPeers,
  short,
} from "@/lib/peers";

/**
 * The address book this node has been handed.
 *
 * Named "peers" and not "connected peers", because the second thing is not
 * available: live sessions live in `proofwork-p2p`, which serves no HTTP, and
 * `proofwork-serve` only reads a log file. The page says so rather than letting
 * a reader assume a list of addresses is a list of connections.
 */
export default function Page() {
  const [base, setBase] = useState(NODE_URL);
  const [peers, setPeers] = useState<Peer[] | null>(null);
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async (url: string) => {
    setLoading(true);
    setError(null);
    try {
      const body = await fetchPeers(url);
      setPeers(body.peers);
      setNote(body.note);
    } catch (cause) {
      setPeers(null);
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
              proofwork peer --identity &lt;file&gt; --transport &lt;peer-id&gt;
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
