"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import {
  type Peer,
  NODE_URL,
  age,
  fetchPeers,
} from "@/lib/peers";
import { resolveNode } from "@/lib/site";
import { type Chain, fetchChain } from "@/lib/chain";
import { type CheckpointAnswer, readCheckpoint } from "@/lib/checkpoint";
import { Box, EmptyState, Hash, NodePicker, Note, PageHeader, Stat } from "@/components/ui";

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

  return (
    <>
      <PageHeader
        title="Peers"
        subtitle="Who has announced that they answer. An announcement is not a connection: read this as who this node could try, not who it is talking to."
        actions={
          <NodePicker
            value={base}
            onChange={setBase}
            onRead={() => void load(base)}
            loading={loading}
          />
        }
      />

      {(chain || checkpoint?.kind === "signed") && (
        <div className="mb-4 grid grid-cols-2 gap-3 sm:max-w-md">
          {chain && <Stat label="Chain links" value={String(chain.links)} />}
          {checkpoint?.kind === "signed" && (
            <Stat label="Checkpoint" value={`height ${checkpoint.value.checkpoint.height}`} />
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
          <Box
            title={
              <>
                Announced <span className="mono ml-1 font-normal text-ink-3">{peers.length}</span>
              </>
            }
            flush
          >
            <div className="overflow-x-auto">
              <table className="w-full min-w-[40rem] border-collapse text-left text-[12.5px]">
                <thead>
                  <tr className="border-b border-edge text-[11.5px] text-ink-3">
                    <th className="px-4 py-2 font-medium">Address</th>
                    <th className="px-3 py-2 font-medium">Identity (ed25519)</th>
                    <th className="px-3 py-2 font-medium">Transport id</th>
                    <th className="px-3 py-2 font-medium">Seq</th>
                    <th className="px-4 py-2 font-medium">Announced</th>
                  </tr>
                </thead>
                <tbody className="divide-edge-y">
                  {peers.map((peer) => (
                    <tr key={peer.identity}>
                      <td className="mono px-4 py-2.5 font-semibold text-ink">{peer.addr}</td>
                      <td className="px-3 py-2.5">
                        <Hash value={peer.identity} chars={8} />
                      </td>
                      <td className="px-3 py-2.5">
                        <Hash value={peer.transport} chars={8} />
                      </td>
                      <td className="mono px-3 py-2.5 text-ink-2">{peer.seq}</td>
                      {/* The age is what a reader wants; the raw value, on
                          hover, is what the peer actually said. Timestamps here
                          are self-reported and advisory (`src/time.rs`). */}
                      <td className="px-4 py-2.5 text-ink-2" title={`self-reported: ${peer.created_at}`}>
                        {age(peer.created_at) ?? peer.created_at}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Box>
        )}

        {note && <p className="text-[12px] leading-relaxed text-ink-3">{note}</p>}
      </div>
    </>
  );
}
