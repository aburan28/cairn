"use client";

import Link from "next/link";
import { useNodeRead } from "@/components/hooks";
import {
  type Peer,
  age,
  fetchPeers,
} from "@/lib/peers";
import { type Chain, fetchChain } from "@/lib/chain";
import { type CheckpointAnswer, readCheckpoint } from "@/lib/checkpoint";
import { Box, EmptyState, Hash, Note, PageHeader, Stat } from "@/components/ui";

/**
 * The address book this node has been handed.
 *
 * Announcements belong to the log; recent session observations belong to
 * Network. Neither list is a promise that a socket remains connected.
 */
export default function Page() {
  const { value, error, loading, refresh } = useNodeRead(async (url) => {
    const body = await fetchPeers(url);
    const [chain, checkpoint] = await Promise.all([fetchChain(url).catch(() => null), readCheckpoint(url)]);
    return { ...body, chain, checkpoint };
  }, { seconds: 30 });
  const peers = value?.peers ?? null;
  const note = value?.note ?? "";
  const chain = value?.chain ?? null;
  const checkpoint = value?.checkpoint ?? null;

  return (
    <>
      <PageHeader
        title="Peers"
        actions={<button className="btn btn-sm" disabled={loading} onClick={() => void refresh()}>Refresh</button>}
        subtitle="Addresses announced in this node's log. For active connections and node types, open Network."
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
          <EmptyState title="No peer announcements in this log">
            That can be normal. A peer can reach this node without an announcement here.{" "}
            <Link href="/network" className="text-accent hover:underline">
              View live topology and node roles →
            </Link>
          </EmptyState>
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
