"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useNodeRead } from "@/components/hooks";
import { Box, CopyButton, Hash, LiveStamp, Note, PageHeader, Skeleton } from "@/components/ui";
import { fetchNetwork, fetchSessions } from "@/lib/network";

/** Raw transport facts have one deliberate home, rather than becoming product identity. */
export default function Page() {
  const [origin, setOrigin] = useState("");
  useEffect(() => setOrigin(window.location.origin), []);
  const { base, value, error, readAt, refresh, loading } = useNodeRead(async (url) => {
    const [network, sessions] = await Promise.all([fetchNetwork(url), fetchSessions(url).catch(() => null)]);
    return { network, sessions };
  }, { seconds: 30 });
  let source = base || origin;
  try { source = new URL(source).origin; } catch { source = "Resolving connection…"; }
  const node = value?.network.node;
  const self = value?.network.peers.this_node ?? value?.sessions?.this_node;
  return <>
    <PageHeader title="Diagnostics" subtitle="Technical connection details for troubleshooting. These addresses describe this connection; they are not always reachable from another machine."
      crumb={{ href: "/network", label: "Network" }} actions={<><LiveStamp at={readAt} /><button className="btn btn-sm" disabled={loading} onClick={() => void refresh()}>{loading ? "Refreshing…" : "Refresh"}</button></>} />
    <Box title="Reader connection"><dl className="kv"><dt>Source</dt><dd className="break-all"><code>{source}</code>{source.startsWith("http") && <CopyButton value={source} />}</dd></dl></Box>
    {error && <div className="mt-4"><Note title="Connection details unavailable" tone="bad">{error}</Note></div>}
    {!value && !error && <Skeleton className="mt-4 h-40" />}
    {value && <div className="mt-4 flex flex-col gap-4">
      <Box title="Node endpoints"><dl className="kv">
        <dt>Reader listener</dt><dd className="break-all mono">{node?.reach?.bound ?? "Not reported"}</dd>
        <dt>Peer listener</dt><dd className="break-all mono">{self?.listen ?? "Not reported"}</dd>
        <dt>Advertised reader URLs</dt><dd>{node?.reach?.urls?.length ? node.reach.urls.map((url) => <div className="break-all mono" key={url}>{url}<CopyButton value={url} /></div>) : "None reported"}</dd>
        <dt>Node id</dt><dd>{self?.peer_id ? <Hash value={self.peer_id} /> : "Not reported"}</dd>
        <dt>Version</dt><dd>{value.network.version}</dd>
        <dt>Agent transport</dt><dd>{node?.mcp?.serving ? node.mcp.transport : "Agent connections off"}</dd>
      </dl><p className="mt-3 text-[12px] text-ink-3">A wildcard listener accepts connections on multiple interfaces. A loopback listener is local to its own computer. Neither is a peer address to share.</p></Box>
      <Box title="Peer connection details">
        {value.sessions?.peers.length ? <ul className="divide-y divide-edge">{value.sessions.peers.map((peer) => <li key={peer.peer_id} className="py-3 text-[12px]">
          <Hash value={peer.peer_id} /><div className="mt-1 break-all mono">{peer.addr ?? "Address not reported"}</div>
          {peer.last_error && <p className="mt-1 break-words text-ink-2">{peer.last_error}</p>}
        </li>)}</ul> : <p className="text-[13px] text-ink-2">No peer connection details reported.</p>}
      </Box>
    </div>}
    <p className="mt-4 text-[13px] text-ink-2"><Link href="/network" className="text-accent hover:underline">Back to Network →</Link></p>
  </>;
}
