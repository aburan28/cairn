"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  type FleetWorker,
  type HostRow,
  type NetworkResponse,
  type PeerAbout,
  type Session,
  type SessionsResponse,
  RouteMissing,
  classLabel,
  describeHost,
  describeReachability,
  fetchNetwork,
  fetchSessions,
  fleetMembers,
  fleetSigning,
  formatMemory,
  formatUptime,
  peerStatus,
  primaryRole,
  reachTone,
  roleWarning,
} from "@/lib/network";
import { type NodeEvent, absorb, fetchEvents } from "@/lib/journal";
import { formatAge, formatMagnitude, formatRate } from "@/lib/progress";
import { type Bridge, appBridge } from "@/lib/draft";
import { AgentConnect, AgentStatus } from "@/components/agents";
import { useEvery, useNode } from "@/components/hooks";
import {
  Badge,
  Box,
  CopyButton,
  Disclosure,
  Hash,
  LiveStamp,
  MemberBadge,
  Note,
  PageHeader,
  Skeleton,
} from "@/components/ui";

/**
 * Seconds between reads while the tab is visible. A peer is `reached` for
 * 120 s after a session and a worker `live` for 180 s after a heartbeat, so
 * twenty seconds sees every change within an interval.
 */
const REFRESH_SECONDS = 20;

const SUBTITLE = "Whom this node has reached, what is working with it, and what it is for: your node, the agents and machines connected to it, and the other nodes it syncs with.";

/**
 * The network as this node sees it, in the order a person asks about it:
 * what is my node, what is connected to it, and the rest.
 *
 * It used to open on three kinds of fact in three colours and a legend
 * explaining them, a five-tile row of counts, a topology diagram and a
 * declared-roles panel that said "no declared role" for a node handing out
 * work all day. The facts are the same and still kept apart -- a peer's
 * hello and a worker's device name are their word, the evidenced roles are
 * the log's -- but each now says so where it is shown, and the primary role
 * is read off what the node does (`primaryRole`), so it is never blank.
 */
export default function Page() {
  const base = useNode();
  const [network, setNetwork] = useState<NetworkResponse | null>(null);
  const [sessions, setSessions] = useState<SessionsResponse | null>(null);
  const [events, setEvents] = useState<{ events: NodeEvent[]; started_at: string | null }>({
    events: [],
    started_at: null,
  });
  const [error, setError] = useState<string | null>(null);
  const [readAt, setReadAt] = useState<Date | null>(null);
  const [bridge, setBridge] = useState<Bridge | null>(null);

  useEffect(() => setBridge(appBridge()), []);

  const load = useCallback(async () => {
    if (base === null) return;
    try {
      // Independently: `/network` reads the log, `/sessions` and `/events` do
      // not, and a node older than either still fills the rest of the page.
      const [nextNetwork, nextSessions, page] = await Promise.all([
        fetchNetwork(base),
        fetchSessions(base).catch((cause: unknown) => {
          if (cause instanceof RouteMissing) return null;
          throw cause;
        }),
        fetchEvents(base).catch(() => null),
      ]);
      setNetwork(nextNetwork);
      setSessions(nextSessions);
      if (page) setEvents((held) => absorb(held, page, 200));
      setReadAt(new Date());
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, [base]);

  useEvery(load, REFRESH_SECONDS, base !== null);

  if (error && !network) {
    return (
      <>
        <PageHeader title="Network" subtitle={SUBTITLE} />
        <Note title="Could not read this node" tone="bad">
          {error}
        </Note>
      </>
    );
  }

  if (!network) {
    return (
      <div className="flex flex-col gap-3">
        <PageHeader title="Network" subtitle={SUBTITLE} actions={<LiveStamp at={null} />} />
        <Skeleton className="h-36 w-full" />
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          <Skeleton className="h-24" />
          <Skeleton className="h-24" />
          <Skeleton className="h-24" />
        </div>
      </div>
    );
  }

  return (
    <Dashboard
      network={network}
      sessions={sessions}
      events={events.events}
      readAt={readAt}
      stale={error}
      bridge={bridge}
    />
  );
}

function Dashboard({
  network,
  sessions,
  events,
  readAt,
  stale,
  bridge,
}: {
  network: NetworkResponse;
  sessions: SessionsResponse | null;
  events: NodeEvent[];
  readAt: Date | null;
  stale: string | null;
  bridge: Bridge | null;
}) {
  const { node, peers, compute } = network;
  const self = peers.this_node ?? sessions?.this_node ?? null;
  const role = useMemo(() => primaryRole(node), [node]);
  const now = readAt?.getTime() ?? Date.now();
  const machines = useMemo(() => machineRows(compute.workers, compute.hosts?.hosts ?? []), [compute]);
  const working = machines.filter((m) => m.status === "live");
  const peerRows = sessions?.available ? sessions.peers : [];
  const connected = peerRows.filter((p) => p.status === "reached").length;
  const mcp = node.mcp;
  const address = node.reach?.urls?.[0] ?? (node.reach?.bound ? `http://${node.reach.bound}` : null);

  return (
    <>
      <PageHeader title="Network" subtitle={SUBTITLE} actions={<LiveStamp at={readAt} error={stale} />} />

      {/* -- your node ------------------------------------------------------- */}
      <section className="card card-pad mb-4 grid gap-5 lg:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
        <div className="min-w-0">
          <div className="text-[11px] font-semibold tracking-[0.08em] text-ink-3 uppercase">Your node</div>
          <div className="mt-1 flex flex-wrap items-center gap-3">
            <h2 className="text-[26px] leading-tight font-semibold text-ink">{role.title}</h2>
            <span className="inline-flex items-center gap-1.5 text-[12.5px] text-ink-2">
              <span className="h-2 w-2 rounded-full bg-accent" aria-hidden />
              online{self ? ` · up ${formatUptime(self.uptime_seconds)}` : ""}
            </span>
          </div>
          <p className="mt-2 max-w-[60ch] text-[13.5px] leading-relaxed text-ink-2">{role.summary}</p>
          {role.also.length > 0 && (
            <p className="mt-2 text-[12.5px] text-ink-2">
              <span className="text-ink-3">Also </span>
              {role.also.join(" · ")}
            </p>
          )}
          {node.warnings.length > 0 && (
            <ul className="mt-2 flex flex-col gap-0.5 text-[12px] text-warn">
              {node.warnings.map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          )}
        </div>
        <dl className="kv self-start">
          <dt>machines use</dt>
          <dd>
            {address ? (
              <span className="inline-flex items-center gap-1">
                <span className="mono text-[12.5px]">{address}</span>
                <CopyButton value={address} />
              </span>
            ) : (
              <span className="text-ink-3">—</span>
            )}
            {node.reach && !node.reach.lan && (
              <div className="text-[11.5px] text-ink-3">this computer only; share it on your network on Contribute</div>
            )}
          </dd>
          {self?.listen && (
            <>
              <dt>nodes dial</dt>
              <dd className="mono text-[12.5px]">{self.listen}</dd>
            </>
          )}
          <dt>from outside</dt>
          <dd>
            <ReachLine network={network} sessions={sessions} />
          </dd>
          {self?.peer_id && (
            <>
              <dt>node id</dt>
              <dd>
                <Hash value={self.peer_id} chars={10} />
              </dd>
            </>
          )}
          <dt>version</dt>
          <dd className="mono text-[12.5px]">{network.version}</dd>
        </dl>
      </section>

      {/* -- what is connected ------------------------------------------------ */}
      <div className="mb-5 grid gap-3 md:grid-cols-3">
        <Summary
          href="#agents"
          label="Agents"
          value={mcp?.serving && mcp.client ? mcp.client.name : mcp?.serving ? "waiting" : "none attached"}
          detail={
            mcp?.serving
              ? `MCP on ${mcp.transport} · ${mcp.calls.toLocaleString("en-US")} call${mcp.calls === 1 ? "" : "s"}`
              : "agents launch a node to attach"
          }
          on={!!(mcp?.serving && mcp.client)}
        />
        <Summary
          href="#machines"
          label="Machines"
          value={`${working.length} working`}
          detail={`${machines.length} known${
            compute.live > 0 && compute.steps_per_second > 0
              ? ` · ${formatRate(compute.steps_per_second)} reported`
              : ""
          }`}
          on={working.length > 0}
        />
        <Summary
          href="#nodes"
          label="Other nodes"
          value={sessions?.available ? `${connected} connected` : peers.available ? `${peers.reached} connected` : "not syncing"}
          detail={
            sessions?.available || peers.available
              ? `${peerRows.length} known · ${peers.announced} in the address book`
              : "this process runs no peer-to-peer service"
          }
          on={connected > 0}
        />
      </div>

      {/* -- agents ---------------------------------------------------------- */}
      <section id="agents" className="mb-5 grid scroll-mt-6 gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <Box title="Agents">
          <AgentStatus mcp={mcp} events={events} now={now} />
        </Box>
        <Box title="Connect an agent">
          <AgentConnect bridge={bridge} />
        </Box>
      </section>

      {/* -- machines -------------------------------------------------------- */}
      <section id="machines" className="mb-5 scroll-mt-6">
        <Box
          title={
            <>
              Machines <span className="mono ml-1 font-normal text-ink-3">{machines.length}</span>
            </>
          }
          aside={
            <Link href="/contribute#compute" className="text-[12px] font-normal text-accent hover:underline">
              Offer compute →
            </Link>
          }
          flush
        >
          {machines.length === 0 ? (
            <p className="px-4 py-6 text-center text-[13px] text-ink-3">
              No machine is working with this node yet. Choose a goal in Contribute to start one.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[44rem] border-collapse text-left text-[12.5px]">
                <thead>
                  <tr className="border-b border-edge text-[11px] text-ink-3">
                    <th className="px-4 py-2 font-medium">Machine</th>
                    <th className="px-3 py-2 font-medium">Working on</th>
                    <th className="px-3 py-2 font-medium">Hardware</th>
                    <th className="px-3 py-2 text-right font-medium">Speed</th>
                    <th className="px-4 py-2 font-medium">Last heard</th>
                  </tr>
                </thead>
                <tbody className="divide-edge-y">
                  {machines.map((machine) => (
                    <MachineLine key={machine.key} machine={machine} />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Box>
        <p className="mt-1.5 px-1 text-[11.5px] text-ink-3">
          Each machine&rsquo;s name, hardware and speed are what it reported, and nobody checks them;
          what it is paid for is decided by each challenge&rsquo;s checker, on the challenge&rsquo;s page.
        </p>
      </section>

      {/* -- other nodes ----------------------------------------------------- */}
      <section id="nodes" className="mb-5 scroll-mt-6">
        <Box
          title={
            <>
              Other nodes <span className="mono ml-1 font-normal text-ink-3">{peerRows.length}</span>
            </>
          }
          aside={
            <Link href="/peers" className="text-[12px] font-normal text-accent hover:underline">
              Address book →
            </Link>
          }
          flush
        >
          <PeersTable sessions={sessions} announced={peers.announced} />
        </Box>
      </section>

      {/* -- the rest -------------------------------------------------------- */}
      <TechnicalDetails network={network} />
    </>
  );
}

function Summary({
  href,
  label,
  value,
  detail,
  on,
}: {
  href: string;
  label: string;
  value: string;
  detail: string;
  on: boolean;
}) {
  return (
    <a href={href} className="tile block transition-colors hover:border-edge-strong hover:bg-surface-2">
      <div className="flex items-center gap-1.5 text-[11.5px] font-medium text-ink-2">
        <span className={`h-1.5 w-1.5 rounded-full ${on ? "bg-accent" : "bg-ink-3"}`} aria-hidden />
        {label}
      </div>
      <div className="mt-1 truncate text-[20px] leading-tight font-semibold text-ink">{value}</div>
      <div className="mt-1 truncate text-[11.5px] text-ink-3">{detail}</div>
    </a>
  );
}

/** Whether a stranger can dial this node, in one badge and a line. */
function ReachLine({ network, sessions }: { network: NetworkResponse; sessions: SessionsResponse | null }) {
  const self = network.peers.this_node ?? sessions?.this_node ?? null;
  const reach = describeReachability(self);
  return (
    <Badge tone={reach.tone} title={reach.detail ?? undefined}>
      {reach.label}
    </Badge>
  );
}

// -- machines --------------------------------------------------------------------

type Machine = {
  key: string;
  name: string;
  member: boolean;
  status: "live" | "stale" | "gone";
  /** What it is working on, as a link target and a title. */
  work: { id: string; title: string } | null;
  hardware: string;
  rate: number | null;
  age: number;
};

/**
 * Workers and registered hosts as one list of machines. A host with a worker
 * on it shows once, as the worker, with the host's hardware; a host with
 * none shows as idle capacity. Never summed: a host is where work could run,
 * a worker is work running.
 */
function machineRows(workers: FleetWorker[], hosts: HostRow[]): Machine[] {
  const rows: Machine[] = [];
  const hostByName = new Map(hosts.map((h) => [h.host, h]));
  const covered = new Set<string>();
  for (const worker of workers) {
    if (worker.status === "gone") continue;
    const hostName = worker.worker.split("/")[0];
    const host = hostByName.get(hostName);
    if (host) covered.add(host.host);
    rows.push({
      key: `w:${worker.objective_id}/${worker.worker}`,
      name: worker.worker,
      member: !!worker.member,
      status: worker.status,
      work: { id: worker.objective_id, title: worker.goal ?? worker.objective_id.slice(7, 15) },
      hardware:
        worker.device !== "unreported"
          ? `${worker.device} · ${classLabel(worker.class)}${worker.lanes ? ` · ${worker.lanes} lanes` : ""}`
          : host
            ? describeHost(host)
            : "unreported",
      rate: worker.status === "live" ? worker.steps_per_second : null,
      age: worker.age_seconds,
    });
  }
  for (const host of hosts) {
    if (covered.has(host.host) || host.status === "gone") continue;
    rows.push({
      key: `h:${host.host}`,
      name: host.host,
      member: !!host.member,
      status: host.status as Machine["status"],
      work: null,
      hardware: describeHost(host),
      rate: null,
      age: host.age_seconds,
    });
  }
  return rows.sort((a, b) => (a.status === b.status ? a.age - b.age : a.status === "live" ? -1 : 1));
}

function MachineLine({ machine }: { machine: Machine }) {
  return (
    <tr className="align-top hover:bg-surface-2">
      <td className="px-4 py-2.5">
        <span className="inline-flex items-center gap-1.5">
          <span
            className={`h-1.5 w-1.5 rounded-full ${machine.status === "live" ? "bg-accent" : "bg-ink-3"}`}
            title={machine.status}
            aria-label={machine.status}
          />
          <span className="mono text-ink">{machine.name}</span>
          <MemberBadge member={machine.member} />
        </span>
      </td>
      <td className="px-3 py-2.5">
        {machine.work ? (
          <Link
            href={`/coordination?id=${encodeURIComponent(machine.work.id)}`}
            className="text-accent hover:underline"
            title={machine.work.id}
          >
            {machine.work.title.replace(/^GOAL-/, "")}
          </Link>
        ) : (
          <span className="text-ink-3">idle</span>
        )}
      </td>
      <td className="px-3 py-2.5 text-ink-2">{machine.hardware}</td>
      <td className="mono px-3 py-2.5 text-right text-ink-2">{formatRate(machine.rate)}</td>
      <td className="mono px-4 py-2.5 text-[12px] text-ink-3">{formatAge(machine.age)}</td>
    </tr>
  );
}

// -- other nodes -----------------------------------------------------------------

function PeersTable({ sessions, announced }: { sessions: SessionsResponse | null; announced: number }) {
  if (!sessions) {
    return (
      <p className="px-4 py-6 text-[13px] text-ink-3">
        This node is older than the session report, so whom it has reached cannot be listed;{" "}
        <Link href="/peers" className="text-accent">
          the address book
        </Link>{" "}
        has the {announced} node{announced === 1 ? "" : "s"} the log names.
      </p>
    );
  }
  if (!sessions.available) {
    return (
      <p className="px-4 py-6 text-[13px] text-ink-3">
        This node is not connected to other nodes. Open Cairn.app&rsquo;s network settings to connect it.
      </p>
    );
  }
  if (sessions.peers.length === 0) {
    return (
      <p className="px-4 py-6 text-[13px] text-ink-3">
        No other node yet. It finds them through the seeds built into it, other nodes on this network,
        and the address book ({announced} announced).
        {sessions.this_node && <> Up for {formatUptime(sessions.this_node.uptime_seconds)}.</>}
      </p>
    );
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[44rem] border-collapse text-left text-[12.5px]">
        <thead>
          <tr className="border-b border-edge text-[11px] text-ink-3">
            <th className="px-4 py-2 font-medium">Node</th>
            <th className="px-3 py-2 font-medium">Status</th>
            <th className="px-3 py-2 font-medium">Address</th>
            <th className="px-3 py-2 font-medium" title="What it said it is when it connected: its word, unchecked">
              Says it is
            </th>
            <th className="px-4 py-2 font-medium">Last problem</th>
          </tr>
        </thead>
        <tbody className="divide-edge-y">
          {sessions.peers.map((peer) => (
            <PeerLine key={peer.peer_id} peer={peer} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function PeerLine({ peer }: { peer: Session }) {
  return (
    <tr className="align-top hover:bg-surface-2">
      <td className="px-4 py-2.5">
        <Hash value={peer.peer_id} chars={8} />
      </td>
      <td className="px-3 py-2.5">
        <Badge tone={reachTone(peer.status)}>{peerStatus(peer)}</Badge>
        <div className="mt-0.5 text-[11px] text-ink-3">
          {peer.inbound_ok + peer.outbound_ok} session{peer.inbound_ok + peer.outbound_ok === 1 ? "" : "s"}
          {peer.age_seconds !== null && `, last ${peer.last_direction === "inbound" ? "from it" : "to it"}`}
        </div>
      </td>
      <td className="mono px-3 py-2.5 text-ink-2">{peer.addr ?? "—"}</td>
      <td className="px-3 py-2.5">
        <PeerSays about={peer.about} />
      </td>
      <td className="px-4 py-2.5 text-[11.5px] text-ink-3" title={peer.last_failed_at ?? undefined}>
        {peer.last_error ?? "—"}
      </td>
    </tr>
  );
}

function PeerSays({ about }: { about: PeerAbout | null | undefined }) {
  if (!about) return <span className="text-ink-3">—</span>;
  return (
    <div className="flex flex-col gap-0.5 text-[11.5px]">
      <div className="flex flex-wrap gap-1">
        {about.roles.length === 0 ? (
          <span className="text-ink-3">no role named</span>
        ) : (
          about.roles.map((role) => (
            <Badge key={role} tone="neutral">
              {role}
            </Badge>
          ))
        )}
      </div>
      <span className="text-ink-3">
        {about.verifiers.length ? `checks ${about.verifiers.join(", ")}` : "checks nothing"}
        {about.version && <span className="mono"> · {about.version}</span>}
      </span>
    </div>
  );
}

// -- technical details -----------------------------------------------------------

function TechnicalDetails({ network }: { network: NetworkResponse }) {
  const { node, roles } = network;
  return (
    <Disclosure summary="Technical details: this machine, checkers, declared roles, and what the log shows">
      <div className="grid gap-5 lg:grid-cols-2">
        <dl className="kv">
          <dt>machine</dt>
          <dd className="mono text-[12px]">
            {node.hardware.cpus ?? "?"} cpus · {formatMemory(node.hardware.memory_mb)} · {node.hardware.os}/
            {node.hardware.arch}
          </dd>
          <dt>per checker</dt>
          <dd className="mono text-[12px]">
            {node.hardware.verifier_limits.cpus ?? "all"} cpus ·{" "}
            {node.hardware.verifier_limits.memory_mb
              ? formatMemory(node.hardware.verifier_limits.memory_mb)
              : "default memory"}
          </dd>
          <dt>can check</dt>
          <dd>
            {node.verifiers.servable.length === 0 ? (
              <span className="text-warn">nothing on this host</span>
            ) : (
              <span className="mono text-[12px]">{node.verifiers.servable.join(", ")}</span>
            )}
            {Object.entries(node.verifiers.unservable).map(([kind, why]) => (
              <div key={kind} className="text-[11.5px] text-ink-3">
                <span className="mono">{kind}</span>: {why}
              </div>
            ))}
          </dd>
          <dt>submissions</dt>
          <dd className="text-[12.5px]">{node.accepts_submissions ? "accepted, then admitted by the rules" : "refused: read-only"}</dd>
          {node.fleet && (
            <>
              <dt>fleet</dt>
              <dd className="text-[12.5px] text-ink-2">
                {fleetSigning(node.fleet)} <Hash value={node.fleet.signs_as} chars={10} />
                {fleetMembers(node.fleet) && <div className="text-[11.5px] text-ink-3">{fleetMembers(node.fleet)}</div>}
              </dd>
            </>
          )}
          {node.peers_policy && node.peers_policy.policy !== "open" && (
            <>
              <dt>peers with</dt>
              <dd className="text-[12.5px]">
                {node.peers_policy.allowed ?? "?"} allowed node{node.peers_policy.allowed === 1 ? "" : "s"} only
              </dd>
            </>
          )}
          <dt>declared</dt>
          <dd>
            {node.roles.declared.length === 0 ? (
              <span className="text-[12px] text-ink-3">
                nothing in <span className="mono">{node.roles.source}</span>; the role above is read off what the
                node does
              </span>
            ) : (
              <ul className="flex flex-col gap-1">
                {node.roles.declared.map((name) => {
                  const known = node.roles.known.find((k) => k.role === name);
                  const warning = roleWarning(name, node.warnings);
                  return (
                    <li key={name} className="text-[12px]">
                      <Badge tone={warning ? "warn" : "accent"}>{name}</Badge>{" "}
                      <span className="text-ink-2">{known?.duty}</span>
                    </li>
                  );
                })}
              </ul>
            )}
          </dd>
        </dl>
        <div className="flex flex-col gap-3 text-[12.5px]">
          <div className="font-medium text-ink">What the log shows, recomputed from it</div>
          <Evidenced
            label="Funded challenges"
            total={roles.coordinators.total}
            rows={roles.coordinators.identities.map((r) => ({
              identity: r.identity,
              detail: `${r.objectives} challenge${r.objectives === 1 ? "" : "s"} · ${formatMagnitude(r.reward_total)} funded`,
            }))}
          />
          <Evidenced
            label="Had answers accepted"
            total={roles.executors.total}
            rows={roles.executors.identities.map((r) => ({
              identity: r.identity,
              detail: `${r.accepted_claims} accepted on ${r.objectives} challenge${r.objectives === 1 ? "" : "s"}`,
            }))}
          />
          <Evidenced
            label="Checked answers under bond"
            total={roles.verifiers.total}
            rows={roles.verifiers.identities.map((r) => ({
              identity: r.identity,
              detail: `${r.attestations} check${r.attestations === 1 ? "" : "s"}${r.slashed ? ` · ${r.slashed} slashed` : ""}`,
            }))}
          />
          <p className="text-[11.5px] text-ink-3">
            The only authority on the network is each challenge&rsquo;s pinned checker. A role is a description of
            what a node does, never a permission.
          </p>
        </div>
      </div>
    </Disclosure>
  );
}

function Evidenced({
  label,
  total,
  rows,
}: {
  label: string;
  total: number;
  rows: { identity: string; detail: string }[];
}) {
  return (
    <div>
      <div className="text-ink-2">
        {label} <span className="mono text-ink-3">{total}</span>
      </div>
      {rows.length === 0 ? (
        <div className="text-[12px] text-ink-3">nobody yet</div>
      ) : (
        <ul className="mt-1 flex flex-col gap-1">
          {rows.slice(0, 4).map((row) => (
            <li key={row.identity} className="flex flex-wrap items-center gap-2 text-[12px]">
              <Hash value={row.identity} chars={8} />
              <span className="text-ink-3">{row.detail}</span>
            </li>
          ))}
          {total > Math.min(rows.length, 4) && (
            <li className="text-[11.5px] text-ink-3">and {total - Math.min(rows.length, 4)} more</li>
          )}
        </ul>
      )}
    </div>
  );
}
