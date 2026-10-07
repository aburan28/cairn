"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  type NetworkResponse,
  fetchNetwork,
  fleetMembers,
  fleetSigning,
  isLeader,
} from "@/lib/network";
import { CLIENTS, claudeAdd, fleetInvite, fleetJoin, fleetLead, mcpStanza, type AgentClient } from "@/lib/agents";
import { NODE_URL, resolveNode } from "@/lib/site";
import { formatAge } from "@/lib/progress";
import {
  Badge,
  Box,
  CopyButton,
  EmptyState,
  Hash,
  MemberBadge,
  NodeSource,
  Note,
  PageHeader,
  Skeleton,
  Stat,
} from "@/components/ui";

/**
 * The leader, its agents, and how agents connect.
 *
 * Three answers operators ask for in one place: is this node leading a
 * fleet, who is working for it right now, and what an agent pastes to join.
 * The fleet facts come from `GET /network`; the stanzas are the documented
 * shapes with placeholder paths, because this page cannot know the
 * reader's filesystem.
 */
export default function Page() {
  const [base, setBase] = useState(NODE_URL);
  const [network, setNetwork] = useState<NetworkResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [client, setClient] = useState<AgentClient>("claude");

  const load = useCallback(async (url: string) => {
    setLoading(true);
    setError(null);
    try {
      setNetwork(await fetchNetwork(url));
    } catch (cause) {
      setNetwork(null);
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void resolveNode().then((url) => {
      setBase(url || window.location.origin);
      void load(url);
    });
  }, [load]);

  const picker = (
    <NodeSource
      value={base}
      onChange={setBase}
      onRead={() => void load(base === window.location.origin ? "" : base)}
      loading={loading}
    />
  );

  if (error && !network) {
    return (
      <>
        <PageHeader title="Agents" actions={picker} />
        <Note title="Could not read this node" tone="bad">
          {error}
        </Note>
      </>
    );
  }

  if (!network) {
    return (
      <div className="flex flex-col gap-3">
        <PageHeader
          title="Agents"
          subtitle="Whether this node leads, who works for it, and what an agent pastes to connect over MCP."
          actions={picker}
        />
        <div className="mt-3 grid grid-cols-2 gap-3 md:grid-cols-4">
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
        </div>
      </div>
    );
  }

  return <Dashboard network={network} picker={picker} origin={base} client={client} setClient={setClient} />;
}

function Dashboard({
  network,
  picker,
  origin,
  client,
  setClient,
}: {
  network: NetworkResponse;
  picker: React.ReactNode;
  origin: string;
  client: AgentClient;
  setClient: (next: AgentClient) => void;
}) {
  const leader = isLeader(network);
  const fleet = network.node.fleet;
  const liveHosts = useMemo(
    () => (network.compute.hosts?.hosts ?? []).filter((h) => h.status === "live"),
    [network],
  );
  const liveWorkers = useMemo(
    () => network.compute.workers.filter((w) => w.status === "live"),
    [network],
  );
  const nodeUrl = origin === "" || origin === window.location.origin ? window.location.origin : origin;

  return (
    <>
      <PageHeader
        title="Agents"
        subtitle="Whether this node leads, who works for it, and what an agent pastes to connect over MCP."
        meta={
          <>
            {leader ? (
              <Badge tone="accent" title="This node signs submissions for its fleet">
                leader
              </Badge>
            ) : (
              <Badge tone="neutral" title="This node leads no fleet">
                not leading
              </Badge>
            )}
            <Badge tone={liveWorkers.length + liveHosts.length > 0 ? "accent" : "neutral"}>
              {liveWorkers.length} workers · {liveHosts.length} hosts live
            </Badge>
          </>
        }
        actions={picker}
      />

      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat
          label="This node"
          value={leader ? "Leader" : "Memberless"}
          from={fleet ? `signs as ${fleet.signs_as.slice(0, 8)}…` : "leads no fleet"}
          tone={leader ? "accent" : "neutral"}
        />
        <Stat
          label="Enrolled members"
          value={fleet?.members ? String(fleet.members.enrolled) : "—"}
          from={fleet?.members ? `${fleet.members.live} heard from recently` : "no fleet"}
        />
        <Stat
          label="Workers live"
          value={String(liveWorkers.length)}
          from="heartbeating now, reported"
        />
        <Stat
          label="Hosts live"
          value={String(liveHosts.length)}
          from="registered machines, reported"
        />
      </div>

      <div className="mb-5 grid gap-4 lg:grid-cols-2">
        <Box
          title={leader ? "Leading this fleet" : "Not leading a fleet"}
          aside={<span className="text-[11px] font-normal text-accent">this node's own report</span>}
        >
          {fleet ? (
            <>
              <p className="text-[13px] text-ink-2">{fleetSigning(fleet)}</p>
              <div className="mt-1">
                <Hash value={fleet.signs_as} chars={12} />
              </div>
              {fleetMembers(fleet) && (
                <p className="mt-2 text-[12.5px] text-ink-2">{fleetMembers(fleet)}</p>
              )}
              <p className="hint mt-3">
                Sources: <span className="mono">{fleet.sources.join(", ")}</span>. Members
                submit under the leader&rsquo;s id; the leader signs and is paid, while each
                machine keeps its own slice and its own line on the roster. Who is enrolled
                is the operator&rsquo;s business — <span className="mono">cairn fleet list</span> on
                the leader names them.
              </p>
              <div className="mt-3 flex flex-col gap-2">
                <div>
                  <p className="mb-1 text-[12px] text-ink-3">On the leader, invite a machine:</p>
                  <div className="relative">
                    <pre className="code pr-9 text-[11.5px]">{fleetInvite()}</pre>
                    <div className="absolute top-1.5 right-1.5">
                      <CopyButton value={fleetInvite()} />
                    </div>
                  </div>
                </div>
                <div>
                  <p className="mb-1 text-[12px] text-ink-3">On the machine, join:</p>
                  <div className="relative">
                    <pre className="code pr-9 text-[11.5px]">{fleetJoin(nodeUrl)}</pre>
                    <div className="absolute top-1.5 right-1.5">
                      <CopyButton value={fleetJoin(nodeUrl)} />
                    </div>
                  </div>
                </div>
              </div>
            </>
          ) : (
            <>
              <p className="text-[13px] text-ink-2">
                Every worker submits and is paid under its own name. Leading a fleet means
                one id signs for every enrolled machine — useful when a room of machines
                should settle to one account.
              </p>
              <p className="mb-1 mt-3 text-[12px] text-ink-3">To lead:</p>
              <div className="relative">
                <pre className="code pr-9 text-[11.5px]">{fleetLead()}</pre>
                <div className="absolute top-1.5 right-1.5">
                  <CopyButton value={fleetLead()} />
                </div>
              </div>
            </>
          )}
        </Box>

        <Box
          title="Connect an agent over MCP"
          aside={<span className="text-[11px] font-normal text-ink-3">stdio, placeholders in /abs/path</span>}
        >
          <div className="mb-2 flex flex-wrap gap-1.5">
            {CLIENTS.map((option) => (
              <button
                key={option.id}
                type="button"
                className={`btn btn-sm ${client === option.id ? "btn-primary" : ""}`}
                onClick={() => setClient(option.id)}
                title={option.file}
              >
                {option.label}
              </button>
            ))}
          </div>
          <div className="relative">
            <pre className="code pr-9 text-[11.5px]">{mcpStanza(client)}</pre>
            <div className="absolute top-1.5 right-1.5">
              <CopyButton value={mcpStanza(client)} />
            </div>
          </div>
          <p className="hint mt-2">
            In {CLIENTS.find((c) => c.id === client)?.file}. The agent then scores free with{" "}
            <span className="mono">score_candidate</span> and submits with{" "}
            <span className="mono">submit_claim</span> — commit first, reveal after the epoch turns.
          </p>
          {client === "claude" && (
            <>
              <p className="mb-1 mt-3 text-[12px] text-ink-3">Or write it without hand-editing JSON:</p>
              <div className="relative">
                <pre className="code pr-9 text-[11.5px]">{claudeAdd()}</pre>
                <div className="absolute top-1.5 right-1.5">
                  <CopyButton value={claudeAdd()} />
                </div>
              </div>
            </>
          )}
        </Box>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Box
          title={
            <>
              Working for this node{" "}
              <span className="mono ml-1 font-normal text-ink-3">{liveWorkers.length}</span>
            </>
          }
          aside={<span className="text-[11px] font-normal text-warn">reported heartbeats</span>}
        >
          {liveWorkers.length === 0 ? (
            <p className="text-[12.5px] text-ink-3">
              Nobody is heartbeating to this node.{" "}
              <Link href="/contribute" className="text-accent hover:underline">
                Add a machine →
              </Link>
            </p>
          ) : (
            <ul className="flex flex-col gap-2">
              {liveWorkers.slice(0, 10).map((worker) => (
                <li key={`${worker.objective_id}/${worker.worker}`} className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-[12.5px]">
                  <span className="mono text-ink">{worker.worker}</span>
                  <MemberBadge member={worker.member} />
                  <Link
                    href={`/task?id=${encodeURIComponent(worker.objective_id)}`}
                    className="text-accent hover:underline"
                    title={worker.objective_id}
                  >
                    {worker.goal ?? "task"} →
                  </Link>
                  <span className="ml-auto text-[12px] text-ink-3">{formatAge(worker.age_seconds)} ago</span>
                </li>
              ))}
            </ul>
          )}
          {liveWorkers.length > 10 && (
            <p className="mt-2 text-[12px] text-ink-3">
              and {liveWorkers.length - 10} more —{" "}
              <Link href="/network" className="text-accent hover:underline">
                all workers
              </Link>
              .
            </p>
          )}
        </Box>

        <Box
          title={
            <>
              Registered hosts{" "}
              <span className="mono ml-1 font-normal text-ink-3">{liveHosts.length} live</span>
            </>
          }
          aside={<span className="text-[11px] font-normal text-warn">reported by cairn agent</span>}
        >
          {!network.compute.hosts ? (
            <EmptyState title="This node predates host registrations">
              A node built with <span className="mono">POST /hosts</span> lists registered machines here.
            </EmptyState>
          ) : liveHosts.length === 0 ? (
            <p className="text-[12.5px] text-ink-3">
              No host is registered live. <span className="mono">cairn agent install --node …</span> on
              a machine puts it here within a minute.
            </p>
          ) : (
            <ul className="flex flex-col gap-2">
              {liveHosts.slice(0, 10).map((host) => (
                <li key={host.host} className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-[12.5px]">
                  <span className="mono text-ink">{host.host}</span>
                  <MemberBadge member={host.member} />
                  <span className="text-ink-3">
                    {typeof host.hardware?.cpus === "number" ? `${host.hardware.cpus} cpus` : ""}
                    {(host.hardware?.gpus?.length ?? 0) > 0 ? ` · ${host.hardware?.gpus?.length} gpus` : ""}
                    {` · ${host.jobs?.running ?? 0}/${host.jobs?.capacity ?? 0} jobs`}
                  </span>
                  <span className="ml-auto text-[12px] text-ink-3">{formatAge(host.age_seconds)} ago</span>
                </li>
              ))}
            </ul>
          )}
        </Box>
      </div>

      <p className="mt-4 text-[12px] text-ink-3">
        Heartbeats and registrations are what machines said, held in memory and checked by nobody.
        What they earned is on each{" "}
        <Link href="/objectives" className="text-accent hover:underline">
          challenge
        </Link>
        , from the log.
      </p>
    </>
  );
}
