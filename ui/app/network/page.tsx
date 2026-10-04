"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  type FleetWorker,
  type NetworkResponse,
  type Session,
  type SessionsResponse,
  NODE_URL,
  RouteMissing,
  classLabel,
  describeReachability,
  fetchNetwork,
  fetchSessions,
  fleetTotals,
  formatMemory,
  formatUptime,
  reachTone,
  roleWarning,
  share,
  sumByClass,
} from "@/lib/network";
import { formatAge, formatMagnitude, formatRate } from "@/lib/progress";
import { resolveNode } from "@/lib/site";
import {
  Badge,
  Box,
  EmptyState,
  Hash,
  NodePicker,
  Note,
  PageHeader,
  Progress,
  SectionHeading,
  Skeleton,
  Stat,
} from "@/components/ui";

/**
 * Seconds between reads while the tab is visible. A peer is `reached` for
 * 120 s after a session and a worker `live` for 180 s after a heartbeat, so
 * twenty seconds sees every change within an interval without asking a node
 * to re-read its log faster than anything on it moves.
 */
const REFRESH_SECONDS = 20;

/**
 * The network as this node sees it.
 *
 * Two routes, `GET /network` and `GET /sessions`, and three kinds of fact on
 * one page, labelled apart because they are not equally trustworthy:
 *
 * - what this node **declares** (its roles) and can see of its own machine;
 * - what peers and workers **did and said** recently -- sessions that
 *   completed, heartbeats that arrived -- held in the node's memory and
 *   verified by nobody;
 * - what the **log evidences**: who funded, whose claims were accepted, who
 *   attested. The one part a reader can check.
 *
 * The page never adds a number from one kind to a number from another. An
 * announcement in the log is not a session, a reported rate is not a paid
 * unit, and a declared role is not a thing the log shows anyone doing.
 */
export default function Page() {
  const [base, setBase] = useState(NODE_URL);
  const [network, setNetwork] = useState<NetworkResponse | null>(null);
  const [sessions, setSessions] = useState<SessionsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [readAt, setReadAt] = useState<Date | null>(null);
  const [showGone, setShowGone] = useState(false);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const load = useCallback(async (url: string, quiet = false) => {
    if (!quiet) setLoading(true);
    setError(null);
    try {
      // Independently: `/network` reads the log and `/sessions` does not, so a
      // node that answers one and not the other still fills half the page.
      const [nextNetwork, nextSessions] = await Promise.all([
        fetchNetwork(url),
        fetchSessions(url).catch((cause: unknown) => {
          if (cause instanceof RouteMissing) return null;
          throw cause;
        }),
      ]);
      setNetwork(nextNetwork);
      setSessions(nextSessions);
      setReadAt(new Date());
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
      if (!quiet) {
        setNetwork(null);
        setSessions(null);
      }
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

  // Re-read on an interval while the tab is visible, as the task page does.
  useEffect(() => {
    if (!network) return;
    const target = base === window.location.origin ? "" : base;
    const start = () => {
      if (timer.current) clearInterval(timer.current);
      timer.current = setInterval(() => void load(target, true), REFRESH_SECONDS * 1000);
    };
    const onVisibility = () => {
      if (document.visibilityState === "visible") {
        void load(target, true);
        start();
      } else if (timer.current) {
        clearInterval(timer.current);
        timer.current = null;
      }
    };
    start();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      if (timer.current) clearInterval(timer.current);
      document.removeEventListener("visibilitychange", onVisibility);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [base, load, network !== null]);

  const picker = (
    <NodePicker
      value={base}
      onChange={setBase}
      onRead={() => void load(base === window.location.origin ? "" : base)}
      loading={loading}
    />
  );

  if (error && !network) {
    return (
      <>
        <PageHeader title="Network" actions={picker} />
        <Note title="Could not read this node" tone="bad">
          {error}
          {error.includes("newer than the node") && (
            <>
              {" "}
              Until then, the log&rsquo;s address book is on{" "}
              <Link href="/peers" className="text-accent">
                the peers page
              </Link>
              .
            </>
          )}
        </Note>
      </>
    );
  }

  if (!network) {
    // The header renders before the node answers, so the page has a name
    // while the numbers are on their way -- and so the static export carries
    // a sentence the smoke test can look for.
    return (
      <div className="flex flex-col gap-3">
        <PageHeader
          title="Network"
          subtitle="Whom this node has reached, what is heartbeating to it, and what it says it is for. Three kinds of fact, kept apart and labelled."
          actions={picker}
        />
        <div className="mt-3 grid grid-cols-2 gap-3 md:grid-cols-5">
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
        </div>
      </div>
    );
  }

  return (
    <Dashboard
      network={network}
      sessions={sessions}
      picker={picker}
      readAt={readAt}
      origin={base}
      stale={error}
      showGone={showGone}
      setShowGone={setShowGone}
    />
  );
}

function Dashboard({
  network,
  sessions,
  picker,
  readAt,
  origin,
  stale,
  showGone,
  setShowGone,
}: {
  network: NetworkResponse;
  sessions: SessionsResponse | null;
  picker: React.ReactNode;
  readAt: Date | null;
  origin: string;
  stale: string | null;
  showGone: boolean;
  setShowGone: (next: boolean) => void;
}) {
  const { node, peers, compute, roles } = network;
  const shown = useMemo(
    () => compute.workers.filter((worker) => showGone || worker.status !== "gone"),
    [compute.workers, showGone],
  );
  const totals = useMemo(() => fleetTotals(shown), [shown]);
  const classes = useMemo(() => sumByClass(shown), [shown]);
  const book = peers.address_book ?? sessions?.address_book ?? null;
  const self = peers.this_node ?? sessions?.this_node ?? null;
  const reach = useMemo(() => describeReachability(self), [self]);

  return (
    <>
      <PageHeader
        title="Network"
        subtitle="Whom this node has reached, what is heartbeating to it, and what it says it is for. Three kinds of fact, kept apart and labelled."
        meta={
          <>
            {node.roles.declared.length > 0 ? (
              node.roles.declared.map((role) => (
                <Badge key={role} tone="info" title={`declared with ${node.roles.source}`}>
                  {role}
                </Badge>
              ))
            ) : (
              <Badge tone="neutral" title={`nothing set in ${node.roles.source}`}>
                no declared role
              </Badge>
            )}
            {self?.peer_id && <Hash value={self.peer_id} chars={8} label="peer" />}
            <span className="mono text-ink-3">v{network.version}</span>
          </>
        }
        actions={picker}
      />

      <p className="mb-4 text-[12px] text-ink-3">
        Read from <span className="mono">{origin}</span>
        {readAt && <> at {readAt.toLocaleTimeString()}</>}, again every {REFRESH_SECONDS} s while
        this tab is visible. <span className="text-info">Declared</span> is what this node says;{" "}
        <span className="text-warn">reported</span> is what peers and workers did and said, held in
        memory and checked by nobody; <span className="text-accent">evidenced</span> is recomputed
        from the log.
        {stale && <span className="text-bad"> The last re-read failed: {stale}</span>}
      </p>

      {/* -- the numbers --------------------------------------------------- */}
      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-5">
        <Stat
          label="Peers reached"
          value={peers.available ? String(peers.reached) : "—"}
          from={
            peers.available
              ? `${peers.recent} recent · ${peers.lost} lost · ${peers.unreached} never reached`
              : "this process runs no p2p service"
          }
          tone={peers.available && peers.reached > 0 ? "accent" : "neutral"}
        />
        <Stat
          label="Address book"
          value={book ? String(book.endpoints) : "—"}
          from={
            book
              ? `dialable now · ${book.hints} hints · ${peers.announced} announced in the log`
              : `${peers.announced} announced in the log`
          }
          tone="neutral"
        />
        <Stat
          label="Workers live"
          value={String(totals.live)}
          from={`${totals.stale} stale · ${compute.gone} gone · ${compute.objectives.length} objective${
            compute.objectives.length === 1 ? "" : "s"
          }`}
          tone={totals.live > 0 ? "accent" : "neutral"}
        />
        <Stat
          label="Compute, reported"
          value={formatRate(totals.live > 0 ? totals.steps_per_second : null)}
          from="summed over live workers; measured by the node where it could"
          tone="warn"
        />
        <Stat
          label="Lanes, reported"
          value={totals.live > 0 ? formatMagnitude(totals.lanes) : "—"}
          from="threads or SIMD lanes the live workers say they run"
          tone="warn"
        />
      </div>

      {/* -- this node --------------------------------------------------- */}
      <div className="mb-5 grid gap-4 lg:grid-cols-2">
        <Box title="This node" aside={<span className="text-[11px] font-normal text-info">declared, and probed at startup</span>}>
          <dl className="kv">
            <dt>roles</dt>
            <dd>
              {node.roles.declared.length === 0 ? (
                <span className="text-ink-3">
                  none declared — set <span className="mono">{node.roles.source}</span>
                </span>
              ) : (
                <ul className="flex flex-col gap-1.5">
                  {node.roles.declared.map((role) => {
                    const warning = roleWarning(role, node.warnings);
                    const known = node.roles.known.find((k) => k.role === role);
                    return (
                      <li key={role} className="flex flex-wrap items-baseline gap-2">
                        <Badge tone={warning ? "warn" : "info"}>{role}</Badge>
                        <span className="text-[12px] text-ink-2">{known?.duty}</span>
                        {warning && <span className="text-[12px] text-warn">{warning}</span>}
                      </li>
                    );
                  })}
                </ul>
              )}
            </dd>
            <dt>accepts submissions</dt>
            <dd className="mono">{node.accepts_submissions ? "yes (--queue)" : "no: read-only"}</dd>
            <dt>reconciles</dt>
            <dd className="mono">{node.runs_p2p ? "yes: a p2p service runs here" : "no: a plain publisher"}</dd>
            {self && (
              <>
                <dt>listens</dt>
                <dd className="mono">{self.listen ?? "—"}</dd>
                <dt>up for</dt>
                <dd className="mono">{formatUptime(self.uptime_seconds)}</dd>
                <dt>from outside</dt>
                <dd>
                  <div className="flex flex-wrap items-baseline gap-2">
                    <Badge tone={reach.tone} title="the router's claim and the roster's evidence, read together">
                      {reach.label}
                    </Badge>
                    {reach.detail && <span className="text-[12px] text-ink-2">{reach.detail}</span>}
                  </div>
                </dd>
              </>
            )}
            <dt>machine</dt>
            <dd className="mono">
              {node.hardware.cpus ?? "?"} cpus · {formatMemory(node.hardware.memory_mb)} ·{" "}
              {node.hardware.os}/{node.hardware.arch}
            </dd>
            <dt>per verifier</dt>
            <dd className="mono">
              {node.hardware.verifier_limits.cpus ?? "all"} cpus ·{" "}
              {node.hardware.verifier_limits.memory_mb
                ? formatMemory(node.hardware.verifier_limits.memory_mb)
                : "default memory"}
            </dd>
            <dt>can verify</dt>
            <dd>
              {node.verifiers.servable.length === 0 ? (
                <span className="text-warn">nothing on this host</span>
              ) : (
                <span className="mono">{node.verifiers.servable.join(", ")}</span>
              )}
              {Object.keys(node.verifiers.unservable).length > 0 && (
                <ul className="mt-1 text-[11.5px] text-ink-3">
                  {Object.entries(node.verifiers.unservable).map(([kind, why]) => (
                    <li key={kind}>
                      <span className="mono">{kind}</span>: {why}
                    </li>
                  ))}
                </ul>
              )}
            </dd>
          </dl>
          <p className="hint mt-3">{node.hardware.note}</p>
        </Box>

        <Box
          title="What a role means here"
          aside={<span className="text-[11px] font-normal text-ink-3">a hint about intent, never a permission</span>}
        >
          <ul className="flex flex-col gap-2 text-[12.5px]">
            {node.roles.known.map((known) => (
              <li key={known.role} className="flex flex-col gap-0.5">
                <div className="flex items-baseline gap-2">
                  <span className="mono font-semibold text-ink">{known.role}</span>
                  <span className="text-ink-2">{known.duty}</span>
                </div>
                <div className="text-[11.5px] text-ink-3">evidence in the log: {known.evidence}</div>
              </li>
            ))}
          </ul>
          <p className="hint mt-3">
            The only authority on this network is a pinned verifier&rsquo;s verdict. A node that
            declares <span className="mono">coordinator</span> gets no say over what settles; a node
            that declares <span className="mono">verifier</span> is believed exactly as far as the
            bond behind each attestation. The declaration buys legibility: a reader sees what the
            operator intends and checks it against what the node can do and what the log shows.
          </p>
        </Box>
      </div>

      {/* -- sessions ---------------------------------------------------- */}
      <SectionHeading
        count={sessions?.available ? sessions.peers.length : undefined}
        aside={
          sessions?.available ? (
            <span className="text-[11px] text-ink-3">
              reached within {sessions.reached_within_seconds ?? 120} s · recent within{" "}
              {sessions.recent_within_seconds ?? 1800} s · a session is one exchange, not a held
              connection
            </span>
          ) : undefined
        }
      >
        Sessions
      </SectionHeading>
      <SessionsTable sessions={sessions} announced={peers.announced} />

      {/* -- hardware ---------------------------------------------------- */}
      <SectionHeading
        count={compute.devices.length}
        aside={
          <label className="flex cursor-pointer items-center gap-1.5 text-[11.5px] text-ink-3">
            <input
              type="checkbox"
              checked={showGone}
              onChange={(event) => setShowGone(event.target.checked)}
            />
            include workers gone for over 30 min
          </label>
        }
      >
        Hardware on the network
      </SectionHeading>
      <div className="mb-5 grid gap-4 lg:grid-cols-[22rem_minmax(0,1fr)]">
        <Box title="By class" aside={<span className="text-[11px] font-normal text-warn">reported</span>}>
          {classes.length === 0 ? (
            <p className="text-[12.5px] text-ink-3">No worker has reported hardware.</p>
          ) : (
            <ul className="flex flex-col gap-3">
              {classes.map((row) => (
                <li key={row.class}>
                  <div className="mb-1 flex items-baseline justify-between gap-2 text-[12.5px]">
                    <span className="font-medium text-ink">{classLabel(row.class)}</span>
                    <span className="mono text-ink-2">
                      {row.live}/{row.workers} live · {formatRate(row.live > 0 ? row.steps_per_second : null)}
                    </span>
                  </div>
                  <Progress value={share(row.steps_per_second, totals.steps_per_second)} tone="warn" />
                </li>
              ))}
            </ul>
          )}
          <p className="hint mt-3">
            The class is the node&rsquo;s heuristic over what each worker called its device; a worker
            that calls its box <span className="mono">rig-3</span> is <em>other</em>, and that is the
            right answer.
          </p>
        </Box>
        <Box title="By device" flush>
          {compute.devices.length === 0 ? (
            <div className="box-body text-[12.5px] text-ink-3">
              Nothing yet. A worker names its hardware with <span className="mono">--device</span>{" "}
              on the reference worker, and it appears here within a minute of its first heartbeat.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[36rem] border-collapse text-left text-[12.5px]">
                <thead>
                  <tr className="border-b border-edge text-[11px] text-ink-3">
                    <th className="px-4 py-2 font-medium">Device</th>
                    <th className="px-3 py-2 font-medium">Class</th>
                    <th className="px-3 py-2 text-right font-medium">Workers</th>
                    <th className="px-3 py-2 text-right font-medium">Live</th>
                    <th className="px-3 py-2 text-right font-medium">
                      <span className="text-warn">Rate</span>
                    </th>
                    <th className="px-4 py-2 text-right font-medium">
                      <span className="text-warn">Lanes</span>
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-edge-y">
                  {compute.devices.map((row) => (
                    <tr key={`${row.device}/${row.class}`} className="hover:bg-surface-2">
                      <td className="mono px-4 py-2 text-ink">{row.device}</td>
                      <td className="px-3 py-2">
                        <Badge tone="neutral">{classLabel(row.class)}</Badge>
                      </td>
                      <td className="mono px-3 py-2 text-right text-ink-2">{row.workers}</td>
                      <td className="mono px-3 py-2 text-right text-ink-2">{row.live}</td>
                      <td className="mono px-3 py-2 text-right text-ink-2">
                        {formatRate(row.live > 0 ? row.steps_per_second : null)}
                      </td>
                      <td className="mono px-4 py-2 text-right text-ink-2">
                        {row.live > 0 ? formatMagnitude(row.lanes) : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Box>
      </div>

      {/* -- workers ----------------------------------------------------- */}
      <SectionHeading
        count={shown.length}
        aside={
          <span className="text-[11px] text-ink-3">
            live within {compute.live_within_seconds} s · stale within {compute.stale_within_seconds} s
          </span>
        }
      >
        Workers
      </SectionHeading>
      {shown.length === 0 ? (
        <EmptyState title="Nobody is heartbeating to this node">
          A worker posts to <span className="mono">POST /progress</span> about once a minute; the
          reference worker is <span className="mono">examples/certicom-ecdlp/tools/orbit_worker.py</span>.
          What it is paid for is on each objective&rsquo;s{" "}
          <Link href="/objectives" className="text-accent">
            task dashboard
          </Link>
          , from the log.
        </EmptyState>
      ) : (
        <div className="box mb-5 overflow-x-auto">
          <table className="w-full min-w-[56rem] border-collapse text-left text-[12.5px]">
            <thead>
              <tr className="border-b border-edge text-[11px] text-ink-3">
                <th className="px-4 py-2 font-medium">Worker</th>
                <th className="px-3 py-2 font-medium">Objective</th>
                <th className="px-3 py-2 font-medium">Status</th>
                <th className="px-3 py-2 font-medium">Device</th>
                <th className="px-3 py-2 text-right font-medium">
                  <span className="text-warn">Rate</span>
                </th>
                <th className="px-3 py-2 text-right font-medium">
                  <span className="text-warn">Lanes</span>
                </th>
                <th className="px-3 py-2 font-medium">
                  <span className="text-warn">Range this epoch</span>
                </th>
                <th className="px-4 py-2 font-medium">Last seen</th>
              </tr>
            </thead>
            <tbody className="divide-edge-y">
              {shown.map((worker) => (
                <WorkerLine key={`${worker.objective_id}/${worker.worker}`} worker={worker} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* -- evidenced roles --------------------------------------------- */}
      <SectionHeading
        aside={<span className="text-[11px] text-accent">recomputed from this node&rsquo;s log</span>}
      >
        Roles the log evidences
      </SectionHeading>
      <div className="mb-5 grid gap-4 md:grid-cols-3">
        <Box
          title={
            <>
              Coordinators <span className="mono ml-1 font-normal text-ink-3">{roles.coordinators.total}</span>
            </>
          }
        >
          <IdentityList
            empty="Nobody has funded an objective in this log."
            rows={roles.coordinators.identities.map((row) => ({
              identity: row.identity,
              detail: `${row.objectives} objective${row.objectives === 1 ? "" : "s"} · ${formatMagnitude(
                row.reward_total,
              )} funded${row.piecework > 0 ? ` · ${row.piecework} piecework` : ""}`,
            }))}
            more={roles.coordinators.total - roles.coordinators.shown}
          />
        </Box>
        <Box
          title={
            <>
              Executors <span className="mono ml-1 font-normal text-ink-3">{roles.executors.total}</span>
            </>
          }
        >
          <IdentityList
            empty="No claim has been accepted in this log."
            rows={roles.executors.identities.map((row) => ({
              identity: row.identity,
              detail: `${row.accepted_claims} accepted claim${row.accepted_claims === 1 ? "" : "s"} on ${
                row.objectives
              } objective${row.objectives === 1 ? "" : "s"}`,
            }))}
            more={roles.executors.total - roles.executors.shown}
          />
        </Box>
        <Box
          title={
            <>
              Verifiers <span className="mono ml-1 font-normal text-ink-3">{roles.verifiers.total}</span>
            </>
          }
        >
          <IdentityList
            empty="Nobody has stood behind a verdict under bond in this log."
            rows={roles.verifiers.identities.map((row) => ({
              identity: row.identity,
              detail: `${row.attestations} attestation${row.attestations === 1 ? "" : "s"}${
                row.slashed > 0 ? ` · ${row.slashed} slashed` : ""
              }`,
              tone: row.slashed > 0 ? "bad" : undefined,
            }))}
            more={roles.verifiers.total - roles.verifiers.shown}
          />
        </Box>
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_22rem]">
        <Note title="Three kinds of fact">{network.note}</Note>
        <Box title="Elsewhere">
          <ul className="flex flex-col gap-1.5 text-[13px]">
            <li>
              <Link href="/peers" className="text-accent hover:underline">
                The log&rsquo;s address book: who announced an address →
              </Link>
            </li>
            <li>
              <Link href="/coordination" className="text-accent hover:underline">
                Coordination: who holds which slice of a divided search →
              </Link>
            </li>
            <li>
              <Link href="/objectives" className="text-accent hover:underline">
                Objectives, and each divided search&rsquo;s task dashboard →
              </Link>
            </li>
          </ul>
          <p className="mt-3 text-[12.5px] text-ink-2">
            Declare what this node is for when starting it:
          </p>
          <pre className="code mt-1.5 text-[11.5px]">{`CAIRN_ROLES=coordinator,verifier cairn run …`}</pre>
        </Box>
      </div>
    </>
  );
}

function SessionsTable({
  sessions,
  announced,
}: {
  sessions: SessionsResponse | null;
  announced: number;
}) {
  if (!sessions) {
    return (
      <div className="mb-5">
        <Note title="This node predates GET /sessions" tone="warn">
          It answers <span className="mono">/network</span> and not <span className="mono">/sessions</span>
          , so the peers it has reached cannot be listed here; the log&rsquo;s address book is on{" "}
          <Link href="/peers" className="text-accent">
            the peers page
          </Link>
          .
        </Note>
      </div>
    );
  }
  if (!sessions.available) {
    return (
      <div className="mb-5">
        <EmptyState title="This process runs no p2p service">
          {sessions.note} It is still a publisher: {announced} peer{announced === 1 ? "" : "s"} announced
          in its log are on{" "}
          <Link href="/peers" className="text-accent">
            the peers page
          </Link>
          .
        </EmptyState>
      </div>
    );
  }
  if (sessions.peers.length === 0) {
    return (
      <div className="mb-5">
        <EmptyState title="No session yet">
          This node has reached nobody and nobody has reached it since it started
          {sessions.this_node ? ` ${formatUptime(sessions.this_node.uptime_seconds)} ago` : ""}. It finds
          peers through a bootstrap file, the seeds built into the binary, the LAN beacon, or a{" "}
          <span className="mono">peer</span> record in its log ({announced} announced). A seed that does not
          answer is named in the node&rsquo;s log once a minute.
          {(sessions.anonymous_inbound_failures ?? 0) > 0 && (
            <>
              {" "}
              {sessions.anonymous_inbound_failures} inbound handshake
              {sessions.anonymous_inbound_failures === 1 ? "" : "s"} failed before naming anyone.
            </>
          )}
        </EmptyState>
      </div>
    );
  }
  return (
    <div className="box mb-5 overflow-x-auto">
      <table className="w-full min-w-[60rem] border-collapse text-left text-[12.5px]">
        <thead>
          <tr className="border-b border-edge text-[11px] text-ink-3">
            <th className="px-4 py-2 font-medium">Peer</th>
            <th className="px-3 py-2 font-medium">Status</th>
            <th className="px-3 py-2 font-medium">Last session</th>
            <th className="px-3 py-2 font-medium">Address seen</th>
            <th className="px-3 py-2 text-right font-medium">In / out</th>
            <th className="px-3 py-2 text-right font-medium">Failures</th>
            <th className="px-3 py-2 text-right font-medium">Entries after</th>
            <th className="px-4 py-2 font-medium">Last error</th>
          </tr>
        </thead>
        <tbody className="divide-edge-y">
          {sessions.peers.map((peer) => (
            <SessionLine key={peer.peer_id} peer={peer} />
          ))}
        </tbody>
      </table>
      {(sessions.anonymous_inbound_failures ?? 0) > 0 && (
        <p className="px-4 py-2 text-[11.5px] text-ink-3">
          Plus {sessions.anonymous_inbound_failures} inbound handshake
          {sessions.anonymous_inbound_failures === 1 ? "" : "s"} that failed before authenticating anyone,
          counted and not attributed: a name on this list is one that completed a handshake.
        </p>
      )}
    </div>
  );
}

function SessionLine({ peer }: { peer: Session }) {
  return (
    <tr className="align-top hover:bg-surface-2">
      <td className="px-4 py-2.5">
        <Hash value={peer.peer_id} chars={8} />
      </td>
      <td className="px-3 py-2.5">
        <Badge tone={reachTone(peer.status)}>{peer.status}</Badge>
      </td>
      <td className="mono px-3 py-2.5 text-ink-2" title={peer.last_ok_at ?? undefined}>
        {peer.age_seconds !== null ? (
          <>
            {formatAge(peer.age_seconds)}{" "}
            <span className="text-ink-3">{peer.last_direction}</span>
          </>
        ) : (
          "never"
        )}
      </td>
      <td className="mono px-3 py-2.5 text-ink-2">{peer.addr ?? "—"}</td>
      <td className="mono px-3 py-2.5 text-right text-ink-2">
        {peer.inbound_ok} / {peer.outbound_ok}
      </td>
      <td className="mono px-3 py-2.5 text-right text-ink-2">{peer.failures}</td>
      <td className="mono px-3 py-2.5 text-right text-ink-2">{peer.entries_after ?? "—"}</td>
      <td className="px-4 py-2.5 text-[11.5px] text-ink-3" title={peer.last_failed_at ?? undefined}>
        {peer.last_error ?? "—"}
      </td>
    </tr>
  );
}

function WorkerLine({ worker }: { worker: FleetWorker }) {
  const tone = worker.status === "live" ? "accent" : worker.status === "stale" ? "warn" : "bad";
  return (
    <tr className="align-top hover:bg-surface-2">
      <td className="mono px-4 py-2.5 text-ink">
        {worker.worker}
        {worker.client && <div className="text-[11px] text-ink-3">{worker.client}</div>}
      </td>
      <td className="px-3 py-2.5">
        <Link
          href={`/task?id=${encodeURIComponent(worker.objective_id)}`}
          className="text-accent hover:underline"
          title={worker.objective_id}
        >
          {worker.goal ?? worker.objective_id.slice(7, 15)}
        </Link>
      </td>
      <td className="px-3 py-2.5">
        <Badge tone={tone}>{worker.status}</Badge>
      </td>
      <td className="px-3 py-2.5">
        <span className="mono text-ink">{worker.device}</span>
        <span className="ml-1.5 text-[11px] text-ink-3">{classLabel(worker.class)}</span>
      </td>
      <td className="mono px-3 py-2.5 text-right text-ink-2">
        {formatRate(worker.status === "live" ? worker.steps_per_second : null)}
      </td>
      <td className="mono px-3 py-2.5 text-right text-ink-2">
        {worker.lanes !== null ? formatMagnitude(worker.lanes) : "—"}
      </td>
      <td className="mono px-3 py-2.5 text-ink-2">
        {worker.units ? (
          <>
            [{formatMagnitude(worker.units.first)}, {formatMagnitude(worker.units.end)})
            {worker.epoch !== null && <span className="text-ink-3"> epoch {worker.epoch}</span>}
          </>
        ) : (
          "—"
        )}
      </td>
      <td className="mono px-4 py-2.5 text-[12px] text-ink-3">{formatAge(worker.age_seconds)}</td>
    </tr>
  );
}

function IdentityList({
  rows,
  empty,
  more,
}: {
  rows: { identity: string; detail: string; tone?: "bad" }[];
  empty: string;
  more: number;
}) {
  if (rows.length === 0) return <p className="text-[12.5px] text-ink-3">{empty}</p>;
  return (
    <ul className="flex flex-col gap-2">
      {rows.map((row) => (
        <li key={row.identity} className="flex flex-col gap-0.5">
          <Hash value={row.identity} chars={10} />
          <span className={`text-[11.5px] ${row.tone === "bad" ? "text-bad" : "text-ink-3"}`}>
            {row.detail}
          </span>
        </li>
      ))}
      {more > 0 && <li className="text-[11.5px] text-ink-3">and {more} more</li>}
    </ul>
  );
}
