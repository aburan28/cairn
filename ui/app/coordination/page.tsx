"use client";

import Link from "next/link";
import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  type Assignment,
  type LeasesResponse,
  type PartitionCell,
  NODE_URL,
  ObjectiveNotFound,
  RouteMissing,
  claimCommand,
  coverageSummary,
  epochProgress,
  fetchAssignment,
  fetchLeaseIndex,
  fetchLeases,
  leaseRows,
  leaseTone,
  partitionHolders,
  taskTone,
} from "@/lib/leases";
import {
  type ProgressResponse,
  type ReportedWorker,
  fetchProgress,
  formatAge,
  formatDuration,
  formatMagnitude,
  formatRate,
  short,
  workerRate,
} from "@/lib/progress";
import { type Objective, fetchObjectives } from "@/lib/objectives";
import { resolveNode } from "@/lib/site";
import {
  Badge,
  Box,
  CopyButton,
  EmptyState,
  Hash,
  NodePicker,
  Note,
  PageHeader,
  Progress,
  SectionHeading,
  Skeleton,
  Stat,
  StatusPill,
} from "@/components/ui";

/** Seconds between reads while the tab is visible; see the task page. */
const REFRESH_SECONDS = 20;

/** The partition counts a reader can draw the unit space in. The default is
 *  the reference worker's `--partitions` when a fleet of this size runs. */
const PARTITION_CHOICES = [8, 16, 32, 64] as const;

/**
 * How one divided search is coordinated, as this node sees it.
 *
 * Three answers on one page, kept apart: the epoch's **assignment**, a pure
 * function of public inputs that anyone recomputes and nothing reserves; what
 * live workers **report** holding, from their heartbeats; and the advisory
 * **leases** workers posted to say what they are about to work. The first is
 * arithmetic; the other two are statements the workers made, held in the
 * node's memory and verified by nobody, and nothing that pays reads either.
 *
 * `?id=` rather than a path segment, as on `/task`: this is a static export
 * embedded in the node binary.
 */
export default function Page() {
  // `useSearchParams` makes the subtree below client-only, so the static
  // export carries this fallback and nothing else. It therefore says what the
  // page is -- the sentence is true with and without `?id=` -- rather than
  // showing two bars, and it is the sentence the smoke test looks for.
  return (
    <Suspense
      fallback={
        <div className="flex flex-col gap-3">
          <PageHeader
            title="Coordination"
            subtitle="How a divided search is coordinated: the epoch's assignment, who holds which slice, and the leases over it."
          />
          <Skeleton className="h-4 w-full max-w-lg" />
          <Skeleton className="h-20 w-full" />
        </div>
      }
    >
      <Coordination />
    </Suspense>
  );
}

function Coordination() {
  const params = useSearchParams();
  const id = params.get("id") ?? "";
  return id ? <Search id={id} /> : <Chooser />;
}

// -- choosing a search --------------------------------------------------------------

function Chooser() {
  const [base, setBase] = useState(NODE_URL);
  const [objectives, setObjectives] = useState<Objective[] | null>(null);
  const [leased, setLeased] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async (url: string) => {
    setLoading(true);
    setError(null);
    try {
      const [listing, index] = await Promise.all([
        fetchObjectives(url),
        fetchLeaseIndex(url).catch(() => ({ objectives: [] as string[] })),
      ]);
      setObjectives(listing);
      setLeased(index.objectives);
    } catch (cause) {
      setObjectives(null);
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

  const divided = useMemo(() => {
    if (!objectives) return [];
    return objectives
      .filter((o) => o.piecework || leased.includes(o.id))
      .sort((a, b) => Number(b.open) - Number(a.open) || b.reward - a.reward);
  }, [objectives, leased]);

  return (
    <>
      <PageHeader
        title="Coordination"
        subtitle="Pick a divided search: this page shows its epoch's assignment, who reports holding which slice, and the leases over it."
        actions={
          <NodePicker
            value={base}
            onChange={setBase}
            onRead={() => void load(base === window.location.origin ? "" : base)}
            loading={loading}
          />
        }
      />
      {error && (
        <Note title="Could not read this node" tone="bad">
          {error}
        </Note>
      )}
      {objectives && divided.length === 0 && (
        <EmptyState title="No divided search on this node">
          A search is divided when its objective carries a <span className="mono">piecework</span> block,
          paying per novel unit. None here does, and nobody has leased a task on any objective.
          Every objective is on{" "}
          <Link href="/objectives" className="text-accent">
            the objectives page
          </Link>
          .
        </EmptyState>
      )}
      {divided.length > 0 && (
        <Box title="Divided searches" flush>
          <ul className="divide-edge-y">
            {divided.map((objective) => (
              <li key={objective.id}>
                <Link
                  href={`/coordination?id=${encodeURIComponent(objective.id)}`}
                  className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-4 py-3 hover:bg-surface-2"
                >
                  <span className="font-medium text-ink">{objective.goal}</span>
                  <StatusPill settled={objective.settled} />
                  {objective.piecework && (
                    <span className="mono text-[12px] text-ink-3">
                      {formatMagnitude(objective.piecework.paid_units)} paid ·{" "}
                      {formatMagnitude(objective.piecework.pool_remaining)} left
                    </span>
                  )}
                  {leased.includes(objective.id) && <Badge tone="accent">leases</Badge>}
                  <span className="ml-auto">
                    <Hash value={objective.id} chars={8} />
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </Box>
      )}
    </>
  );
}

// -- one search ---------------------------------------------------------------------

function Search({ id }: { id: string }) {
  const [base, setBase] = useState(NODE_URL);
  const [partitions, setPartitions] = useState<number>(16);
  const [assignment, setAssignment] = useState<Assignment | null>(null);
  const [progress, setProgress] = useState<ProgressResponse | null>(null);
  const [leases, setLeases] = useState<LeasesResponse | null>(null);
  const [leasesMissing, setLeasesMissing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [loading, setLoading] = useState(false);
  const [readAt, setReadAt] = useState<Date | null>(null);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const load = useCallback(
    async (url: string, quiet = false) => {
      if (!quiet) setLoading(true);
      setError(null);
      setNotFound(false);
      try {
        // Three routes, one page. The assignment is asked for as a reader --
        // the name is immaterial, since the answer is a pure function -- and
        // the leases route may be newer than the node, which is a fact to
        // show rather than a failure to hide the rest behind.
        const [nextAssignment, nextProgress, nextLeases] = await Promise.all([
          fetchAssignment(id, "reader", partitions, url),
          fetchProgress(id, url),
          fetchLeases(id, url).catch((cause: unknown) => {
            if (cause instanceof RouteMissing) {
              setLeasesMissing(true);
              return null;
            }
            throw cause;
          }),
        ]);
        setAssignment(nextAssignment);
        setProgress(nextProgress);
        setLeases(nextLeases);
        setReadAt(new Date());
      } catch (cause) {
        if (cause instanceof ObjectiveNotFound) {
          setNotFound(true);
        } else {
          setError(cause instanceof Error ? cause.message : String(cause));
        }
        if (!quiet) {
          setAssignment(null);
          setProgress(null);
          setLeases(null);
        }
      } finally {
        setLoading(false);
      }
    },
    [id, partitions],
  );

  useEffect(() => {
    void resolveNode().then((url) => {
      setBase(url || window.location.origin);
      void load(url);
    });
  }, [load]);

  useEffect(() => {
    if (!assignment) return;
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
  }, [base, load, assignment !== null]);

  const picker = (
    <>
      <label className="flex items-center gap-1.5 text-[12px] text-ink-3">
        Partitions
        <select
          className="field py-1.5"
          value={partitions}
          onChange={(event) => setPartitions(Number(event.target.value))}
        >
          {PARTITION_CHOICES.map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
      </label>
      <NodePicker
        value={base}
        onChange={setBase}
        onRead={() => void load(base === window.location.origin ? "" : base)}
        loading={loading}
      />
    </>
  );

  if (notFound) {
    return (
      <>
        <PageHeader crumb={{ href: "/coordination", label: "Coordination" }} title="No such search" actions={picker} />
        <EmptyState title={`This node knows no objective ${short(id)}.`}>
          A node only knows the objectives in its own log, so a different node may.
        </EmptyState>
      </>
    );
  }

  if (error && !assignment) {
    return (
      <>
        <PageHeader crumb={{ href: "/coordination", label: "Coordination" }} title="Coordination" actions={picker} />
        <Note title="Could not read this node" tone="bad">
          {error}
          {error.includes("newer than the node") && (
            <>
              {" "}
              The search&rsquo;s settled work is still on{" "}
              <Link href={`/task?id=${encodeURIComponent(id)}`} className="text-accent">
                its task dashboard
              </Link>
              .
            </>
          )}
        </Note>
      </>
    );
  }

  if (!assignment || !progress) {
    return (
      <div className="flex flex-col gap-3">
        <Skeleton className="h-7 w-56" />
        <Skeleton className="h-4 w-full max-w-lg" />
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
      id={id}
      assignment={assignment}
      progress={progress}
      leases={leases}
      leasesMissing={leasesMissing}
      partitions={partitions}
      picker={picker}
      readAt={readAt}
      origin={base}
      stale={error}
    />
  );
}

function Dashboard({
  id,
  assignment,
  progress,
  leases,
  leasesMissing,
  partitions,
  picker,
  readAt,
  origin,
  stale,
}: {
  id: string;
  assignment: Assignment;
  progress: ProgressResponse;
  leases: LeasesResponse | null;
  leasesMissing: boolean;
  partitions: number;
  picker: React.ReactNode;
  readAt: Date | null;
  origin: string;
  stale: string | null;
}) {
  const { reported } = progress;
  const units = assignment.units?.of ?? progress.piecework?.units ?? null;
  const cells = useMemo(
    () => (units ? partitionHolders(reported.workers, leases?.tasks ?? [], units, partitions) : []),
    [reported.workers, leases, units, partitions],
  );
  const coverage = useMemo(() => coverageSummary(cells), [cells]);
  const rows = useMemo(() => leaseRows(leases?.tasks ?? []), [leases]);
  const elapsed = epochProgress(assignment.epoch_seconds, assignment.epoch_ends_in_seconds);
  const reporting = useMemo(
    () =>
      [...reported.workers]
        .filter((worker) => worker.status !== "gone")
        .sort((a, b) => (a.status === b.status ? a.worker.localeCompare(b.worker) : a.status === "live" ? -1 : 1)),
    [reported.workers],
  );

  return (
    <>
      <PageHeader
        crumb={{ href: "/coordination", label: "Coordination" }}
        title={progress.goal || short(id)}
        subtitle={
          progress.kind === "piecework"
            ? "How this divided search is coordinated: the epoch's assignment, who reports holding which slice, and the advisory leases over it."
            : "Not a divided search: there is no unit space to assign. The epoch and any leases workers posted are still here."
        }
        meta={
          <>
            <StatusPill settled={progress.settled} />
            <Badge tone="accent">{progress.kind}</Badge>
            <Badge tone={reported.live > 0 ? "accent" : "neutral"}>
              {reported.live} live{reported.stale > 0 && <>, {reported.stale} stale</>}
            </Badge>
            <Hash value={id} chars={8} />
          </>
        }
        actions={picker}
      />

      <p className="mb-4 text-[12px] text-ink-3">
        Read from <span className="mono">{origin}</span>
        {readAt && <> at {readAt.toLocaleTimeString()}</>}, again every {REFRESH_SECONDS} s while this
        tab is visible. The <span className="text-accent">assignment</span> is arithmetic anyone can
        recompute; <span className="text-warn">reported</span> ranges and{" "}
        <span className="text-accent">leases</span> are what workers said, held in memory and checked by
        nobody.
        {stale && <span className="text-bad"> The last re-read failed: {stale}</span>}
      </p>

      {/* -- the epoch ------------------------------------------------------ */}
      <div className="mb-3 grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat
          label="Epoch"
          value={String(assignment.epoch)}
          from={`${formatDuration(assignment.epoch_seconds)} each, from the record's own timestamp`}
        />
        <Stat
          label="Turns in"
          value={formatDuration(assignment.epoch_ends_in_seconds)}
          from="every slice rotates at the turn; ask again then"
        />
        <Stat
          label="Partitions covered"
          value={units ? `${coverage.covered + coverage.contested}/${partitions}` : "—"}
          from={
            units
              ? `${coverage.uncovered} nobody reports · ${coverage.contested} more than one does`
              : "no unit space on this objective"
          }
          tone={coverage.uncovered === 0 && units ? "neutral" : "warn"}
        />
        <Stat
          label="Leases held"
          value={leases ? String(leases.held) : "—"}
          from={
            leases
              ? `${leases.contended} contended · ${leases.completed} completed · ${leases.expired} expired`
              : leasesMissing
                ? "this node predates leases"
                : "reading…"
          }
          tone="accent"
        />
        <Stat
          label="Units"
          value={units ? formatMagnitude(units) : "—"}
          from={assignment.units ? `${formatMagnitude(assignment.units.unit_price)} each, paid per novel unit` : "not piecework"}
          tone="neutral"
        />
      </div>

      <div className="mb-5 grid gap-4 lg:grid-cols-[22rem_minmax(0,1fr)]">
        <Box title={`Epoch ${assignment.epoch}`}>
          <Progress value={elapsed} label="elapsed" />
          <dl className="kv mt-3">
            <dt>anchor</dt>
            <dd>
              <Hash value={assignment.anchor} chars={8} />
            </dd>
            <dt>length</dt>
            <dd className="mono">{assignment.epoch_seconds} s</dd>
            <dt>assignment</dt>
            <dd className="mono text-[11.5px]">H(beacon(epoch) ‖ node_id ‖ objective_id) mod {partitions}</dd>
          </dl>
          <p className="hint mt-3">
            No dispatcher, no reservation: every worker computes its own slice from these inputs and
            can compute anyone else&rsquo;s. Two workers on one slice waste a little compute and
            nothing else, and the mapping rotates at the turn so no region can be squatted.
          </p>
        </Box>

        <Box
          title="Who holds what this epoch"
          aside={
            units ? (
              <span className="text-[11px] font-normal text-ink-3">
                {partitions} partitions of {formatMagnitude(units)} units · reported ranges over the assignment
              </span>
            ) : undefined
          }
        >
          {units ? (
            <PartitionStrip cells={cells} partitions={partitions} />
          ) : (
            <p className="text-[12.5px] text-ink-3">
              This objective has no unit space, so there is nothing to divide. Leases, if any, are
              below.
            </p>
          )}
        </Box>
      </div>

      {/* -- leases --------------------------------------------------------- */}
      <SectionHeading
        count={rows.length}
        aside={
          leases ? (
            <span className="text-[11px] text-ink-3">
              default ttl {leases.default_ttl_seconds} s · at most {formatDuration(leases.max_ttl_seconds)}
            </span>
          ) : undefined
        }
      >
        Leases
      </SectionHeading>
      {leasesMissing ? (
        <div className="mb-5">
          <Note title="This node predates leases" tone="warn">
            It answers <span className="mono">/work_assignment</span> and <span className="mono">/progress</span>{" "}
            and not <span className="mono">/leases</span>; a node built after the route was added shows
            them here.
          </Note>
        </div>
      ) : rows.length === 0 ? (
        <div className="mb-5">
          <EmptyState title="No lease on this objective">
            A worker posts one before it starts a task, so the next worker can see it and pick
            something else. From a shell:
            <div className="relative mt-3 text-left">
              <pre className="code pr-9 text-[11.5px]">{claimCommand(origin, id, units)}</pre>
              <div className="absolute top-2 right-2">
                <CopyButton value={claimCommand(origin, id, units)} />
              </div>
            </div>
          </EmptyState>
        </div>
      ) : (
        <div className="box mb-5 overflow-x-auto">
          <table className="w-full min-w-[56rem] border-collapse text-left text-[12.5px]">
            <thead>
              <tr className="border-b border-edge text-[11px] text-ink-3">
                <th className="px-4 py-2 font-medium">Task</th>
                <th className="px-3 py-2 font-medium">Lease</th>
                <th className="px-3 py-2 font-medium">Holder</th>
                <th className="px-3 py-2 font-medium">Units</th>
                <th className="px-3 py-2 text-right font-medium">Expires in</th>
                <th className="px-3 py-2 font-medium">Since</th>
                <th className="px-4 py-2 font-medium">Note</th>
              </tr>
            </thead>
            <tbody className="divide-edge-y">
              {rows.map((row) => (
                <tr key={`${row.task}/${row.holder}`} className="align-top hover:bg-surface-2">
                  <td className="mono px-4 py-2.5 text-ink">
                    {row.task}
                    <div>
                      <Badge tone={taskTone(row.taskStatus)}>{row.taskStatus}</Badge>
                    </div>
                  </td>
                  <td className="px-3 py-2.5">
                    <Badge tone={leaseTone(row.status)}>{row.status}</Badge>
                    {row.released && (
                      <div className="mt-1 text-[11px] text-ink-3">{row.released.outcome}</div>
                    )}
                  </td>
                  <td className="mono px-3 py-2.5 text-ink">{row.holder}</td>
                  <td className="mono px-3 py-2.5 text-ink-2">
                    {row.units ? `[${formatMagnitude(row.units.first)}, ${formatMagnitude(row.units.end)})` : "—"}
                    {row.epoch !== null && <span className="text-ink-3"> epoch {row.epoch}</span>}
                  </td>
                  <td className="mono px-3 py-2.5 text-right text-ink-2" title={row.expires_at}>
                    {row.status === "held" || row.status === "contended"
                      ? formatDuration(row.expires_in_seconds)
                      : "—"}
                  </td>
                  <td className="mono px-3 py-2.5 text-[12px] text-ink-3" title={row.renewed_at}>
                    {row.since.slice(11, 19)}
                  </td>
                  <td className="px-4 py-2.5 text-[12px] text-ink-2">{row.note ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* -- workers reporting ----------------------------------------------- */}
      <SectionHeading count={reporting.length}>Workers reporting</SectionHeading>
      {reporting.length === 0 ? (
        <div className="mb-5">
          <EmptyState title="No worker is heartbeating on this objective">
            The slices above are assigned whether or not anyone takes them. Start a worker from a
            checkout and it appears here within a minute; what it is paid for is on{" "}
            <Link href={`/task?id=${encodeURIComponent(id)}`} className="text-accent">
              the task dashboard
            </Link>
            .
          </EmptyState>
        </div>
      ) : (
        <div className="box mb-5 overflow-x-auto">
          <table className="w-full min-w-[40rem] border-collapse text-left text-[12.5px]">
            <thead>
              <tr className="border-b border-edge text-[11px] text-ink-3">
                <th className="px-4 py-2 font-medium">Worker</th>
                <th className="px-3 py-2 font-medium">Status</th>
                <th className="px-3 py-2 font-medium">
                  <span className="text-warn">Range reported</span>
                </th>
                <th className="px-3 py-2 text-right font-medium">
                  <span className="text-warn">Rate</span>
                </th>
                <th className="px-4 py-2 font-medium">Last seen</th>
              </tr>
            </thead>
            <tbody className="divide-edge-y">
              {reporting.map((worker) => (
                <ReportingLine key={worker.worker} worker={worker} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="flex flex-col gap-4">
          <Note title="What a lease is, and is not">
            {leases?.note ??
              "A lease is a worker's announcement that it is on a task for the next so many seconds, held in the node's memory. The earliest live claim on a task holds it; a lease is never a record, never a lock, never evidence of work, and nothing that moves money reads it."}
          </Note>
          <Note title="What the assignment is">{assignment.note}</Note>
        </div>
        <Box title="Elsewhere">
          <ul className="flex flex-col gap-1.5 text-[13px]">
            <li>
              <Link href={`/task?id=${encodeURIComponent(id)}`} className="text-accent hover:underline">
                The task dashboard: what the log has paid for →
              </Link>
            </li>
            <li>
              <Link href={`/challenge?id=${encodeURIComponent(id)}`} className="text-accent hover:underline">
                The objective: statement, checker, how to submit →
              </Link>
            </li>
            <li>
              <Link href="/network" className="text-accent hover:underline">
                The network: peers reached, hardware heartbeating, roles →
              </Link>
            </li>
          </ul>
          <p className="mt-3 text-[12.5px] text-ink-2">Take a slice from this node, as a worker would:</p>
          <pre className="code mt-1.5 text-[11.5px]">
            {`curl -s '${origin}/work_assignment?objective_id=${id}&node_id=<your name>&partitions=${partitions}'`}
          </pre>
        </Box>
      </div>
    </>
  );
}

/**
 * The unit space as one strip of partitions. Each cell is coloured by how
 * many live workers report a range overlapping it -- none, one, more than
 * one -- and ringed when a live lease covers it, so the two statements sit
 * in one place: what workers say they hold, and what they said they would.
 */
function PartitionStrip({ cells, partitions }: { cells: PartitionCell[]; partitions: number }) {
  return (
    <div className="flex flex-col gap-2">
      <div
        className="grid h-10 w-full gap-px overflow-hidden rounded bg-edge"
        style={{ gridTemplateColumns: `repeat(${partitions}, minmax(0, 1fr))` }}
        role="img"
        aria-label={`${partitions} partitions; ${cells.filter((c) => c.holders.length > 0).length} have a live worker`}
      >
        {cells.map((cell) => {
          const fill =
            cell.holders.length === 0
              ? "bg-surface-3"
              : cell.holders.length === 1
                ? "bg-accent/70"
                : "bg-ink-2/70";
          const ring = cell.leased.length > 0 ? "ring-2 ring-inset ring-accent" : "";
          const title = [
            `partition ${cell.index}: units [${cell.first.toLocaleString("en-US")}, ${cell.end.toLocaleString("en-US")})`,
            cell.holders.length > 0 ? `reported by ${cell.holders.join(", ")}` : "nobody reports holding it",
            cell.leased.length > 0 ? `leased by ${cell.leased.join(", ")}` : "",
          ]
            .filter(Boolean)
            .join(" · ");
          return <div key={cell.index} className={`h-full ${fill} ${ring}`} title={title} />;
        })}
      </div>
      <p className="text-[11px] text-ink-3">
        <span className="text-accent">Green</span>: one live worker reports a range here.{" "}
        <span className="text-ink-2">Dark grey</span>: more than one does, which wastes a little compute and
        nothing else. Light grey: nobody does. <span className="text-accent">Green ring</span>: a live lease
        covers it. Hover a cell for the unit range and the names.
      </p>
    </div>
  );
}

function ReportingLine({ worker }: { worker: ReportedWorker }) {
  const tone = worker.status === "live" ? "accent" : "warn";
  return (
    <tr className="align-top hover:bg-surface-2">
      <td className="mono px-4 py-2.5 text-ink">
        {worker.worker}
        {worker.device && <div className="text-[11px] text-ink-3">{worker.device}</div>}
      </td>
      <td className="px-3 py-2.5">
        <Badge tone={tone}>{worker.status}</Badge>
      </td>
      <td className="mono px-3 py-2.5 text-ink-2">
        {worker.units ? (
          <>
            [{formatMagnitude(worker.units.first)}, {formatMagnitude(worker.units.end)})
            {worker.unit !== null && <span className="text-ink-3"> at {formatMagnitude(worker.unit)}</span>}
            {worker.epoch !== null && <span className="text-ink-3"> · epoch {worker.epoch}</span>}
          </>
        ) : (
          "—"
        )}
      </td>
      <td className="mono px-3 py-2.5 text-right text-ink-2">{formatRate(workerRate(worker))}</td>
      <td className="mono px-4 py-2.5 text-[12px] text-ink-3" title={worker.received_at}>
        {formatAge(worker.age_seconds)}
      </td>
    </tr>
  );
}
