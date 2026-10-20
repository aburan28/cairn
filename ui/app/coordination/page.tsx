"use client";

import Link from "next/link";
import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  type Assignment,
  type LeasesResponse,
  type PartitionCell,
  ObjectiveNotFound,
  RouteMissing,
  coverageSummary,
  coordinatedObjectives,
  epochProgress,
  fetchAssignment,
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
import { type NetworkResponse, fetchNetwork } from "@/lib/network";
import { type Bridge, appBridge, briefProblem, BRIEF_MAX } from "@/lib/draft";
import {
  type CoordinationStatus, cancelCoordination, coordinationBudget, coordinationBusy,
  coordinationStatus, generateCoordination, launchCoordination,
} from "@/lib/coordination-draft";
import { objectiveTitle } from "@/lib/title";
import { useEvery, useNode, useNodeRead } from "@/components/hooks";
import {
  Badge,
  Box,
  CopyButton,
  Disclosure,
  EmptyState,
  Hash,
  LiveStamp,
  MemberBadge,
  Note,
  PageHeader,
  Progress,
  Skeleton,
  Stat,
  StatusPill,
} from "@/components/ui";

/** Seconds between reads while the tab is visible; see the task page. */
const REFRESH_SECONDS = 20;

/** The partition counts a reader can draw the unit space in. */
const PARTITION_CHOICES = [8, 16, 32, 64] as const;

const SUBTITLE =
  "How a divided search is coordinated: one big search split across many machines and agents, each paid for every piece it finishes. Describe a new one, or watch the ones running.";

/** Descriptions to start from, so the box is never a blank page. */
const EXAMPLES = [
  "Search every 32-bit seed of xorshift32 for one whose first output is 0xdeadbeef. One piece is a block of 65,536 consecutive seeds; a finished piece reports the matches in its block, or none.",
  "Find integers n below 2^40 whose Collatz trajectory takes more than 1,000 steps. One piece is a range of 2^24 starting values; pay for each range reported with its longest trajectory.",
  "Collect distinguished points for a Pollard rho walk on the ECC2K-23 practice curve. Each point is one piece, paid once however many machines reach it.",
] as const;

/**
 * Coordinated tasks: launch one from a description, and watch the ones running.
 *
 * A coordinated task is an objective with a `piecework` block -- a search the
 * network divides by arithmetic, each worker taking its own slice per epoch,
 * every novel finished unit paid from the pool. Turning a description into one
 * needs a checker written and pinned. Cairn.app asks the configured AI provider
 * in the background, checks its spec with the node's verifier, and returns a
 * preview the person can launch. Credentials and generated code stay native.
 *
 * `?id=` rather than a path segment: this is a static export embedded in the
 * node binary.
 */
export default function Page() {
  // `useSearchParams` makes the subtree below client-only, so the static
  // export carries this fallback -- which states what the page is, and is the
  // sentence the smoke test looks for.
  return (
    <Suspense
      fallback={
        <div className="flex flex-col gap-3">
          <PageHeader title="Coordination" subtitle={SUBTITLE} />
          <Skeleton className="h-40 w-full" />
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
  return id ? <Search key={id} id={id} /> : <Overview />;
}

// -- the overview: launch, and what is running ------------------------------------

function Overview() {
  const { value, error, readAt } = useNodeRead(async (base) => {
    const [objectives, network] = await Promise.all([fetchObjectives(base), fetchNetwork(base).catch(() => null)]);
    return { objectives, network };
  }, { seconds: REFRESH_SECONDS });
  const objectives = value?.objectives ?? null;
  const network = value?.network ?? null;

  const tasks = useMemo(() => coordinatedObjectives(objectives ?? []), [objectives]);
  // A settled task is history, not work in progress: listing it under
  // "Running" beside a "Settled" pill said two things at once.
  const running = tasks.filter((objective) => !objective.settled);
  const finished = tasks.filter((objective) => objective.settled);
  const live = useMemo(() => {
    const by = new Map<string, number>();
    for (const row of network?.compute.objectives ?? []) by.set(row.objective_id, row.live);
    return by;
  }, [network]);

  return (
    <>
      <PageHeader title="Coordination" subtitle={SUBTITLE} actions={<><LiveStamp at={readAt} error={objectives ? error : null} /><Link className="btn btn-sm" href="/workspace">Workspaces</Link></>} />

      <Launch />

      <h2 className="mt-7 mb-3 text-[13px] font-semibold tracking-[0.06em] text-ink-2 uppercase">
        Running <span className="mono ml-1 text-ink-3">{running.length}</span>
      </h2>
      {error && !objectives && (
        <Note title="Could not read this node" tone="bad">
          {error}
        </Note>
      )}
      {objectives === null && !error && (
        <div className="grid gap-3 md:grid-cols-2">
          <Skeleton className="h-28" />
          <Skeleton className="h-28" />
        </div>
      )}
      {objectives && running.length === 0 && (
        <EmptyState title={finished.length ? "Nothing running now" : "No coordinated task yet"}>
          Describe one above and Cairn will prepare its challenge spec. Any challenge with a{" "}
          <span className="mono">piecework</span> block appears here once it is posted.
        </EmptyState>
      )}
      {running.length > 0 && (
        <ul className="grid gap-3 md:grid-cols-2">
          {running.map((objective) => (
            <TaskCard key={objective.id} objective={objective} live={live.get(objective.id) ?? 0} />
          ))}
        </ul>
      )}
      {finished.length > 0 && (
        <>
          <h2 className="mt-7 mb-3 text-[13px] font-semibold tracking-[0.06em] text-ink-2 uppercase">
            Finished <span className="mono ml-1 text-ink-3">{finished.length}</span>
          </h2>
          <ul className="grid gap-3 md:grid-cols-2">
            {finished.map((objective) => (
              <TaskCard key={objective.id} objective={objective} live={live.get(objective.id) ?? 0} />
            ))}
          </ul>
        </>
      )}
    </>
  );
}

function TaskCard({ objective, live }: { objective: Objective; live: number }) {
  const pw = objective.piecework!;
  const funded = pw.paid_total + pw.pool_remaining;
  const spent = funded > 0 ? pw.paid_total / funded : 0;
  return (
    <li>
      <Link
        href={`/coordination?id=${encodeURIComponent(objective.id)}`}
        className="card card-pad flex h-full flex-col gap-2.5 transition-colors hover:border-edge-strong hover:bg-surface-2"
      >
        <div className="flex items-start gap-2">
          <span className="line-clamp-2 min-w-0 flex-1 font-medium text-ink">{objectiveTitle(objective)}</span>
          <StatusPill settled={objective.settled} />
        </div>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px] text-ink-2">
          <span className="inline-flex items-center gap-1.5">
            <span className={`h-1.5 w-1.5 rounded-full ${live > 0 ? "bg-accent" : "bg-ink-3"}`} aria-hidden />
            {live} machine{live === 1 ? "" : "s"} working
          </span>
          {pw.units ? <span>{formatMagnitude(pw.units)} pieces</span> : null}
          <span>
            {formatMagnitude(pw.unit_price)} unit{pw.unit_price === 1 ? "" : "s"} a piece
          </span>
        </div>
        <Progress value={spent} label={`${formatMagnitude(pw.paid_total)} of ${formatMagnitude(funded)} paid out`} />
      </Link>
    </li>
  );
}

/** Drafting belongs to the app, so it survives a reader reload during launch. */
function Launch() {
  const [description, setDescription] = useState("");
  const [budget, setBudget] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const [bridge, setBridge] = useState<Bridge | null>(null);
  const [available, setAvailable] = useState(false);
  const [state, setState] = useState<CoordinationStatus | null>(null);
  const [pending, setPending] = useState(false);
  const version = useRef(0);

  useEffect(() => {
    let live = true;
    const native = appBridge();
    setBridge(native);
    if (native) {
      void coordinationStatus(native).then((next) => {
        if (!live) return;
        setState(next);
        setDescription(next.brief);
        setBudget(next.budget);
        setAvailable(true);
      }).catch((cause: Error) => { if (live) setProblem(cause.message); });
    }
    return () => { live = false; version.current += 1; };
  }, []);

  useEvery(async () => {
    if (!bridge || pending) return;
    const asked = version.current;
    try {
      const next = await coordinationStatus(bridge);
      if (asked === version.current) setState(next);
    } catch (cause) {
      if (asked === version.current) setProblem(cause instanceof Error ? cause.message : String(cause));
    }
  }, 1, available && coordinationBusy(state?.phase));

  async function act(action: (bridge: Bridge) => Promise<CoordinationStatus>) {
    if (!bridge || pending) return;
    const asked = ++version.current;
    setPending(true);
    setProblem(null);
    try {
      const next = await action(bridge);
      if (asked === version.current) setState(next);
    } catch (cause) {
      if (asked === version.current) setProblem(cause instanceof Error ? cause.message : String(cause));
    } finally {
      if (asked === version.current) setPending(false);
    }
  }

  const busy = pending || coordinationBusy(state?.phase);
  let budgetError: string | null = null;
  let amount = "";
  try { amount = coordinationBudget(budget); }
  catch (cause) { budgetError = cause instanceof Error ? cause.message : String(cause); }
  const current = state?.brief === description.trim() && state?.budget === amount && !budgetError;
  const preview = current && state?.spec ? state : null;

  return (
    <section id="launch" className="card card-pad scroll-mt-6" aria-busy={busy}>
      <div className="flex flex-wrap items-baseline gap-2">
        <h2 className="text-[15px] font-semibold text-ink">Launch a coordinated task</h2>
        <span className="text-[12.5px] text-ink-3">
          Describe the task. Cairn prepares and checks a challenge spec using your AI provider.
        </span>
      </div>
      <textarea
        className="field mt-3 min-h-28 resize-y leading-relaxed"
        value={description}
        onChange={(event) => { setDescription(event.target.value); setProblem(null); }}
        disabled={busy}
        placeholder="e.g. Search every 32-bit seed of this generator for one whose first output is 0xdeadbeef. One piece is a block of 65,536 seeds."
        aria-label="Describe the task"
        maxLength={BRIEF_MAX}
      />
      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        <span className="text-[11.5px] text-ink-3">Try:</span>
        {EXAMPLES.map((example, n) => (
          <button key={n} type="button" className="btn btn-sm btn-ghost text-ink-2" disabled={busy}
            onClick={() => { setDescription(example); setProblem(null); }} title={example}>
            {["Seed search", "Collatz ranges", "Rho points"][n]}
          </button>
        ))}
      </div>
      <div className="mt-3 flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-[12px] text-ink-3">
          Budget (optional)
          <input className="field field-mono w-40" inputMode="numeric" placeholder="units in all"
            value={budget} disabled={busy} onChange={(event) => { setBudget(event.target.value); setProblem(null); }} />
        </label>
        <button type="button" className="btn btn-primary"
          disabled={!!briefProblem(description) || !!budgetError || busy || !available}
          onClick={() => void act((native) => generateCoordination(native, description, budget))}>
          {state?.phase === "drafting" ? "Generating spec…" : state?.phase === "checking" ? "Checking spec…" : "Generate challenge spec"}
        </button>
        {(state?.phase === "drafting" || state?.phase === "checking") && (
          <button type="button" className="btn" disabled={pending} onClick={() => void act(cancelCoordination)}>Cancel</button>
        )}
        {bridge && (
          <button type="button" className="btn btn-ghost text-ink-2" disabled={busy}
            onClick={() => { void bridge.postMessage({ kind: "open", sheet: "settings" })
              .catch((cause) => setProblem(cause instanceof Error ? cause.message : String(cause))); }}>AI settings</button>
        )}
      </div>
      {!bridge && <p className="mt-3 text-[12.5px] text-ink-2">Open this node in Cairn for Mac to generate and launch a challenge with your configured AI provider.</p>}
      {(problem || budgetError) && <p role="alert" className="mt-3 text-[12.5px] text-bad">{problem || budgetError}</p>}
      <div aria-live="polite" className="mt-3 text-[12.5px] text-ink-2">
        {state?.phase === "drafting" && <p>{state.message || `Preparing the challenge${state.provider ? ` with ${state.provider}` : ""}…`}</p>}
        {state?.phase === "checking" && <p>Checking the spec and testing valid and invalid examples…</p>}
        {current && state?.phase === "error" && <p className="text-bad" role="alert">{state.message}</p>}
      </div>
      {preview && (
        <div className="mt-5 flex flex-col gap-3 border-t border-edge pt-4">
          <h3 className="text-[14px] font-semibold text-ink">{preview.phase === "posted" ? "Challenge launched" : "Your challenge spec"}</h3>
          <p className="text-[13px] leading-relaxed whitespace-pre-wrap text-ink">{preview.statement}</p>
          <p className="text-[12.5px] text-ink-2">{preview.unit}</p>
          <dl className="grid grid-cols-1 gap-3 text-[13px] sm:grid-cols-3">
            <div><dt className="text-ink-3">Pieces</dt><dd className="mono break-all text-ink">{preview.units}</dd></div>
            <div><dt className="text-ink-3">Units per piece</dt><dd className="mono break-all text-ink">{preview.unitPrice}</dd></div>
            <div><dt className="text-ink-3">Total budget</dt><dd className="mono break-all text-ink">{preview.reward}</dd></div>
          </dl>
          {preview.notes && <p className="text-[12.5px] text-ink-2">{preview.notes}</p>}
          <p role="status" className="text-[12.5px] text-ink-2">{preview.message}</p>
          <details className="text-[12.5px]">
            <summary className="cursor-pointer text-ink-2">View challenge JSON</summary>
            <pre className="code mt-2 max-h-80 overflow-auto text-[11.5px]">{preview.spec}</pre>
          </details>
          {preview.phase === "posted" ? (
            <Link href={`/coordination?id=${encodeURIComponent(preview.objectiveId!)}`} className="btn btn-primary self-start">View running challenge →</Link>
          ) : (
            <button type="button" className="btn btn-primary self-start" disabled={busy || preview.phase !== "ready"}
              onClick={() => void act((native) => launchCoordination(native, preview.draftId!))}>
              {preview.phase === "launching" ? "Launching…" : "Launch challenge"}
            </button>
          )}
        </div>
      )}
    </section>
  );
}

// -- one search ---------------------------------------------------------------------

function Search({ id }: { id: string }) {
  const requestVersion = useRef(0);
  const base = useNode();
  const [partitions, setPartitions] = useState<number>(16);
  const [assignment, setAssignment] = useState<Assignment | null>(null);
  const [progress, setProgress] = useState<ProgressResponse | null>(null);
  const [leases, setLeases] = useState<LeasesResponse | null>(null);
  const [leasesMissing, setLeasesMissing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [readAt, setReadAt] = useState<Date | null>(null);

  const load = useCallback(async () => {
    if (base === null) return;
    const version = ++requestVersion.current;
    let missingLeases = false;
    try {
      // The assignment is asked for as a reader -- the name is immaterial,
      // the answer is a pure function -- and the leases route may be newer
      // than the node, which is a fact to show rather than a failure.
      const [nextAssignment, nextProgress, nextLeases] = await Promise.all([
        fetchAssignment(id, "reader", partitions, base),
        fetchProgress(id, base),
        fetchLeases(id, base).catch((cause: unknown) => {
          if (cause instanceof RouteMissing) {
            missingLeases = true;
            return null;
          }
          throw cause;
        }),
      ]);
      if (version !== requestVersion.current) return;
      setAssignment(nextAssignment);
      setProgress(nextProgress);
      setLeases(nextLeases);
      setLeasesMissing(missingLeases);
      setReadAt(new Date());
      setError(null);
      setNotFound(false);
    } catch (cause) {
      if (version !== requestVersion.current) return;
      if (cause instanceof ObjectiveNotFound) setNotFound(true);
      else setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, [base, id, partitions]);

  useEvery(load, REFRESH_SECONDS, base !== null, partitions);

  const crumb = { href: "/coordination", label: "Coordination" };
  if (notFound) {
    return (
      <>
        <PageHeader crumb={crumb} title="No such task" />
        <EmptyState title={`This node knows no objective ${short(id)}.`}>
          A node only knows the challenges in its own log, so another node may.
        </EmptyState>
      </>
    );
  }
  if (error && !assignment) {
    return (
      <>
        <PageHeader crumb={crumb} title="Coordination" />
        <Note title="Could not read this node" tone="bad">
          {error}
        </Note>
      </>
    );
  }
  if (!assignment || !progress) {
    return (
      <div className="flex flex-col gap-3">
        <Skeleton className="h-7 w-56" />
        <div className="mt-3 grid grid-cols-2 gap-3 md:grid-cols-4">
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
      setPartitions={setPartitions}
      readAt={readAt}
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
  setPartitions,
  readAt,
  stale,
}: {
  id: string;
  assignment: Assignment;
  progress: ProgressResponse;
  leases: LeasesResponse | null;
  leasesMissing: boolean;
  partitions: number;
  setPartitions: (n: number) => void;
  readAt: Date | null;
  stale: string | null;
}) {
  const { reported, derived } = progress;
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
  const paidUnits = derived.units_paid;
  const pw = progress.piecework;

  return (
    <>
      <PageHeader
        crumb={{ href: "/coordination", label: "Coordination" }}
        title={progress.goal ? progress.goal.replace(/^GOAL-/, "") : short(id)}
        meta={
          <>
            <StatusPill settled={progress.settled} />
            <Badge tone={reported.live > 0 ? "accent" : "neutral"}>
              {reported.live} working{reported.stale > 0 && <>, {reported.stale} quiet</>}
            </Badge>
            <Hash value={id} chars={8} />
          </>
        }
        actions={
          <>
            <LiveStamp at={readAt} error={stale} />
            <Link href={`/workspace?objective=${id}`} className="btn btn-sm">Workspaces</Link>
            <Link href={`/task?id=${encodeURIComponent(id)}`} className="btn btn-sm">
              Progress
            </Link>
            <Link href={`/challenge?id=${encodeURIComponent(id)}`} className="btn btn-sm">
              Challenge
            </Link>
          </>
        }
      />

      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat
          label="Pieces paid"
          value={units ? `${formatMagnitude(paidUnits)} / ${formatMagnitude(units)}` : formatMagnitude(paidUnits)}
          from={
            pw
              ? `${formatMagnitude(pw.unit_price)} unit${pw.unit_price === 1 ? "" : "s"} each · ${formatMagnitude(pw.pool_remaining)} left`
              : "from the log"
          }
          tone="accent"
        />
        <Stat
          label="Machines working"
          value={String(reported.live)}
          from={
            reported.live === 0
              ? "none reporting now"
              : reported.steps_per_second > 0
                ? `${formatRate(reported.steps_per_second)} reported`
                : "speed not reported"
          }
        />
        <Stat
          label="Slices covered"
          value={units ? `${coverage.covered + coverage.contested}/${partitions}` : "—"}
          from={units ? `${coverage.uncovered} with nobody on them` : "no unit space"}
          tone={units && coverage.uncovered > 0 ? "warn" : "neutral"}
        />
        <Stat
          label="Epoch turns in"
          value={formatDuration(assignment.epoch_ends_in_seconds)}
          from={`epoch ${assignment.epoch}; every slice moves then`}
        />
      </div>

      <Box
        className="mb-4"
        title="Who is working on what"
        aside={
          units ? (
            <label className="flex items-center gap-1.5 text-[11.5px] font-normal text-ink-3">
              slices
              <select
                className="field py-0.5 text-[12px]"
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
          ) : undefined
        }
      >
        {units ? (
          <PartitionStrip cells={cells} partitions={partitions} />
        ) : (
          <p className="text-[12.5px] text-ink-3">This challenge is not divided into pieces, so there is nothing to split.</p>
        )}
        <div className="mt-3">
          <Progress value={elapsed} label={`epoch ${assignment.epoch}`} />
        </div>
      </Box>

      <Box
        className="mb-4"
        flush
        title={
          <>
            Machines <span className="mono ml-1 font-normal text-ink-3">{reporting.length}</span>
          </>
        }
        aside={
          <Link href="/contribute#compute" className="text-[12px] font-normal text-accent hover:underline">
            Add a machine →
          </Link>
        }
      >
        {reporting.length === 0 ? (
          <p className="px-4 py-6 text-center text-[13px] text-ink-3">
            No machine is reporting on this task. The slices are assigned whether or not anyone takes them.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[40rem] border-collapse text-left text-[12.5px]">
              <thead>
                <tr className="border-b border-edge text-[11px] text-ink-3">
                  <th className="px-4 py-2 font-medium">Machine</th>
                  <th className="px-3 py-2 font-medium">Its slice</th>
                  <th className="px-3 py-2 text-right font-medium">Speed</th>
                  <th className="px-4 py-2 font-medium">Last heard</th>
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
      </Box>

      {rows.length > 0 && (
        <Box
          className="mb-4"
          flush
          title={
            <>
              Tasks taken <span className="mono ml-1 font-normal text-ink-3">{rows.length}</span>
            </>
          }
          aside={<span className="text-[11px] font-normal text-ink-3">what machines said they are on; nothing pays on it</span>}
        >
          <div className="overflow-x-auto">
            <table className="w-full min-w-[44rem] border-collapse text-left text-[12.5px]">
              <thead>
                <tr className="border-b border-edge text-[11px] text-ink-3">
                  <th className="px-4 py-2 font-medium">Task</th>
                  <th className="px-3 py-2 font-medium">Held by</th>
                  <th className="px-3 py-2 font-medium">Pieces</th>
                  <th className="px-3 py-2 text-right font-medium">Expires in</th>
                  <th className="px-4 py-2 font-medium">Note</th>
                </tr>
              </thead>
              <tbody className="divide-edge-y">
                {rows.map((row) => (
                  <tr key={`${row.task}/${row.holder}`} className="align-top hover:bg-surface-2">
                    <td className="mono px-4 py-2.5 text-ink">
                      {row.task}{" "}
                      <Badge tone={taskTone(row.taskStatus)}>{row.taskStatus}</Badge>
                    </td>
                    <td className="mono px-3 py-2.5 text-ink">
                      {row.holder}
                      <MemberBadge member={row.member} />{" "}
                      <Badge tone={leaseTone(row.status)}>{row.status}</Badge>
                    </td>
                    <td className="mono px-3 py-2.5 text-ink-2">
                      {row.units ? `[${formatMagnitude(row.units.first)}, ${formatMagnitude(row.units.end)})` : "—"}
                    </td>
                    <td className="mono px-3 py-2.5 text-right text-ink-2" title={row.expires_at}>
                      {row.status === "held" || row.status === "contended" ? formatDuration(row.expires_in_seconds) : "—"}
                    </td>
                    <td className="px-4 py-2.5 text-[12px] text-ink-2">{row.note ?? row.released?.outcome ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Box>
      )}

      <Disclosure summary="How work is split">
        <div className="text-[12.5px] leading-relaxed text-ink-2">
            <p>
              Nobody hands out the slices. Every machine computes its own from public inputs —{" "}
              <span className="mono text-[11.5px]">H(beacon(epoch) ‖ machine ‖ challenge) mod {partitions}</span> — and
              can compute anyone else&rsquo;s. Two machines on one slice waste a little compute and nothing else, and
              the mapping moves every epoch so no slice can be squatted.
            </p>
            <p className="mt-2 text-ink-3">{assignment.note}</p>
            {leasesMissing ? (
              <p className="mt-2 text-ink-3">This node is older than task leases.</p>
            ) : leases ? (
              <p className="mt-2 text-ink-3">{leases.note}</p>
            ) : null}
        </div>
      </Disclosure>
    </>
  );
}

/**
 * The unit space as one strip of slices, coloured by how many live machines
 * report a range in it and ringed where a live task lease covers it.
 */
function PartitionStrip({ cells, partitions }: { cells: PartitionCell[]; partitions: number }) {
  return (
    <div className="flex flex-col gap-2">
      <div
        className="grid h-9 w-full gap-px overflow-hidden rounded bg-edge"
        style={{ gridTemplateColumns: `repeat(${partitions}, minmax(0, 1fr))` }}
        role="img"
        aria-label={`${partitions} slices; ${cells.filter((c) => c.holders.length > 0).length} have a machine on them`}
      >
        {cells.map((cell) => {
          const fill =
            cell.holders.length === 0 ? "bg-surface-3" : cell.holders.length === 1 ? "bg-accent/70" : "bg-ink-2/70";
          const ring = cell.leased.length > 0 ? "ring-2 ring-inset ring-accent" : "";
          const title = [
            cell.end > cell.first ? `slice ${cell.index}: pieces ${cell.first.toLocaleString("en-US")}–${(cell.end - 1).toLocaleString("en-US")}` : `slice ${cell.index}: no pieces`,
            cell.holders.length > 0 ? `on it: ${cell.holders.join(", ")}` : "nobody on it",
            cell.leased.length > 0 ? `task taken by ${cell.leased.join(", ")}` : "",
          ]
            .filter(Boolean)
            .join(" · ");
          return <div key={cell.index} className={`h-full ${fill} ${ring}`} title={title} />;
        })}
      </div>
      <p className="text-[11px] text-ink-3">
        <span className="text-accent">Green</span>: one machine on it. <span className="text-ink-2">Dark</span>: more
        than one. Light: nobody yet. Ringed: a machine has taken it as a task. Open slice details for ranges and names.
      </p>
      <Disclosure summary="Slice details">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[30rem] text-left text-[12px]">
            <thead><tr className="border-b border-edge">
              <th scope="col" className="px-2 py-2">Slice</th>
              <th scope="col" className="px-2 py-2">Pieces (inclusive)</th>
              <th scope="col" className="px-2 py-2">Machines reporting</th>
              <th scope="col" className="px-2 py-2">Task leases</th>
            </tr></thead>
            <tbody>{cells.map((cell) => <tr key={cell.index} className="border-b border-edge">
              <th scope="row" className="mono px-2 py-2 font-normal">{cell.index}</th>
              <td className="mono px-2 py-2">{cell.end > cell.first ? `${cell.first.toLocaleString("en-US")}–${(cell.end - 1).toLocaleString("en-US")}` : "No pieces"}</td>
              <td className="mono px-2 py-2">{cell.holders.join(", ") || "Nobody"}</td>
              <td className="mono px-2 py-2">{cell.leased.join(", ") || "None"}</td>
            </tr>)}</tbody>
          </table>
        </div>
      </Disclosure>
    </div>
  );
}

function ReportingLine({ worker }: { worker: ReportedWorker }) {
  return (
    <tr className="align-top hover:bg-surface-2">
      <td className="px-4 py-2.5">
        <span className="inline-flex items-center gap-1.5">
          <span
            className={`h-1.5 w-1.5 rounded-full ${worker.status === "live" ? "bg-accent" : "bg-ink-3"}`}
            title={worker.status}
          />
          <span className="mono text-ink">{worker.worker}</span>
        </span>
        {worker.device && <div className="pl-3 text-[11px] text-ink-3">{worker.device}</div>}
      </td>
      <td className="mono px-3 py-2.5 text-ink-2">
        {worker.units ? (
          <>
            {formatMagnitude(worker.units.first)}–{formatMagnitude(worker.units.end)}
            {worker.unit !== null && <span className="text-ink-3"> at {formatMagnitude(worker.unit)}</span>}
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
