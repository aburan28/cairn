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
  claimCommand,
  coverageSummary,
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
import { type McpPresence, PromptRefused, renderPrompt, slashCommand } from "@/lib/agents";
import { type Bridge, appBridge } from "@/lib/draft";
import { objectiveTitle } from "@/lib/title";
import { AgentConnect } from "@/components/agents";
import { useEvery, useNode } from "@/components/hooks";
import {
  Badge,
  Box,
  Command,
  CopyButton,
  Disclosure,
  EmptyState,
  Hash,
  LiveStamp,
  MemberBadge,
  Note,
  PageHeader,
  Progress,
  Sheet,
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
 * needs a checker written and pinned, which no page may do for a node (see
 * `lib/draft.ts`): so the page asks the node for its `coordinate_task` prompt,
 * hands it to the operator's agent, and watches for the objective to appear.
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
  return id ? <Search id={id} /> : <Overview />;
}

// -- the overview: launch, and what is running ------------------------------------

function Overview() {
  const base = useNode();
  const [objectives, setObjectives] = useState<Objective[] | null>(null);
  const [network, setNetwork] = useState<NetworkResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [readAt, setReadAt] = useState<Date | null>(null);

  const load = useCallback(async () => {
    if (base === null) return;
    try {
      const [listing, net] = await Promise.all([fetchObjectives(base), fetchNetwork(base).catch(() => null)]);
      setObjectives(listing);
      setNetwork(net);
      setReadAt(new Date());
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, [base]);

  useEvery(load, REFRESH_SECONDS, base !== null);

  const running = useMemo(
    () =>
      (objectives ?? [])
        .filter((o) => o.piecework)
        .sort((a, b) => Number(b.open) - Number(a.open) || b.reward - a.reward),
    [objectives],
  );
  const live = useMemo(() => {
    const by = new Map<string, number>();
    for (const row of network?.compute.objectives ?? []) by.set(row.objective_id, row.live);
    return by;
  }, [network]);

  return (
    <>
      <PageHeader title="Coordination" subtitle={SUBTITLE} actions={<LiveStamp at={readAt} error={objectives ? error : null} />} />

      <Launch base={base} objectives={objectives} mcp={network?.node.mcp} onPosted={() => void load()} />

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
        <EmptyState title="No coordinated task yet">
          Describe one above and your agent will set it up. Any challenge with a{" "}
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

/**
 * Describe → prompt → the agent posts it → the page sees it.
 *
 * The prompt is the node's (`POST /prompts/coordinate_task`), the same text
 * Claude Code gets from `/mcp__cairn__coordinate_task`, so the page and the
 * slash command teach one format. The page then watches `/objectives` for a
 * divided search it had not seen when the prompt was written: that is the
 * agent's post arriving, whichever agent made it.
 */
function Launch({
  base,
  objectives,
  mcp,
  onPosted,
}: {
  base: string | null;
  objectives: Objective[] | null;
  mcp: McpPresence | undefined;
  onPosted: () => void;
}) {
  const [description, setDescription] = useState("");
  const [budget, setBudget] = useState("");
  const [prompt, setPrompt] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [connect, setConnect] = useState(false);
  const [bridge, setBridge] = useState<Bridge | null>(null);
  /** Divided searches that existed when the prompt was written. */
  const known = useRef<Set<string> | null>(null);
  const [posted, setPosted] = useState<Objective | null>(null);

  useEffect(() => setBridge(appBridge()), []);

  useEffect(() => {
    if (!prompt || !objectives || !known.current) return;
    const fresh = objectives.find((o) => o.piecework && !known.current!.has(o.id));
    if (fresh) setPosted(fresh);
  }, [objectives, prompt]);

  // Ask more often while waiting for the agent's post: it is the one moment
  // somebody is staring at this box.
  useEvery(onPosted, 8, prompt !== null && posted === null);

  async function write() {
    if (base === null) return;
    setBusy(true);
    setProblem(null);
    try {
      const args: Record<string, string> = { description: description.trim() };
      if (budget.trim()) args.budget = budget.trim();
      const text = await renderPrompt(base, "coordinate_task", args);
      known.current = new Set((objectives ?? []).filter((o) => o.piecework).map((o) => o.id));
      setPosted(null);
      setPrompt(text);
    } catch (cause) {
      setProblem(
        cause instanceof PromptRefused
          ? cause.message
          : cause instanceof Error
            ? cause.message
            : String(cause),
      );
    } finally {
      setBusy(false);
    }
  }

  const attached = mcp?.serving && mcp.client ? mcp.client : null;
  const ready = description.trim().length >= 20;

  return (
    <section id="launch" className="card card-pad scroll-mt-6">
      <div className="flex flex-wrap items-baseline gap-2">
        <h2 className="text-[15px] font-semibold text-ink">Launch a coordinated task</h2>
        <span className="text-[12.5px] text-ink-3">
          Say what to search and what one finished piece is. Your agent turns it into a challenge.
        </span>
      </div>

      <textarea
        className="field mt-3 min-h-28 resize-y leading-relaxed"
        value={description}
        onChange={(event) => {
          setDescription(event.target.value);
          setPrompt(null);
        }}
        placeholder="e.g. Search every 32-bit seed of this generator for one whose first output is 0xdeadbeef. One piece is a block of 65,536 seeds."
        aria-label="Describe the task"
        maxLength={8000}
      />
      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        <span className="text-[11.5px] text-ink-3">Try:</span>
        {EXAMPLES.map((example, n) => (
          <button
            key={n}
            type="button"
            className="btn btn-sm btn-ghost text-ink-2"
            onClick={() => {
              setDescription(example);
              setPrompt(null);
            }}
            title={example}
          >
            {["Seed search", "Collatz ranges", "Rho points"][n]}
          </button>
        ))}
      </div>

      <div className="mt-3 flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-[12px] text-ink-3">
          Budget (optional)
          <input
            className="field field-mono w-40"
            inputMode="numeric"
            placeholder="units in all"
            value={budget}
            onChange={(event) => {
              setBudget(event.target.value);
              setPrompt(null);
            }}
          />
        </label>
        <button type="button" className="btn btn-primary" disabled={!ready || busy || base === null} onClick={() => void write()}>
          {busy ? "Writing…" : "Write the agent prompt"}
        </button>
        {!ready && description.trim().length > 0 && (
          <span className="text-[12px] text-ink-3">A sentence or two more: what is searched, and what one piece is.</span>
        )}
      </div>
      {problem && <p className="mt-2 text-[12.5px] text-bad">{problem}</p>}

      {prompt && (
        <ol className="mt-5 flex flex-col gap-4 border-t border-edge pt-4">
          <li>
            <Step n={1} title="Give this to your agent">
              {attached ? (
                <>
                  <span className="text-accent">{attached.name}</span> is attached to this node now. In Claude Code you
                  can also type <span className="mono">{slashCommand("coordinate_task")}</span> and paste your description.
                </>
              ) : (
                <>
                  Paste it into Claude Code, Codex or OpenCode with the cairn tools.{" "}
                  <button type="button" className="text-accent hover:underline" onClick={() => setConnect(true)}>
                    No agent connected yet?
                  </button>
                </>
              )}
            </Step>
            <div className="relative mt-2">
              <pre className="code max-h-72 overflow-y-auto pr-9 text-[11.5px]">{prompt}</pre>
              <div className="absolute top-2 right-2">
                <CopyButton value={prompt} />
              </div>
            </div>
          </li>
          <li>
            <Step n={2} title="It writes the checker, tests it, and asks you">
              The agent writes a checker that accepts only a correctly finished piece, runs it on a good and a bad
              example, and shows you the challenge — pieces, price per piece, budget — before posting anything.
            </Step>
          </li>
          <li>
            <Step n={3} title={posted ? "Posted" : "Waiting for it to appear"}>
              {posted ? (
                <>
                  <Link href={`/coordination?id=${encodeURIComponent(posted.id)}`} className="text-accent hover:underline">
                    {objectiveTitle(posted)} →
                  </Link>{" "}
                  Machines join it from <Link href="/contribute#compute" className="text-accent hover:underline">Contribute</Link>.
                </>
              ) : (
                <span className="inline-flex items-center gap-2">
                  <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent" aria-hidden />
                  Watching this node for a new coordinated task.
                </span>
              )}
            </Step>
          </li>
        </ol>
      )}

      {connect && (
        <Sheet title="Connect an agent" onClose={() => setConnect(false)}>
          <AgentConnect bridge={bridge} />
        </Sheet>
      )}
    </section>
  );
}

function Step({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-3">
      <span className="mono flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-accent-soft text-[11px] text-accent">
        {n}
      </span>
      <div className="min-w-0">
        <div className="text-[13px] font-medium text-ink">{title}</div>
        <div className="mt-0.5 text-[12.5px] leading-relaxed text-ink-2">{children}</div>
      </div>
    </div>
  );
}

// -- one search ---------------------------------------------------------------------

function Search({ id }: { id: string }) {
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
    try {
      // The assignment is asked for as a reader -- the name is immaterial,
      // the answer is a pure function -- and the leases route may be newer
      // than the node, which is a fact to show rather than a failure.
      const [nextAssignment, nextProgress, nextLeases] = await Promise.all([
        fetchAssignment(id, "reader", partitions, base),
        fetchProgress(id, base),
        fetchLeases(id, base).catch((cause: unknown) => {
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
      setError(null);
      setNotFound(false);
    } catch (cause) {
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
      origin={base || (typeof window === "undefined" ? "" : window.location.origin)}
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
  origin,
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
  origin: string;
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

      <Disclosure summary="How the work is split, and the commands behind it">
        <div className="grid gap-4 lg:grid-cols-2">
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
          <div className="flex flex-col gap-2 text-[12.5px] text-ink-2">
            <div>A machine&rsquo;s slice for this epoch:</div>
            <Command
              text={`curl -s '${origin}/work_assignment?objective_id=${id}&node_id=<machine name>&partitions=${partitions}'`}
            />
            <div>Taking a task, so the next machine picks another:</div>
            <Command text={claimCommand(origin, id, units)} />
          </div>
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
            `slice ${cell.index}: pieces ${cell.first.toLocaleString("en-US")}–${cell.end.toLocaleString("en-US")}`,
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
        than one. Light: nobody yet. Ringed: a machine has taken it as a task. Hover for names.
      </p>
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
