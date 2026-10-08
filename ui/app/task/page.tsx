"use client";

import Link from "next/link";
import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  type ProgressResponse,
  type WorkerRow,
  NODE_URL,
  ObjectiveNotFound,
  RouteMissing,
  amount,
  assignedBins,
  collisionOdds,
  coverageFraction,
  denseHours,
  etaSeconds,
  fetchProgress,
  formatAge,
  formatDuration,
  formatLog2,
  formatMagnitude,
  formatPercent,
  formatRate,
  mergeWorkers,
  shareOfExpected,
  short,
  workerRate,
} from "@/lib/progress";
import { type SearchJob, expectedSteps, expectedUnits, jobFor, stepsPerUnit } from "@/lib/jobs";
import { fetchObjective } from "@/lib/frontier";
import { resolveNode } from "@/lib/site";
import {
  Badge,
  Box,
  CopyButton,
  EmptyState,
  Hash,
  MemberBadge,
  LiveStamp,
  Note,
  PageHeader,
  Progress,
  SectionHeading,
  Skeleton,
  Stat,
  StatusPill,
} from "@/components/ui";

/**
 * Seconds between reads while the tab is visible. A heartbeat is live for
 * 180 s and a worker posts about once a minute, so twenty seconds sees every
 * change in liveness within one interval without asking a node to re-read
 * its log faster than anything on it moves. The campaign's own status page
 * refreshes every sixty.
 */
const REFRESH_SECONDS = 20;

/** Hours of settlement history drawn. Two days fits a laptop window. */
const HISTORY_HOURS = 48;

/**
 * One objective's search in flight: what the log has paid for, what the
 * workers say they are doing, and how far that is along the expected cost.
 *
 * `?id=` rather than a path segment, as on `/challenge` -- this is a static
 * export embedded in the node binary. The page reads one route,
 * `GET /progress/{id}`, plus the objective record for the funder's
 * statement and verifier; everything it draws beyond those two answers is
 * arithmetic on them and on the job constants in `lib/jobs.ts`.
 */
export default function Page() {
  return (
    <Suspense
      fallback={
        <div className="flex flex-col gap-3">
          <Skeleton className="h-7 w-56" />
          <Skeleton className="h-4 w-full max-w-lg" />
        </div>
      }
    >
      <Task />
    </Suspense>
  );
}

function Task() {
  const params = useSearchParams();
  const id = params.get("id") ?? "";

  const [base, setBase] = useState(NODE_URL);
  const [progress, setProgress] = useState<ProgressResponse | null>(null);
  const [verifier, setVerifier] = useState<Record<string, unknown> | null>(null);
  const [statement, setStatement] = useState<string>("");
  const [funder, setFunder] = useState<string>("");
  const [reward, setReward] = useState<number>(0);
  const [error, setError] = useState<string | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [loading, setLoading] = useState(false);
  const [readAt, setReadAt] = useState<Date | null>(null);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const job: SearchJob | null = useMemo(() => jobFor(verifier), [verifier]);

  const load = useCallback(
    async (url: string, quiet = false) => {
      if (!id) return;
      if (!quiet) setLoading(true);
      setError(null);
      setNotFound(false);
      try {
        // The objective record carries the verifier, which names the job;
        // the trail_bits from the known job let the node bin paid seeds even
        // before any worker has declared them in a heartbeat.
        const record = await fetchObjective(id, url).catch(() => null);
        const known = jobFor(record?.record.verifier);
        const next = await fetchProgress(id, url, {
          trailBits: known?.trailBits,
        });
        setProgress(next);
        if (record) {
          setVerifier((record.record.verifier as Record<string, unknown>) ?? null);
          setStatement(record.record.statement);
          setFunder(record.record.funder);
          setReward(record.record.reward);
        }
        setReadAt(new Date());
      } catch (cause) {
        if (cause instanceof ObjectiveNotFound) {
          setNotFound(true);
        } else {
          setError(cause instanceof Error ? cause.message : String(cause));
        }
        if (!quiet) setProgress(null);
      } finally {
        setLoading(false);
      }
    },
    [id],
  );

  useEffect(() => {
    void resolveNode().then((url) => {
      setBase(url || window.location.origin);
      void load(url);
    });
  }, [load]);

  // Re-read on an interval while the tab is visible. Hidden tabs stop, and a
  // tab that comes back reads at once rather than waiting out the interval,
  // which is the moment a reader is actually looking.
  useEffect(() => {
    if (!progress) return;
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
    // `progress` is only a gate for "has loaded once"; re-arming on every
    // read would restart the interval each time it fires.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [base, load, progress !== null]);

  if (!id) {
    return (
      <>
        <h1 className="text-[26px] font-semibold">Which task?</h1>
        <p className="prose-block mt-2">
          This page needs an objective id: <code className="mono">/task?id=sha256:…</code>. Pick one
          from{" "}
          <Link href="/objectives" className="text-accent hover:underline">
            the objectives
          </Link>
          .
        </p>
      </>
    );
  }

  const picker = (
    <>
      <LiveStamp at={readAt} error={progress ? error : null} />
      <Link href={`/coordination?id=${encodeURIComponent(id)}`} className="btn btn-sm">
        Coordination
      </Link>
    </>
  );

  if (notFound) {
    return (
      <>
        <PageHeader
          crumb={{ href: "/objectives", label: "Objectives" }}
          title="No such task"
          actions={picker}
        />
        <EmptyState title={`This node knows no objective ${short(id)}.`}>
          A node only knows the objectives in its own log, so a different node may. The
          objective is also what workers post heartbeats against, so the dashboard has nothing
          to show until this node holds it.
        </EmptyState>
      </>
    );
  }

  if (error && !progress) {
    return (
      <>
        <PageHeader
          crumb={{ href: "/objectives", label: "Objectives" }}
          title="Task progress"
          actions={picker}
        />
        <Note title="Could not read this node" tone="bad">
          {error}
          {error.includes("newer than the node") && (
            <>
              {" "}
              Until then, settled work for this objective is visible on{" "}
              <Link href={`/challenge?id=${encodeURIComponent(id)}`} className="text-accent">
                its challenge page
              </Link>
              .
            </>
          )}
        </Note>
      </>
    );
  }

  if (!progress) {
    return (
      <div className="flex flex-col gap-3">
        <Skeleton className="h-7 w-56" />
        <Skeleton className="h-4 w-full max-w-lg" />
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
      progress={progress}
      job={job}
      statement={statement}
      funder={funder}
      reward={
        reward ||
        (progress.piecework?.paid_total ?? 0) + (progress.piecework?.pool_remaining ?? 0)
      }
      picker={picker}
      readAt={readAt}
      origin={base}
      stale={error}
    />
  );
}

function Dashboard({
  id,
  progress,
  job,
  statement,
  funder,
  reward,
  picker,
  readAt,
  origin,
  stale,
}: {
  id: string;
  progress: ProgressResponse;
  job: SearchJob | null;
  statement: string;
  funder: string;
  reward: number;
  picker: React.ReactNode;
  readAt: Date | null;
  origin: string;
  /** The last quiet re-read failed; the numbers shown are from before it. */
  stale: string | null;
}) {
  const { derived, reported, piecework } = progress;
  const rows = useMemo(
    () => mergeWorkers(derived.workers, reported.workers),
    [derived.workers, reported.workers],
  );

  const expected = job ? expectedSteps(job) : null;
  const perUnit = job ? stepsPerUnit(job) : null;
  const unitsExpected = job ? expectedUnits(job) : null;
  const share = expected ? shareOfExpected(derived.steps, expected) : null;
  const odds = expected ? collisionOdds(derived.steps, expected) : null;
  const rate = reported.live > 0 ? reported.steps_per_second : null;
  const eta = expected ? etaSeconds(derived.steps, expected, rate) : null;
  const unitsPerHour = derived.last_day.units_paid / 24;
  const poolSpent =
    piecework && reward > 0 ? Math.min(1, piecework.paid_total / reward) : null;
  const unitWord = job?.version === 2 ? "orbit" : "unit";
  const hours = useMemo(() => denseHours(derived.hourly, HISTORY_HOURS, new Date()), [derived.hourly]);

  return (
    <>
      <PageHeader
        crumb={{ href: "/objectives", label: "Objectives" }}
        title={progress.goal || short(id)}
        subtitle={
          job
            ? `${job.name}: a distributed Pollard rho paid per ${unitWord}. What the log has settled, beside what the workers report.`
            : progress.kind === "piecework"
              ? "A divided search paid per unit. What the log has settled, beside what the workers report."
              : "Not a divided search: this objective pays once, or along a ratchet. Its frontier is on the challenge page; what follows is whatever the log and the workers say about it."
        }
        meta={
          <>
            <StatusPill settled={progress.settled} />
            <Badge tone="accent">{progress.kind}</Badge>
            <LivePill live={reported.live} stale={reported.stale} />
            {funder && (
              <span>
                funded by <span className="mono text-ink">{funder}</span>
              </span>
            )}
            <Hash value={id} chars={8} />
          </>
        }
        actions={picker}
      />

      <p className="mb-4 text-[12px] text-ink-3">
        <span className="text-accent">Settled</span> figures are recomputed from the node&rsquo;s
        log; <span className="text-warn">reported</span> ones are what workers posted and nobody
        checked.
        {stale && <span className="text-bad"> The last re-read failed: {stale}</span>}
      </p>

      {/* -- the search ------------------------------------------------------ */}
      <div className="mb-3 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat
          label={`${capitalize(unitWord)}s paid`}
          value={amount(derived.units_paid)}
          from={
            unitsExpected
              ? `of about ${formatMagnitude(unitsExpected)} ${unitWord}s the whole search needs`
              : `${amount(derived.claims_paid)} paid claims, from the log`
          }
        />
        <Stat
          label="Group operations walked"
          value={derived.steps > 0 ? formatLog2(derived.steps) : "0"}
          from={
            derived.steps > 0
              ? `${formatMagnitude(derived.steps)}, summed from the paid witnesses`
              : "from the paid witnesses"
          }
          hint={derived.steps_method}
          tone="accent"
        />
        <Stat
          label="Share of expected work"
          value={formatPercent(share)}
          from={expected ? `expected ${formatLog2(expected)} ops for ${job?.name}` : "job unknown to this reader"}
          tone="accent"
        />
        <Stat
          label="Workers live"
          value={String(reported.live)}
          from={`${reported.stale} stale · ${reported.gone} gone · ${derived.workers.length} ever paid`}
        />
      </div>
      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat
          label="Rate, reported"
          value={formatRate(rate)}
          from={
            rate !== null
              ? "sum over live workers; measured by the node where it could"
              : "no live worker is reporting"
          }
          tone="warn"
        />
        <Stat
          label="To the expected cost"
          value={eta !== null ? formatDuration(eta) : "—"}
          from={
            eta === null
              ? expected
                ? "needs a live reported rate"
                : "needs a known job"
              : eta < 0
                ? "past it; a collision is a coin flip, not a certainty"
                : "at the reported rate, if it holds"
          }
          tone="warn"
        />
        <Stat
          label="Odds a collision happened"
          value={formatPercent(odds)}
          from={odds !== null ? "birthday bound on the settled work" : "needs a known job"}
          tone="accent"
        />
        <Stat
          label="Pool"
          value={piecework ? amount(piecework.pool_remaining) : "—"}
          from={
            piecework
              ? `left of ${amount(reward)}; ${amount(piecework.unit_price)} per ${unitWord}`
              : "not piecework"
          }
        />
      </div>

      <div className="mb-5 grid gap-4 lg:grid-cols-2">
        <Box title="Progress against the expected cost">
          {share !== null ? (
            <div className="flex flex-col gap-3">
              <Progress value={Math.min(1, share)} label="settled work, as a share of the expected cost" />
              <p className="text-[12.5px] text-ink-2">
                Pollard rho has no finish line, only an expectation: about{" "}
                <span className="mono">{formatLog2(expected!)}</span> group operations here, with
                even odds of a collision by 94% of that and nine in ten by 171%. The bar is the
                settled share; the odds tile is what that share is worth.
                {perUnit && (
                  <>
                    {" "}
                    One {unitWord} is about <span className="mono">{formatLog2(perUnit)}</span>{" "}
                    steps, so the step total is read off the paid witnesses rather than
                    estimated.
                  </>
                )}
              </p>
            </div>
          ) : (
            <p className="text-[12.5px] text-ink-2">
              This reader does not know the job this objective&rsquo;s checker pins, so it cannot
              say how far along the search is. The paid units and steps above are still exact;
              only the denominator is missing. Known jobs are listed in{" "}
              <span className="mono">ui/lib/jobs.ts</span>
              .
            </p>
          )}
        </Box>
        <Box title="Pool">
          <div className="flex flex-col gap-3">
            {poolSpent !== null ? (
              <Progress value={poolSpent} label="of the funded pool paid out" tone="warn" />
            ) : (
              <p className="text-[12.5px] text-ink-3">No pool to draw on.</p>
            )}
            <dl className="kv">
              <dt>paid out</dt>
              <dd className="mono">{amount(piecework?.paid_total ?? derived.reward)}</dd>
              <dt>paid claims</dt>
              <dd className="mono">{amount(derived.claims_paid)}</dd>
              <dt>last hour</dt>
              <dd className="mono">
                {amount(derived.last_hour.units_paid)} {unitWord}s in {amount(derived.last_hour.claims_paid)}{" "}
                claims
              </dd>
              <dt>last day</dt>
              <dd className="mono">
                {amount(derived.last_day.units_paid)} {unitWord}s · {unitsPerHour.toFixed(1)} an hour
              </dd>
              <dt>in flight</dt>
              <dd className="mono">
                {amount(derived.in_flight)} commitments not yet revealed
                {derived.rejected > 0 && <> · {amount(derived.rejected)} rejected</>}
              </dd>
            </dl>
          </div>
        </Box>
      </div>

      {/* -- workers ------------------------------------------------------- */}
      <SectionHeading
        count={rows.length}
        aside={
          <span className="text-[11px] text-ink-3">
            live within {reported.live_within_seconds} s · stale within {reported.stale_within_seconds} s
          </span>
        }
      >
        Workers
      </SectionHeading>
      {rows.length === 0 ? (
        <EmptyState title="Nobody has worked this objective yet">
          No settlement names a submitter and no worker has posted a heartbeat.
          A worker connected to this node will appear here after its first report.
        </EmptyState>
      ) : (
        <div className="box mb-5 overflow-x-auto">
          <table className="w-full min-w-[64rem] border-collapse text-left text-[12.5px]">
            <thead>
              <tr className="border-b border-edge text-[11px] text-ink-3">
                <th className="px-4 py-2 font-medium">Worker</th>
                <th className="px-3 py-2 font-medium">Status</th>
                <th className="px-3 py-2 text-right font-medium">
                  <span className="text-accent">{capitalize(unitWord)}s paid</span>
                </th>
                <th className="px-3 py-2 font-medium">Share of paid</th>
                <th className="px-3 py-2 text-right font-medium">
                  <span className="text-accent">Steps paid</span>
                </th>
                <th className="px-3 py-2 text-right font-medium">
                  <span className="text-warn">Rate</span>
                </th>
                <th className="px-3 py-2 text-right font-medium">
                  <span className="text-warn">Pending</span>
                </th>
                <th className="px-3 py-2 font-medium">
                  <span className="text-warn">Assignment</span>
                </th>
                <th className="px-3 py-2 font-medium">Last paid</th>
                <th className="px-4 py-2 font-medium">
                  <span className="text-warn">Last seen</span>
                </th>
              </tr>
            </thead>
            <tbody className="divide-edge-y">
              {rows.map((row) => (
                <WorkerLine key={row.name} row={row} total={derived.units_paid} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* -- the unit space and the history -------------------------------- */}
      <div className="mb-5 grid gap-4 lg:grid-cols-2">
        <Box
          title="Unit space"
          aside={
            derived.coverage ? (
              <span className="text-[11px] font-normal text-ink-3">
                {amount(derived.coverage.units_touched)} of {amount(derived.coverage.units)} units
                touched · {formatPercent(coverageFraction(derived.coverage))} of bins
              </span>
            ) : undefined
          }
        >
          {derived.coverage ? (
            <CoverageStrip
              counts={derived.coverage.counts}
              assigned={assignedBins(reported.workers, derived.coverage.units, derived.coverage.bins)}
            />
          ) : (
            <p className="text-[12.5px] text-ink-3">
              The unit each paid seed came from needs the job&rsquo;s seed layout, which no
              worker has declared yet and this reader does not know for this checker.
            </p>
          )}
        </Box>
        <Box title={`${capitalize(unitWord)}s settled per hour, last ${HISTORY_HOURS} h`}>
          <HourlyBars hours={hours} />
        </Box>
      </div>

      {/* -- the words ----------------------------------------------------- */}
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_22rem]">
        {statement && (
          <Box
            title="Statement"
            aside={
              <span className="text-[11px] font-normal text-warn">
                written by the funder, not checked
              </span>
            }
          >
            <p className="text-[13.5px] leading-relaxed text-ink [overflow-wrap:anywhere]">{statement}</p>
          </Box>
        )}
        <div className="flex min-w-0 flex-col gap-4">
          <Note title="Two kinds of number">
            {derived.note} {reported.note}
          </Note>
          <Box title="Elsewhere">
            <ul className="flex flex-col gap-1.5 text-[13px]">
              <li>
                <Link href={`/challenge?id=${encodeURIComponent(id)}`} className="text-accent hover:underline">
                  The objective: statement, checker, how to submit →
                </Link>
              </li>
              <li>
                <Link href="/log" className="text-accent hover:underline">
                  Every record this page was derived from →
                </Link>
              </li>
              {job && (
                <li className="text-ink-2">
                  The job document: <span className="mono">{job.path}</span> in a checkout.
                </li>
              )}
            </ul>
            <p className="mt-3 text-[12.5px] text-ink-2">
              Run a worker against this node, from a checkout:
            </p>
            <div className="relative mt-1.5">
              <pre className="code pr-9 text-[11.5px]">{workerCommand(origin, id, job)}</pre>
              <div className="absolute top-2 right-2">
                <CopyButton value={workerCommand(origin, id, job)} />
              </div>
            </div>
          </Box>
        </div>
      </div>
    </>
  );
}

function LivePill({ live, stale }: { live: number; stale: number }) {
  if (live === 0 && stale === 0) {
    return <span className="pill pill-settled">no workers reporting</span>;
  }
  return (
    <span className={`pill ${live > 0 ? "pill-open" : "pill-settled"}`}>
      {live} live{stale > 0 && <>, {stale} stale</>}
    </span>
  );
}

function WorkerLine({ row, total }: { row: WorkerRow; total: number }) {
  const paid = row.derived?.units_paid ?? 0;
  const share = total > 0 ? paid / total : 0;
  const rate = workerRate(row.reported);
  const tone =
    row.status === "live" ? "accent" : row.status === "stale" ? "warn" : row.status === "gone" ? "bad" : "neutral";
  return (
    <tr className="align-top transition-colors hover:bg-surface-2">
      <td className="mono px-4 py-2.5 text-ink">
        {row.name}
        <MemberBadge member={row.reported?.member} />
        {row.reported?.device && (
          <div className="text-[11px] text-ink-3">{row.reported.device}</div>
        )}
      </td>
      <td className="px-3 py-2.5">
        <Badge tone={tone} title={row.status === "settled" ? "known from settlements only; no heartbeat" : undefined}>
          {row.status === "settled" ? "no heartbeat" : row.status}
        </Badge>
      </td>
      <td className="mono px-3 py-2.5 text-right text-ink">{amount(paid)}</td>
      <td className="px-3 py-2.5">
        <div className="w-28">
          <Progress value={share} />
        </div>
      </td>
      <td className="mono px-3 py-2.5 text-right text-ink-2" title={row.derived ? String(row.derived.steps) : undefined}>
        {row.derived && row.derived.steps > 0 ? formatLog2(row.derived.steps) : "—"}
      </td>
      <td className="mono px-3 py-2.5 text-right text-ink-2">{formatRate(rate)}</td>
      <td className="mono px-3 py-2.5 text-right text-ink-2">
        {row.reported ? amount(row.reported.units_pending) : "—"}
        {row.derived && row.derived.in_flight > 0 && (
          <span className="text-ink-3" title="commitments not yet revealed">
            {" "}
            +{row.derived.in_flight}
          </span>
        )}
      </td>
      <td className="mono px-3 py-2.5 text-ink-2">
        {row.reported?.units ? (
          <>
            [{amount(row.reported.units.first)}, {amount(row.reported.units.end)})
            {row.reported.unit !== null && <span className="text-ink-3"> at {amount(row.reported.unit)}</span>}
          </>
        ) : (
          "—"
        )}
      </td>
      <td className="mono px-3 py-2.5 text-[12px] text-ink-3" title={row.derived?.last_paid_at ?? undefined}>
        {row.derived?.last_paid_at ? row.derived.last_paid_at.slice(0, 16).replace("T", " ") : "—"}
      </td>
      <td className="mono px-4 py-2.5 text-[12px] text-ink-3" title={row.reported?.received_at}>
        {row.reported ? formatAge(row.reported.age_seconds) : "—"}
      </td>
    </tr>
  );
}

/**
 * The unit space as a strip: one cell per bin, darker where more paid
 * elements came from, with the live workers' assignments drawn under it so
 * the two layers line up -- what has been walked, over what is being walked.
 */
function CoverageStrip({
  counts,
  assigned,
}: {
  counts: number[];
  assigned: { name: string; from: number; to: number }[];
}) {
  const max = Math.max(1, ...counts);
  const bins = counts.length;
  return (
    <div className="flex flex-col gap-2">
      <div
        className="flex h-8 w-full overflow-hidden rounded bg-surface-3"
        role="img"
        aria-label={`${counts.filter((c) => c > 0).length} of ${bins} bins of the unit space have paid elements`}
      >
        {counts.map((count, i) => (
          <div
            key={i}
            className="h-full flex-1 bg-accent"
            style={{ opacity: count === 0 ? 0 : 0.25 + 0.75 * Math.sqrt(count / max) }}
            title={`bin ${i}: ${count} paid element${count === 1 ? "" : "s"}`}
          />
        ))}
      </div>
      <div className="relative h-3 w-full" aria-label="live assignments this epoch">
        {assigned.map((range, i) => (
          <div
            key={`${range.name}-${i}`}
            className="absolute top-0 h-full rounded-sm bg-warn/70"
            style={{
              left: `${(range.from / bins) * 100}%`,
              width: `${Math.max(0.5, ((range.to - range.from + 1) / bins) * 100)}%`,
            }}
            title={`${range.name}: bins ${range.from}–${range.to}`}
          />
        ))}
      </div>
      <p className="text-[11px] text-ink-3">
        <span className="text-accent">Green</span>: where paid elements came from, by seed, darker
        with more. <span className="text-ink-2">Grey</span>: the unit ranges live workers report
        holding this epoch. {bins} bins.
      </p>
    </div>
  );
}

/** Settled units per hour as bars. Inline SVG, no chart library. */
function HourlyBars({ hours }: { hours: { hour: string; units_paid: number }[] }) {
  const max = Math.max(1, ...hours.map((h) => h.units_paid));
  const total = hours.reduce((sum, h) => sum + h.units_paid, 0);
  const width = 100;
  const gap = 0.15;
  const slot = width / hours.length;
  return (
    <div className="flex flex-col gap-2">
      <svg
        viewBox={`0 0 ${width} 32`}
        preserveAspectRatio="none"
        className="h-24 w-full"
        role="img"
        aria-label={`${total} units settled over the last ${hours.length} hours`}
      >
        {hours.map((hour, i) => {
          const h = (hour.units_paid / max) * 30;
          return (
            <rect
              key={hour.hour}
              x={i * slot + (slot * gap) / 2}
              y={32 - h}
              width={slot * (1 - gap)}
              height={h}
              className="fill-accent"
              opacity={hour.units_paid === 0 ? 0 : 0.9}
            >
              <title>
                {hour.hour.slice(0, 13).replace("T", " ")}: {hour.units_paid} paid
              </title>
            </rect>
          );
        })}
        <line x1="0" y1="31.75" x2={width} y2="31.75" className="stroke-edge-strong" strokeWidth="0.5" />
      </svg>
      <p className="text-[11px] text-ink-3">
        {total === 0
          ? "Nothing settled in this window. An hour with no bar is an hour with no settlement, not missing data."
          : `${amount(total)} in the window; the tallest bar is ${amount(max)}. An empty hour is an hour with no settlement.`}
      </p>
    </div>
  );
}

/**
 * The command that works this objective from a checkout, with this node and
 * this objective filled in. The reference worker and the job document are
 * named by path rather than linked: this page links nowhere off the node it
 * was served from.
 */
function workerCommand(origin: string, id: string, job: SearchJob | null | undefined): string {
  return [
    "python3 examples/certicom-ecdlp/tools/orbit_worker.py",
    `--node ${origin}`,
    `--job ${job?.path ?? "<job document>"}`,
    `--objective ${id}`,
    "--worker <your name>",
  ].join(" \\\n  ");
}

function capitalize(word: string): string {
  return word.charAt(0).toUpperCase() + word.slice(1);
}
