"use client";

import Link from "next/link";
import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  type ProgressResponse,
  type WorkerRow,
  NODE_URL,
  ObjectiveNotFound,
  amount,
  assignedBins,
  collisionOdds,
  denseHours,
  fetchProgress,
  formatAge,
  formatLog2,
  formatMagnitude,
  formatPercent,
  formatRate,
  mergeWorkers,
  shareOfExpected,
  short,
  workForOdds,
  workerRate,
} from "@/lib/progress";
import { type SearchJob, expectedSteps, expectedUnits, jobFor, stepsPerUnit } from "@/lib/jobs";
import { type Objective, fetchObjectives } from "@/lib/objectives";
import { fetchObjective } from "@/lib/frontier";
import { resolveNode } from "@/lib/site";
import { goalSlug } from "@/lib/title";
import { WorkPanel } from "@/components/WorkPanel";
import {
  Badge,
  Box,
  Disclosure,
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
    return <ProgressIndex />;
  }

  const picker = <LiveStamp at={readAt} error={progress ? error : null} />;

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
      base={base}
      progress={progress}
      job={job}
      funder={funder}
      reward={
        reward ||
        (progress.piecework?.paid_total ?? 0) + (progress.piecework?.pool_remaining ?? 0)
      }
      picker={picker}
      stale={error}
    />
  );
}

/** The navigation destination is useful without a copied objective id. */
function ProgressIndex() {
  const router = useRouter();
  const [objectives, setObjectives] = useState<Objective[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [readAt, setReadAt] = useState<Date | null>(null);

  useEffect(() => {
    let active = true;
    void resolveNode().then((base) => fetchObjectives(base)).then((list) => {
      if (!active) return;
      setObjectives(list);
      setReadAt(new Date());
    }).catch((cause: unknown) => {
      if (active) setError(cause instanceof Error ? cause.message : String(cause));
    });
    return () => { active = false; };
  }, []);

  const searches = useMemo(() =>
    (objectives ?? [])
      .filter((objective) => objective.piecework)
      .sort((a, b) => Number(b.open) - Number(a.open) || a.goal.localeCompare(b.goal)),
  [objectives]);

  useEffect(() => {
    if (searches.length === 1) {
      router.replace(`/task?id=${encodeURIComponent(searches[0].id)}`);
    }
  }, [router, searches]);

  return (
    <>
      <PageHeader
        title="Progress"
        subtitle="Follow verified results and current activity for a shared search."
        actions={<LiveStamp at={readAt} error={error} />}
      />
      {error && <Note title="Could not read this node" tone="bad">{error}</Note>}
      {!error && objectives === null && <Skeleton className="h-32 w-full" />}
      {!error && searches.length === 1 && <Skeleton className="h-32 w-full" />}
      {!error && objectives !== null && searches.length === 0 && (
        <EmptyState title="No shared searches yet">
          When this node has a search divided into paid tasks, its progress will appear here.
        </EmptyState>
      )}
      {searches.length > 1 && (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {searches.map((objective) => (
            <Link
              key={objective.id}
              href={`/task?id=${encodeURIComponent(objective.id)}`}
              className="box block p-5 transition-colors hover:bg-surface-2 focus-visible:outline-2 focus-visible:outline-accent"
            >
              <div className="mb-3 flex items-center justify-between gap-3">
                <Badge tone={objective.open ? "accent" : "neutral"}>
                  {objective.open ? "Open" : "Settled"}
                </Badge>
                <span className="text-[11px] text-ink-3">View progress →</span>
              </div>
              <h2 className="text-[17px] font-semibold text-ink">
                {objective.goal ? goalSlug(objective.goal) : short(objective.id)}
              </h2>
              <p className="mt-2 text-[12.5px] text-ink-2">
                {amount(objective.piecework?.pool_remaining ?? 0)} available to pay ·{" "}
                {amount(objective.piecework?.paid_total ?? 0)} paid
              </p>
            </Link>
          ))}
        </div>
      )}
    </>
  );
}

function Dashboard({
  id,
  base,
  progress,
  job,
  funder,
  reward,
  picker,
  stale,
}: {
  id: string;
  base: string;
  progress: ProgressResponse;
  job: SearchJob | null;
  funder: string;
  reward: number;
  picker: React.ReactNode;
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
  const medianWork = expected ? workForOdds(0.5, expected) : null;
  const ninetyWork = expected ? workForOdds(0.9, expected) : null;
  const unitsPerHour = derived.last_day.units_paid / 24;
  const poolSpent =
    piecework && reward > 0 ? Math.min(1, piecework.paid_total / reward) : null;
  const unitWord = job?.version === 2 ? "orbit" : "unit";
  const hours = useMemo(() => {
    const generated = Date.parse(progress.generated_at);
    // On a failed refresh, keep the chart's window at the last node snapshot;
    // filling later hours with zeros would turn missing data into no work.
    return denseHours(derived.hourly, HISTORY_HOURS,
      new Date(Number.isFinite(generated) ? generated : Date.now()));
  }, [derived.hourly, progress.generated_at]);

  const searchName = progress.goal
    ? goalSlug(progress.goal).toUpperCase()
    : job?.name.replace(/^cairn /, "") ?? short(id);

  return (
    <>
      <PageHeader
        crumb={{ href: "/task", label: "Progress" }}
        title={searchName}
        subtitle={
          progress.kind === "piecework"
            ? "See verified results, current contributors, and rewards for this shared search."
            : "See verified results and current contributor activity."
        }
        meta={<StatusPill settled={progress.settled} />}
        actions={
          <>
            {picker}
            {!progress.settled && (
              <Link
                href={"/contribute?objective=" + encodeURIComponent(id) + "#compute"}
                className="btn btn-primary btn-sm"
              >
                Contribute to this search
              </Link>
            )}
          </>
        }
      />

      {stale && (
        <div className="mb-4">
          <Note title="Could not refresh this page" tone="bad">
            Showing the last successful read. {stale}
          </Note>
        </div>
      )}

      {!stale && derived.units_paid > 0 && derived.last_hour.units_paid === 0 && (
        <div className="mb-4">
          <Note title="Nothing paid in the last hour" tone="warn">
            Workers may still be walking. The latest verified result was{" "}
            {derived.last_paid_at && Number.isFinite(Date.parse(derived.last_paid_at))
              ? formatAge(Math.max(0, (Date.now() - Date.parse(derived.last_paid_at)) / 1000))
              : "earlier"}.
          </Note>
        </div>
      )}

      <section className="box mb-5 overflow-hidden p-5 md:p-6" aria-label="Search progress dashboard">
        <div className="flex flex-wrap items-start justify-between gap-5">
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-ink-3">
              Operations in paid trails
            </p>
            <p className="mono mt-2 text-[42px] font-semibold leading-none text-accent md:text-[52px]">
              {derived.steps > 0 ? formatLog2(derived.steps) : "0"}
            </p>
            <p className="mt-2 text-[12.5px] text-ink-2">
              {amount(derived.steps)} counted from paid witnesses; capped and unpaid trails are excluded
            </p>
          </div>
          <div className="min-w-[12rem] rounded-lg border border-edge bg-surface-2 px-4 py-3">
            <p className="text-[11px] text-ink-3">Model chance on paid trails</p>
            <p className="mono mt-1 text-[29px] font-semibold text-accent">{formatPercent(odds)}</p>
            <p className="text-[11px] text-ink-3">from verified work and the search model</p>
          </div>
        </div>

        {expected ? (
          <>
            <div className="mt-5 rounded-lg border border-edge bg-surface-2 p-3 md:p-4">
              <ProbabilityCurve steps={derived.steps} expected={expected} />
            </div>
            <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <HeroMetric
                label="Paid work vs expected cost"
                value={formatPercent(share)}
                note={`${formatLog2(expected)} operations is the model mean`}
              />
              <HeroMetric
                label="Live reported rate"
                value={rate && rate > 0 ? formatRate(rate) : "—"}
                note={rate && rate > 0 ? `${reported.live} worker${reported.live === 1 ? "" : "s"} reporting` : "No live rate reported"}
              />
              <HeroMetric
                label="Paid in the last hour"
                value={`${amount(derived.last_hour.units_paid)} ${unitWord}${derived.last_hour.units_paid === 1 ? "" : "s"}`}
                note="Settled in this node's log"
              />
              <HeroMetric
                label="Operations reported now"
                value={reported.live > 0 ? formatMagnitude(reported.steps) : "—"}
                note="Live worker session counters; not a lifetime total"
              />
            </div>
            <p className="mt-4 text-[12px] leading-relaxed text-ink-3">
              The curve is a random-walk estimate using only operations in paid witness trails.
              It cannot include other work the fleet may have done. The live rate is self-reported
              and is not added to the curve. Reaching the expected cost does not guarantee a collision.
            </p>
          </>
        ) : (
          <p className="mt-5 text-[12.5px] text-ink-2">
            This reader does not know the search parameters pinned by this checker, so it cannot
            estimate collision odds. Verified work and contributor activity remain available below.
          </p>
        )}
      </section>

      {!progress.settled && <WorkPanel objective={id} base={base} />}

      <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat
          label={"Verified " + unitWord + "s"}
          value={amount(derived.units_paid)}
          from={amount(derived.claims_paid) + " paid claims in the log"}
          tone="accent"
        />
        <Stat
          label="Paid claims"
          value={amount(derived.claims_paid)}
          from="Verified settlements in the log"
        />
        <Stat
          label={piecework ? "Reward remaining" : "Objective reward"}
          value={piecework ? amount(piecework.pool_remaining) : amount(reward)}
          from={piecework ? amount(piecework.unit_price) + " per verified " + unitWord : "Objective reward"}
        />
        <Stat
          label="Awaiting reveal"
          value={amount(derived.in_flight)}
          from="Committed, not yet verified"
        />
      </div>

      <div className="mb-5 grid gap-4 lg:grid-cols-2">
        <Box title={"Verified " + unitWord + "s by hour · last " + HISTORY_HOURS + " hours"}>
          <HourlyBars hours={hours} />
        </Box>
        <Box title={"Cumulative verified " + unitWord + "s · last " + HISTORY_HOURS + " hours"}>
          <CumulativeChart hours={hours} total={derived.units_paid} unitWord={unitWord} />
        </Box>
      </div>

      <div className="mb-5 grid gap-4 lg:grid-cols-2">
        <Box
          title="Where verified work came from"
          aside={derived.coverage ? <span className="text-[11px] font-normal text-ink-3">
            {amount(derived.coverage.units_touched)} of {amount(derived.coverage.units)} units touched
          </span> : undefined}
        >
          {derived.coverage ? (
            <CoverageStrip
              counts={derived.coverage.counts}
              assigned={assignedBins(reported.workers, derived.coverage.units, derived.coverage.bins)}
            />
          ) : (
            <p className="text-[12.5px] text-ink-3">No unit coverage is available yet.</p>
          )}
        </Box>
        <Box title="Reward pool">
          {poolSpent !== null ? (
            <div className="flex flex-col gap-3">
              <Progress value={poolSpent} label="Paid from the funded pool" />
              <p className="text-[12.5px] text-ink-2">
                {amount(piecework?.paid_total ?? 0)} paid of {amount(reward)} funded.
                {derived.last_day.units_paid > 0
                  ? " " + amount(derived.last_day.units_paid) + " " + unitWord + "s paid in the last day."
                  : " No work was paid in the last day."}
              </p>
            </div>
          ) : (
            <p className="text-[12.5px] text-ink-2">This objective has no per-unit reward pool.</p>
          )}
        </Box>
      </div>

      <SectionHeading count={rows.length}>Contributors</SectionHeading>
      {rows.length === 0 ? (
        <EmptyState
          title="No contributors to show yet"
          action={
            !progress.settled ? (
              <Link href={"/contribute?objective=" + encodeURIComponent(id) + "#compute"} className="btn btn-primary btn-sm">
                Start contributing
              </Link>
            ) : undefined
          }
        >
          This node has no paid contributor or recent worker report for this search.
        </EmptyState>
      ) : (
        <div className="box mb-5 overflow-x-auto">
          <table className="w-full min-w-[40rem] border-collapse text-left text-[12.5px]">
            <thead>
              <tr className="border-b border-edge text-[11px] text-ink-3">
                <th className="px-4 py-2 font-medium">Contributor</th>
                <th className="px-3 py-2 font-medium">Activity</th>
                <th className="px-3 py-2 text-right font-medium">Verified {unitWord}s</th>
                <th className="px-3 py-2 text-right font-medium">Reported rate</th>
                <th className="px-3 py-2 font-medium">Last seen</th>
              </tr>
            </thead>
            <tbody className="divide-edge-y">
              {rows.map((row) => (
                <WorkerLine key={row.name} row={row} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Disclosure summary="Search details and history">
        <div className="grid gap-4 lg:grid-cols-2">
          <Box title="Search estimate">
            <dl className="kv">
              <dt>Verified steps</dt>
              <dd className="mono" title={derived.steps_method}>
                {derived.steps > 0 ? formatLog2(derived.steps) : "0"}
              </dd>
              <dt>Expected effort</dt>
              <dd className="mono">{expected ? formatLog2(expected) : "—"}</dd>
              <dt>Estimated collision chance</dt>
              <dd className="mono">{formatPercent(odds)}</dd>
              <dt>Reported worker rate</dt>
              <dd className="mono">{formatRate(rate)}</dd>
              <dt>Work for 50% odds</dt>
              <dd className="mono">{medianWork ? formatLog2(medianWork) : "—"}</dd>
              <dt>Work for 90% odds</dt>
              <dd className="mono">{ninetyWork ? formatLog2(ninetyWork) : "—"}</dd>
            </dl>
            <p className="mt-3 text-[12px] text-ink-3">
              {job ? "The estimate uses this search's known parameters and paid witness trails only." : "Search parameters are unavailable."}
              {unitsExpected && perUnit
                ? " About " + formatMagnitude(unitsExpected) + " " + unitWord + "s are expected across the search."
                : ""}
            </p>
          </Box>
          <Box title="Recent activity">
            <dl className="kv">
              <dt>Last hour</dt>
              <dd className="mono">{amount(derived.last_hour.units_paid)} {unitWord}s paid</dd>
              <dt>Last day</dt>
              <dd className="mono">{amount(derived.last_day.units_paid)} {unitWord}s paid</dd>
              <dt>Average, last day</dt>
              <dd className="mono">{unitsPerHour.toFixed(1)} per hour</dd>
              <dt>Workers no longer live</dt>
              <dd className="mono">{reported.stale} stale · {reported.gone} gone</dd>
              <dt>Rejected claims</dt>
              <dd className="mono">{amount(derived.rejected)}</dd>
              {(derived.unavailable ?? 0) > 0 && (
                <>
                  <dt>Checks unavailable</dt>
                  <dd className="mono">{amount(derived.unavailable ?? 0)}</dd>
                </>
              )}
              {(derived.invalid_spec ?? 0) > 0 && (
                <>
                  <dt>Verifier setup errors</dt>
                  <dd className="mono">{amount(derived.invalid_spec ?? 0)}</dd>
                </>
              )}
            </dl>
          </Box>
        </div>
      </Disclosure>

      <div className="mt-5 border-t border-edge pt-4 text-[12.5px] text-ink-2">
        <p>
          Verified results and payouts come from the node&rsquo;s log. Worker activity is self-reported
          and may be incomplete.
        </p>
        <div className="mt-2 flex flex-wrap gap-x-5 gap-y-1">
          <Link href={"/challenge?id=" + encodeURIComponent(id)} className="text-accent hover:underline">
            Challenge details →
          </Link>
          <Link href={"/coordination?id=" + encodeURIComponent(id)} className="text-accent hover:underline">
            Coordination →
          </Link>
          <Link href="/network" className="text-accent hover:underline">Network →</Link>
          <Link href="/log" className="text-accent hover:underline">Verified records →</Link>
        </div>
        <Disclosure summary="Record identity and funding">
          <div className="flex flex-wrap items-center gap-2 text-[12px]">
            {funder && <span>Funded by <span className="mono">{funder}</span></span>}
            <Hash value={id} chars={8} />
          </div>
        </Disclosure>
      </div>
    </>
  );
}

function HeroMetric({ label, value, note }: { label: string; value: string; note: string }) {
  return (
    <div className="rounded-lg border border-edge bg-surface-2 px-3 py-3">
      <p className="text-[11px] text-ink-3">{label}</p>
      <p className="mono mt-1 text-[20px] font-semibold text-ink">{value}</p>
      <p className="mt-1 text-[11px] leading-snug text-ink-3">{note}</p>
    </div>
  );
}

/** Probability against counted work in paid witness trails. */
function ProbabilityCurve({ steps, expected }: { steps: number; expected: number }) {
  const ratio = steps / expected;
  const maxRatio = Math.max(2.1, ratio * 1.12);
  const left = 45;
  const top = 12;
  const width = 645;
  const height = 170;
  const x = (at: number) => left + (Math.min(at, maxRatio) / maxRatio) * width;
  const y = (chance: number) => top + (1 - chance) * height;
  const oddsAt = (at: number) => collisionOdds(at * expected, expected) ?? 0;
  const points = Array.from({ length: 101 }, (_, index) => {
    const at = (index / 100) * maxRatio;
    return `${index === 0 ? "M" : "L"}${x(at).toFixed(1)},${y(oddsAt(at)).toFixed(1)}`;
  }).join(" ");
  const median = workForOdds(0.5, expected)! / expected;
  const ninety = workForOdds(0.9, expected)! / expected;

  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <p className="text-[12px] font-medium text-ink">Chance of a collision by paid-trail work</p>
        <span className="text-[11px] text-ink-3">50% near 0.94× · 90% near 1.71× expected cost</span>
      </div>
      <svg
        viewBox="0 0 720 216"
        preserveAspectRatio="none"
        className="h-44 w-full md:h-52"
        role="img"
        aria-label={`Estimated collision chance ${formatPercent(collisionOdds(steps, expected))} after ${steps > 0 ? formatLog2(steps) : "0"} operations in paid witness trails`}
      >
        {[0, 0.5, 0.9].map((chance) => (
          <g key={chance}>
            <line x1={left} y1={y(chance)} x2={left + width} y2={y(chance)} className="stroke-edge-strong" strokeWidth="1" />
            <text x="39" y={y(chance) + 4} textAnchor="end" className="fill-ink-3 text-[11px]">{Math.round(chance * 100)}%</text>
          </g>
        ))}
        {[median, ninety].map((at, index) => (
          <line key={index} x1={x(at)} y1={top} x2={x(at)} y2={top + height} className="stroke-edge-strong" strokeWidth="1" strokeDasharray="3 4" />
        ))}
        <path d={points} fill="none" stroke="currentColor" strokeWidth="3" className="text-accent" vectorEffect="non-scaling-stroke" />
        <line x1={x(ratio)} y1={y(oddsAt(ratio))} x2={x(ratio)} y2={top + height} className="stroke-accent" strokeWidth="1.5" strokeDasharray="3 3" />
        <circle cx={x(ratio)} cy={y(oddsAt(ratio))} r="5" className="fill-accent stroke-surface" strokeWidth="2" />
        <text x={left} y="207" className="fill-ink-3 text-[11px]">0</text>
        <text x={x(1)} y="207" textAnchor="middle" className="fill-ink-3 text-[11px]">1× expected</text>
        <text x={left + width} y="207" textAnchor="end" className="fill-ink-3 text-[11px]">{maxRatio.toFixed(1)}×</text>
      </svg>
      <div className="mt-1 flex flex-wrap gap-x-5 gap-y-1 text-[11px] text-ink-3">
        <span><span className="text-accent">●</span> Counted paid-trail work now</span>
      </div>
    </div>
  );
}

/** The node supplies hourly settlements, so the line starts at the lifetime
 * total minus this visible window rather than inventing older snapshots. */
function CumulativeChart({
  hours, total, unitWord,
}: {
  hours: { hour: string; units_paid: number }[];
  total: number;
  unitWord: string;
}) {
  const windowTotal = hours.reduce((sum, hour) => sum + hour.units_paid, 0);
  const before = total - windowTotal;
  let added = 0;
  const points = [`0,30`, ...hours.map((hour, index) => {
    added += hour.units_paid;
    const x = ((index + 1) / hours.length) * 100;
    const y = 30 - (added / Math.max(1, windowTotal)) * 28;
    return `${x.toFixed(2)},${y.toFixed(2)}`;
  })].join(" ");
  return (
    <div className="flex flex-col gap-2">
      {before < 0 ? (
        <p className="text-[12.5px] text-ink-2">The hourly settlements exceed the lifetime total; this chart needs a fresh node read.</p>
      ) : (
        <>
          <svg viewBox="0 0 100 32" preserveAspectRatio="none" className="h-24 w-full" role="img"
            aria-label={`${amount(before)} verified ${unitWord}s before this window; ${amount(total)} now`}>
            <line x1="0" y1="30" x2="100" y2="30" className="stroke-edge-strong" strokeWidth="0.5" />
            <polyline points={points} fill="none" className="stroke-accent" strokeWidth="1.2" vectorEffect="non-scaling-stroke" />
          </svg>
          <div className="flex justify-between text-[11px] text-ink-3">
            <span>{amount(before)} at start</span>
            <span>{amount(total)} now</span>
          </div>
          <p className="text-[11px] text-ink-3">
            {windowTotal === 0 ? "No verified units were paid in this window." : `${amount(windowTotal)} ${unitWord}s paid in this window.`}
          </p>
        </>
      )}
    </div>
  );
}

function WorkerLine({ row }: { row: WorkerRow }) {
  const paid = row.derived?.units_paid ?? 0;
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
          {row.status === "settled" ? "not reporting" : row.status}
        </Badge>
      </td>
      <td className="mono px-3 py-2.5 text-right text-ink">{amount(paid)}</td>
      <td className="mono px-3 py-2.5 text-right text-ink-2">{formatRate(rate)}</td>
      <td className="mono px-3 py-2.5 text-ink-3" title={row.reported?.received_at}>
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
            className="absolute top-0 h-full rounded-sm bg-ink-3/55"
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
