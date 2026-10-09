"use client";

import Link from "next/link";
import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  type ProgressResponse,
  type WorkerRow,
  NODE_URL,
  ObjectiveNotFound,
  amount,
  assignedBins,
  collisionOdds,
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
import { goalSlug } from "@/lib/title";
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

function Dashboard({
  id,
  progress,
  job,
  funder,
  reward,
  picker,
  stale,
}: {
  id: string;
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
  const eta = expected ? etaSeconds(derived.steps, expected, rate) : null;
  const unitsPerHour = derived.last_day.units_paid / 24;
  const poolSpent =
    piecework && reward > 0 ? Math.min(1, piecework.paid_total / reward) : null;
  const unitWord = job?.version === 2 ? "orbit" : "unit";
  const hours = useMemo(() => denseHours(derived.hourly, HISTORY_HOURS, new Date()), [derived.hourly]);

  const searchName = progress.goal
    ? goalSlug(progress.goal).toUpperCase()
    : job?.name.replace(/^cairn /, "") ?? short(id);

  return (
    <>
      <PageHeader
        crumb={{ href: "/objectives", label: "Objectives" }}
        title={searchName + " progress"}
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

      <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat
          label={"Verified " + unitWord + "s"}
          value={amount(derived.units_paid)}
          from={amount(derived.claims_paid) + " paid claims in the log"}
          tone="accent"
        />
        <Stat
          label="Workers reporting now"
          value={String(reported.live)}
          from="Self-reported · last 3 min"
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
        <Box title="Search progress">
          {share !== null ? (
            <div className="flex flex-col gap-3">
              <Progress value={share} label="Verified work compared with the expected search effort" />
              <p className="text-[12.5px] leading-relaxed text-ink-2">
                Based on verified work. A collision may arrive earlier or later than this estimate.
              </p>
            </div>
          ) : (
            <p className="text-[12.5px] text-ink-2">
              The expected search effort is unavailable for this objective. Verified results are still shown above.
            </p>
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
              <dt>Time at reported rate</dt>
              <dd className="mono">{eta !== null ? formatDuration(eta) : "—"}</dd>
            </dl>
            <p className="mt-3 text-[12px] text-ink-3">
              {job ? "The estimate uses this search's known parameters." : "Search parameters are unavailable."}
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
            </dl>
          </Box>
          <Box
            title="Where verified work came from"
            aside={
              derived.coverage ? (
                <span className="text-[11px] font-normal text-ink-3">
                  {amount(derived.coverage.units_touched)} of {amount(derived.coverage.units)} units touched
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
              <p className="text-[12.5px] text-ink-3">No unit coverage is available yet.</p>
            )}
          </Box>
          <Box title={"Verified " + unitWord + "s by hour · last " + HISTORY_HOURS + " hours"}>
            <HourlyBars hours={hours} />
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
