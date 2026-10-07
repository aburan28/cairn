"use client";

import Link from "next/link";
import { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  type Goal,
  type GoalsResponse,
  type Underserved,
  angleLabel,
  describeMatch,
  describeUnderserved,
  fetchGoals,
  findGoals,
} from "@/lib/goals";
import { NODE_URL, RouteMissing } from "@/lib/network";
import { resolveNode } from "@/lib/site";
import { Badge, Box, EmptyState, Hash, NodePicker, Note, PageHeader, Skeleton, Stat } from "@/components/ui";

/**
 * Goals: what the network is trying to beat, and from which angles.
 *
 * Every objective carries a `goal` handle; this page is the node's grouping
 * of them -- `GET /goals` -- one row per problem, the angles taken on it,
 * and the objectives under each. The search box is the deduplication: type
 * what you are about to fund, and the node says whether somebody already
 * funds it, under which handle, from which angles, so the next objective is
 * posted as an angle on the same goal rather than a second spelling of it.
 */
export default function Page() {
  return (
    <Suspense fallback={<Header picker={null} />}>
      <Goals />
    </Suspense>
  );
}

function Header({ picker }: { picker: React.ReactNode }) {
  return (
    <PageHeader
      title="Goals"
      subtitle="What this network is trying to beat, and from which angles. Read off the goal handle every objective carries; two spellings of one problem are joined and said so."
      actions={picker}
    />
  );
}

function Goals() {
  const params = useSearchParams();
  const [base, setBase] = useState(NODE_URL);
  const [data, setData] = useState<GoalsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState(params.get("q") ?? "");
  const [matches, setMatches] = useState<Goal[] | null>(null);
  const [searching, setSearching] = useState(false);
  const [loading, setLoading] = useState(false);
  const focus = params.get("key");
  const angleFocus = params.get("angle");

  const load = useCallback(async (url: string) => {
    setError(null);
    setLoading(true);
    try {
      setData(await fetchGoals(url));
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : String(failure));
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

  // The search is the node's, not the page's: the alias catalog lives there.
  useEffect(() => {
    const needle = query.trim();
    if (needle.length < 3) {
      setMatches(null);
      return;
    }
    let cancelled = false;
    setSearching(true);
    const timer = setTimeout(() => {
      findGoals(needle, base)
        .then((found) => {
          if (!cancelled) setMatches(found.matches);
        })
        .catch(() => {
          if (!cancelled) setMatches([]);
        })
        .finally(() => {
          if (!cancelled) setSearching(false);
        });
    }, 250);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [query, base]);

  const picker = (
    <NodePicker
      value={base}
      onChange={(url) => {
        setBase(url);
        void load(url);
      }}
      onRead={() => void load(base === window.location.origin ? "" : base)}
      loading={loading}
    />
  );

  const shown = useMemo(() => {
    const goals = data?.goals ?? [];
    const keyed = focus ? goals.filter((g) => g.key === focus) : goals;
    if (angleFocus === null) return keyed;
    return keyed.map((g) => ({ ...g, angles: g.angles.filter((a) => a.path === angleFocus) }));
  }, [data, focus, angleFocus]);

  if (error && !data) {
    return (
      <>
        <Header picker={picker} />
        <Note title="Could not read this node" tone="bad">
          {error}
          {error.includes("newer than the node") && (
            <>
              {" "}
              Until then, objectives are listed by goal on{" "}
              <Link href="/objectives" className="text-accent">
                the objectives page
              </Link>
              .
            </>
          )}
        </Note>
      </>
    );
  }

  if (!data) {
    return (
      <div className="flex flex-col gap-3">
        <Header picker={picker} />
        <div className="mt-3 grid grid-cols-2 gap-3 md:grid-cols-4">
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
        </div>
      </div>
    );
  }

  const totals = data.goals.reduce(
    (sum, g) => ({
      objectives: sum.objectives + g.objectives,
      open: sum.open + g.open,
      workers: sum.workers + g.live_workers,
      angles: sum.angles + g.angles.filter((a) => a.path !== "").length,
    }),
    { objectives: 0, open: 0, workers: 0, angles: 0 },
  );

  return (
    <>
      <Header picker={picker} />

      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Goals" value={String(data.total)} from="distinct problems the objectives name" />
        <Stat label="Angles named" value={String(totals.angles)} from="approaches declared as GOAL-key/angle" />
        <Stat label="Objectives" value={`${totals.open} open / ${totals.objectives}`} from="under every goal" />
        <Stat
          label="Live workers"
          value={String(totals.workers)}
          from="heartbeating in the last three minutes, reported"
          tone="warn"
        />
      </div>

      {/* -- before you post: is it already here? ---------------------------- */}
      <Box
        title="Before you post"
        aside={<span className="text-[11px] font-normal text-accent">asked of this node&rsquo;s alias catalog</span>}
      >
        <p className="mb-2 text-[13px] text-ink-2">
          Say what you want solved. If somebody already funds it, post yours as an angle on the same goal
          — <span className="mono">GOAL-&lt;key&gt;/&lt;angle&gt;</span> — instead of a second spelling of it.
        </p>
        <input
          className="field w-full"
          placeholder="e.g. solve ECC2K-130 with index calculus"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          aria-label="What you want solved"
        />
        {query.trim().length >= 3 && (
          <div className="mt-3 flex flex-col gap-2">
            {searching && matches === null && <span className="text-[12px] text-ink-3">asking the node…</span>}
            {matches !== null && matches.length === 0 && (
              <span className="text-[13px] text-ink-2">
                No goal here or in the catalog matches. A new problem: name it{" "}
                <span className="mono">GOAL-&lt;a-short-key&gt;</span> and it becomes a goal others can take angles on.
              </span>
            )}
            {(matches ?? []).map((goal) => (
              <div key={goal.key} className="flex flex-wrap items-baseline gap-2 text-[13px]">
                <Badge tone={goal.objectives > 0 ? "accent" : "neutral"}>{goal.name}</Badge>
                <span className="text-ink-2">{describeMatch(goal)}</span>
                {goal.objectives > 0 && (
                  <Link href={`/goals?key=${encodeURIComponent(goal.key)}`} className="text-accent">
                    see its angles
                  </Link>
                )}
              </div>
            ))}
          </div>
        )}
      </Box>

      {/* -- where compute is scarce ------------------------------------------ */}
      {!focus && (data.underserved?.length ?? 0) > 0 && (
        <div className="mt-5">
          <Scarce rows={data.underserved ?? []} />
        </div>
      )}

      {/* -- the goals ------------------------------------------------------- */}
      <div className="mt-5 flex flex-col gap-4">
        {(focus || angleFocus !== null) && (
          <div className="text-[13px] text-ink-2">
            {angleFocus !== null ? (
              <>
                Showing one approach.{" "}
                <Link href={focus ? `/goals?key=${encodeURIComponent(focus)}` : "/goals"} className="text-accent">
                  Show every approach
                </Link>
                .
              </>
            ) : (
              <>
                Showing one goal.{" "}
                <Link href="/goals" className="text-accent">
                  Show every goal
                </Link>
                .
              </>
            )}
          </div>
        )}
        {shown.length === 0 && (
          <EmptyState title={focus ? "No such goal on this node" : "No objectives yet"}>
            {focus
              ? "Nothing funded here names that goal. The catalog may still know it; the search above says."
              : "A goal appears when an objective names it. Post one from the Submit page, or ask an agent to."}
          </EmptyState>
        )}
        {shown.map((goal) => (
          <GoalCard key={goal.key} goal={goal} />
        ))}
      </div>

      <p className="mt-6 text-[12px] text-ink-3">{data.note}</p>
    </>
  );
}

/**
 * The angles with the most open reward per live worker: where one more
 * worker would matter most. Heartbeats are self-reported, so a busy-looking
 * angle may not be; the worst that does is send fewer workers there.
 */
function Scarce({ rows }: { rows: Underserved[] }) {
  return (
    <Box
      title="Where compute is scarce"
      aside={<span className="text-[11px] font-normal text-ink-3">open reward ÷ (live workers + 1)</span>}
    >
      <ol className="flex flex-col gap-2">
        {rows.map((row) => (
          <li key={row.handle} className="flex flex-wrap items-baseline gap-2 text-[13px]">
            <span className="mono text-[12px] text-accent">
              {row.reward_per_worker.toLocaleString("en-US")} units each
            </span>
            <Link href={`/goals?key=${encodeURIComponent(row.goal)}`} className="text-ink">
              {row.goal_name}
            </Link>
            <Link
              href={`/goals?key=${encodeURIComponent(row.goal)}&angle=${encodeURIComponent(row.angle)}`}
              className="mono text-[12px] text-accent hover:underline"
            >
              {angleLabel(row.angle, row.goal)}
            </Link>
            <span className="text-ink-3">{describeUnderserved(row)}</span>
            {row.objectives[0] && (
              <Link
                href={`/challenge?id=${encodeURIComponent(row.objectives[0])}`}
                className="text-[12px] text-accent"
              >
                richest open objective
              </Link>
            )}
          </li>
        ))}
      </ol>
      <p className="mt-2 text-[12px] text-ink-3">
        Workers are heartbeats this node holds, reported and unverified; rewards are what the log has funded and not
        yet paid.
      </p>
    </Box>
  );
}

function GoalCard({ goal }: { goal: Goal }) {
  return (
    <Box
      title={goal.name}
      aside={
        <span className="mono text-[11px] font-normal text-ink-3">
          {goal.handle}
          {goal.handles.length > 1 && ` · also ${goal.handles.slice(1).join(", ")}`}
        </span>
      }
    >
      <div className="mb-3 flex flex-wrap items-baseline gap-2 text-[13px] text-ink-2">
        {goal.known ? (
          <Badge tone="accent" title={`in the catalog, family ${goal.family ?? "?"}`}>
            known
          </Badge>
        ) : (
          <Badge tone="neutral" title="named only by the objectives that carry it">
            from the log
          </Badge>
        )}
        <span>
          {goal.objectives} objective{goal.objectives === 1 ? "" : "s"}, {goal.open} open, {goal.settled} settled
        </span>
        {goal.live_workers > 0 && (
          <span className="text-warn">
            {goal.live_workers} live worker{goal.live_workers === 1 ? "" : "s"}
          </span>
        )}
        {goal.summary && <span className="basis-full text-ink-2">{goal.summary}</span>}
      </div>
      <div className="flex flex-col gap-3">
        {goal.angles.map((angle, position) => (
          <div key={angle.path || "(none)"} className="rounded-md border border-line p-3">
            <div className="mb-2 flex flex-wrap items-baseline gap-2">
              <Link
                href={`/goals?key=${encodeURIComponent(goal.key)}&angle=${encodeURIComponent(angle.path)}`}
                className="mono text-[13px] text-accent hover:underline"
                title={angle.path === "" ? "Objectives that named no approach — click to see them on their own" : "Click to see this approach on its own"}
              >
                {angleLabel(angle.path, goal.key, position + 1)}
              </Link>
              {angle.parent !== null && (
                <span className="text-[12px] text-ink-3">
                  refines <span className="mono">{angle.parent}</span>
                </span>
              )}
              <span className="text-[12px] text-ink-3">
                {angle.open} open · {angle.settled} settled
                {angle.live_workers > 0 ? ` · ${angle.live_workers} live` : ""}
              </span>
            </div>
            <ul className="flex flex-col gap-1.5">
              {angle.objectives.map((entry) => (
                <li key={entry.id} className="flex flex-wrap items-baseline gap-2 text-[13px]">
                  <Hash value={entry.id} href={`/challenge?id=${encodeURIComponent(entry.id)}`} chars={12} />
                  <Badge tone={entry.settled ? "neutral" : "accent"}>{entry.settled ? "settled" : "open"}</Badge>
                  <span className="mono text-[12px] text-ink-3">{entry.verifier_kind}</span>
                  <span className="text-ink-2">{entry.statement_excerpt}</span>
                  <span className="mono text-[12px] text-ink-3">{entry.reward.toLocaleString()} units</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </Box>
  );
}
