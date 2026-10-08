"use client";

import Link from "next/link";
import { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  type Angle,
  type Goal,
  type GoalsResponse,
  type Underserved,
  angleLabel,
  describeAngle,
  describeMatch,
  describeUnderserved,
  fetchGoals,
  findGoals,
} from "@/lib/goals";
import { useNode } from "@/components/hooks";
import { Badge, Box, EmptyState, Hash, Note, PageHeader, Skeleton, Stat } from "@/components/ui";

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
      crumb={{ href: "/objectives", label: "Objectives" }}
      title="Goals"
      subtitle="The problems this network is working on, and each approach taken to them. Open an approach to see what it is about and what is funded under it."
      actions={picker}
    />
  );
}

function Goals() {
  const params = useSearchParams();
  const node = useNode();
  const base = node ?? "";
  const [data, setData] = useState<GoalsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState(params.get("q") ?? "");
  const [matches, setMatches] = useState<Goal[] | null>(null);
  const [searching, setSearching] = useState(false);
  const [loading, setLoading] = useState(false);
  const focus = params.get("key");

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
    if (node !== null) void load(node);
  }, [load, node]);

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
    <Link href="/submit" className="btn btn-sm btn-primary">
      {loading ? "Reading…" : "Post a challenge"}
    </Link>
  );

  const shown = useMemo(() => {
    const goals = data?.goals ?? [];
    if (!focus) return goals;
    return goals.filter((g) => g.key === focus);
  }, [data, focus]);

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
        <Stat label="Approaches named" value={String(totals.angles)} from="declared as GOAL-key/approach" />
        <Stat label="Objectives" value={`${totals.open} open / ${totals.objectives}`} from="under every goal" />
        <Stat
          label="Machines working"
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
          <Scarce rows={data.underserved ?? []} goals={data.goals} />
        </div>
      )}

      {/* -- the goals ------------------------------------------------------- */}
      <div className="mt-5 flex flex-col gap-4">
        {focus && (
          <div className="text-[13px] text-ink-2">
            Showing one goal.{" "}
            <Link href="/goals" className="text-accent">
              Show every goal
            </Link>
            .
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
function Scarce({ rows, goals }: { rows: Underserved[]; goals: Goal[] }) {
  // The label an angle has on its goal's card, so the two places agree.
  const label = (row: Underserved) => {
    const angles = goals.find((g) => g.key === row.goal)?.angles ?? [];
    const index = angles.findIndex((a) => a.path === row.angle);
    return index >= 0 ? angleLabel(angles[index], index) : angleLabel({ path: row.angle, objectives: [] }, 0);
  };
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
            <span className="mono text-[12px] text-ink-2">{label(row)}</span>
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
      <div className="flex flex-col gap-2">
        {goal.angles.map((angle, index) => (
          <AngleRow key={angle.path || "(none)"} angle={angle} index={index} />
        ))}
      </div>
    </Box>
  );
}

/**
 * One approach to a goal, folded to a line until it is opened. Opened, it says
 * what the approach is -- its method family when the name is one of the agreed
 * words, otherwise that its funders named none -- and what is funded under it,
 * with each objective's statement, so "what is this other approach even about"
 * has an answer on the page.
 */
function AngleRow({ angle, index }: { angle: Angle; index: number }) {
  const [open, setOpen] = useState(false);
  const label = angleLabel(angle, index);
  return (
    <div className="rounded-md border border-edge">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        className="flex w-full cursor-pointer flex-wrap items-baseline gap-x-2 gap-y-0.5 px-3 py-2.5 text-left hover:bg-surface-2"
      >
        <span className="text-[10px] text-ink-3" aria-hidden>
          {open ? "▾" : "▸"}
        </span>
        <span className="mono text-[13px] text-ink">{label}</span>
        {angle.parent !== null && (
          <span className="text-[12px] text-ink-3">
            refines <span className="mono">{angle.parent}</span>
          </span>
        )}
        <span className="ml-auto text-[12px] text-ink-3">
          {angle.open} open · {angle.settled} settled
          {angle.live_workers > 0 ? ` · ${angle.live_workers} working` : ""}
        </span>
      </button>
      {open && (
        <div className="border-t border-edge px-3 py-3">
          <div className="flex flex-col gap-1 text-[12.5px] leading-relaxed text-ink-2">
            {describeAngle(angle).map((line) => (
              <p key={line}>{line}</p>
            ))}
          </div>
          <ul className="mt-3 flex flex-col gap-2">
            {angle.objectives.map((entry) => (
              <li key={entry.id} className="rounded-md bg-surface-2 px-3 py-2 text-[12.5px]">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={entry.settled ? "neutral" : "accent"}>{entry.settled ? "settled" : "open"}</Badge>
                  <span className="mono text-[11.5px] text-ink-3">{entry.verifier_kind}</span>
                  <span className="mono text-[11.5px] text-ink-3">{entry.reward.toLocaleString("en-US")} units</span>
                  <span className="ml-auto">
                    <Hash value={entry.id} href={`/challenge?id=${encodeURIComponent(entry.id)}`} chars={10} />
                  </span>
                </div>
                {entry.statement_excerpt && (
                  <p className="mt-1 text-ink-2" title="The funder's words, unchecked">
                    {entry.statement_excerpt}
                  </p>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
