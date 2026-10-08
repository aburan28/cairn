"use client";

import { goalSlug, objectiveTitle } from "@/lib/title";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  type Objective,
  type ObjectiveDetail,
  NODE_URL,
  amount,
  fetchObjectiveDetail,
  fetchObjectives,
  overspent,
  poolFraction,
  ratchetProgress,
  short,
} from "@/lib/objectives";
import {
  Badge,
  EmptyState,
  Note,
  PageHeader,
  Progress,
  SectionHeading,
  Skeleton,
  Stat,
} from "@/components/ui";
import { resolveNode } from "@/lib/site";

/**
 * What this node will pay for, and how far each question has got.
 *
 * The companion to the chain page. That one answers "have I forked"; this one
 * answers "is there anything here worth working on", which is the question
 * somebody arriving at a node actually has.
 *
 * A client component for the same reason: which node it reads has to be
 * changeable without a redeploy, because comparing two nodes is the point.
 *
 * The search, filter and sort controls compute nothing about admissibility.
 * They reorder and hide rows the node already decided about — `open`,
 * `settled`, the frontier and the pool are all the node's fields, and a second
 * opinion computed here would be a third place for a rule to drift.
 */

type Sort = "reward" | "progress" | "goal";

export default function Page() {
  const [objectives, setObjectives] = useState<Objective[] | null>(null);
  const [details, setDetails] = useState<Record<string, ObjectiveDetail>>({});
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const [query, setQuery] = useState("");
  const [showSettled, setShowSettled] = useState(true);
  const [kind, setKind] = useState("all");
  const [sort, setSort] = useState<Sort>("reward");

  const load = useCallback(async (url: string) => {
    setLoading(true);
    setError(null);
    try {
      const list = await fetchObjectives(url);
      setObjectives(list);
      // Detail is an enhancement, so it is fetched after the list is already on
      // screen and a failure leaves the summary standing rather than blanking
      // the page.
      const fetched = await Promise.all(
        list.map(async (objective) => {
          const detail = await fetchObjectiveDetail(url, objective.id);
          return [objective.id, detail] as const;
        }),
      );
      const next: Record<string, ObjectiveDetail> = {};
      for (const [id, detail] of fetched) if (detail) next[id] = detail;
      setDetails(next);
    } catch (cause) {
      setObjectives(null);
      setDetails({});
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void resolveNode().then((url) => {
      void load(url);
    });
  }, [load]);

  const kinds = useMemo(
    () => [...new Set((objectives ?? []).map((o) => o.verifier_kind))].sort(),
    [objectives],
  );

  const shown = useMemo(() => {
    const needle = query.trim().toLowerCase();
    let rows = objectives ?? [];
    if (!showSettled) rows = rows.filter((o) => o.open);
    if (kind !== "all") rows = rows.filter((o) => o.verifier_kind === kind);
    if (needle) {
      rows = rows.filter(
        (o) =>
          o.goal.toLowerCase().includes(needle) ||
          o.statement.toLowerCase().includes(needle) ||
          o.id.includes(needle) ||
          o.funder.toLowerCase().includes(needle),
      );
    }
    const ranked = [...rows];
    ranked.sort((a, b) => {
      if (sort === "goal") return objectiveTitle(a).localeCompare(objectiveTitle(b));
      if (sort === "reward") return b.reward - a.reward;
      // "progress": how much of the pool is still payable, largest first —
      // which is the ordering somebody deciding what to work on wants.
      const left = poolFraction(a) ?? (a.settled ? 0 : 1);
      const right = poolFraction(b) ?? (b.settled ? 0 : 1);
      return right - left;
    });
    return ranked;
  }, [objectives, query, showSettled, kind, sort]);

  // Both are the node's fields. Deriving `open` as `!settled` here was how a
  // ratchet with most of its pool left ended up under "settled": the node's
  // `settled` meant "a settlement record exists", and a ratchet writes one on
  // every paying move. The node now publishes both, and the rule lives there.
  const open = shown.filter((o) => o.open);
  const settled = shown.filter((o) => o.settled);

  const pool = (objectives ?? []).reduce((sum, o) => sum + o.reward, 0);
  const remaining = (objectives ?? []).reduce(
    (sum, o) => sum + (o.frontier?.pool_remaining ?? (o.settled ? 0 : o.reward)),
    0,
  );

  const paidOut = (objectives ?? []).reduce(
    (sum, o) => sum + (o.frontier?.paid_cumulative ?? o.settlement?.reward ?? 0),
    0,
  );
  const openCount = (objectives ?? []).filter((o) => o.open).length;

  return (
    <>
      <PageHeader
        title="Objectives"
        subtitle="Every question this node knows about, and what is still payable on it. The node derived all of it from its log."
        actions={
          <>
            <Link href="/goals" className="btn btn-sm">
              Goals
            </Link>
            <Link href="/submit" className="btn btn-sm btn-primary">
              Post a challenge
            </Link>
          </>
        }
      />

      {objectives && objectives.length > 0 && (
        <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4">
          <Stat label="Objectives" value={String(objectives.length)} />
          <Stat
            label="Open"
            value={String(openCount)}
            from={openCount ? "worth working on" : "all settled"}
          />
          <Stat label="Still payable" value={amount(remaining)} from={`of ${amount(pool)} funded`} tone="accent" />
          <Stat label="Paid out" value={amount(paidOut)} tone="accent" />
        </div>
      )}

      {error && (
        <div className="mb-4">
          <Note title="could not read objectives" tone="bad">
            {error}
          </Note>
        </div>
      )}

      {objectives && objectives.length > 0 && (
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <input
            id="search"
            aria-label="Search"
            className="field max-w-sm min-w-52 flex-1 py-1.5"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search name, statement, funder or id"
          />
          <select
            id="kind"
            aria-label="Verifier"
            className="field w-auto py-1.5"
            value={kind}
            onChange={(event) => setKind(event.target.value)}
          >
            <option value="all">All verifiers</option>
            {kinds.map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </select>
          <select
            id="sort"
            aria-label="Sort"
            className="field w-auto py-1.5"
            value={sort}
            onChange={(event) => setSort(event.target.value as Sort)}
          >
            <option value="reward">Largest bounty</option>
            <option value="progress">Most left to earn</option>
            <option value="goal">Name, A–Z</option>
          </select>
          <label className="flex cursor-pointer items-center gap-2 px-1 text-[13px] text-ink-2">
            <input
              type="checkbox"
              className="accent-[var(--accent)]"
              checked={showSettled}
              onChange={(event) => setShowSettled(event.target.checked)}
            />
            Show settled
          </label>
        </div>
      )}

      {loading && !objectives && (
        <div className="box divide-edge-y">
          {[0, 1, 2, 3].map((n) => (
            <div key={n} className="flex items-center gap-4 px-4 py-3.5">
              <Skeleton className="h-4 w-48" />
              <Skeleton className="h-3 flex-1" />
              <Skeleton className="h-3 w-20" />
            </div>
          ))}
        </div>
      )}

      {objectives && objectives.length === 0 && (
        <EmptyState
          title="This node knows of no objectives."
          action={
            <Link href="/submit" className="btn btn-primary">
              Post the first one
            </Link>
          }
        >
          Fund one from this page, or with{" "}
          <code className="mono">cairn post &lt;objective.json&gt;</code>.
        </EmptyState>
      )}

      {objectives && objectives.length > 0 && shown.length === 0 && (
        <EmptyState title="Nothing matches those filters.">
          {objectives.length} objective{objectives.length === 1 ? "" : "s"} on this
          node, none of them matching.
        </EmptyState>
      )}

      {open.length > 0 && (
        <ObjectiveTable title="Open" rows={open} details={details} />
      )}

      {settled.length > 0 && (
        <ObjectiveTable title="Settled" rows={settled} details={details} />
      )}
    </>
  );
}

/**
 * One row per objective. It used to be one card per objective, each carrying
 * its statement, funder, pinned checker and two progress bars, so a node with
 * six objectives was three screens of cards. The detail is all still one click
 * away on the objective's own page; a list is for choosing which one to open.
 */
function ObjectiveTable({
  title,
  rows,
  details,
}: {
  title: string;
  rows: Objective[];
  details: Record<string, ObjectiveDetail>;
}) {
  return (
    <section className="mb-6">
      <SectionHeading count={rows.length}>{title}</SectionHeading>
      <div className="box overflow-x-auto">
        {/* Fixed layout, so Open and Settled line up column for column. The
            other five columns take 40rem, so the minimum is what leaves the
            title column room: at 46rem it got 6rem, and every name read as
            "GOAL-e…". Narrower than this, the box scrolls. */}
        <table className="w-full min-w-[58rem] table-fixed border-collapse text-left text-[13px]">
          <colgroup>
            <col />
            <col className="w-28" />
            <col className="w-28" />
            <col className="w-48" />
            <col className="w-28" />
            <col className="w-28" />
          </colgroup>
          <thead>
            <tr className="border-b border-edge text-[11.5px] text-ink-3">
              <th className="px-4 py-2 font-medium">Objective</th>
              <th className="px-3 py-2 font-medium">Verifier</th>
              <th className="px-3 py-2 text-right font-medium">Bounty</th>
              <th className="px-3 py-2 font-medium">Progress</th>
              <th className="px-3 py-2 font-medium">Held by</th>
              <th className="px-4 py-2 text-right font-medium">Posted</th>
            </tr>
          </thead>
          <tbody className="divide-edge-y">
            {rows.map((objective) => (
              <ObjectiveRow
                key={objective.id}
                objective={objective}
                detail={details[objective.id]}
              />
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function ObjectiveRow({
  objective,
  detail,
}: {
  objective: Objective;
  detail?: ObjectiveDetail;
}) {
  const href = `/challenge?id=${encodeURIComponent(objective.id)}`;
  const fraction = poolFraction(objective);
  const suspect = overspent(objective);
  const moved =
    detail?.ratchet && objective.frontier
      ? ratchetProgress(detail.ratchet, objective.frontier.score)
      : null;
  const holder = objective.frontier?.holder ?? objective.settlement?.submitter;

  return (
    <tr className="group align-top transition-colors hover:bg-surface-2">
      <td className="px-4 py-3">
        {/* The title is the statement's first sentence -- the funder's words,
            attacker-supplied text in src/mcp.rs's terms. React escapes it;
            the objective's own page carries it in full under its "not
            checked" label. The goal slug sits under it as the id it is. */}
        <Link
          href={href}
          className="line-clamp-2 font-medium text-ink [overflow-wrap:anywhere] group-hover:underline"
          title={`Funder's statement, not checked: ${objective.statement}`}
        >
          {objectiveTitle(objective)}
        </Link>
        {goalSlug(objective.goal) && (
          <p className="mono mt-0.5 text-[11.5px] text-ink-3">{goalSlug(objective.goal)}</p>
        )}
        {suspect && (
          <p className="mt-1 text-[12px] text-bad">
            Paid plus remaining exceeds what was funded. Audit this node before trusting it.
          </p>
        )}
      </td>
      <td className="px-3 py-3">
        <Badge tone="accent">{objective.verifier_kind}</Badge>
      </td>
      <td className="mono px-3 py-3 text-right text-ink">{amount(objective.reward)}</td>
      <td className="px-3 py-3">
        {objective.frontier && detail?.ratchet ? (
          <div className="flex flex-col gap-1">
            <div className="flex items-baseline justify-between text-[12px] text-ink-2">
              <span>
                <span className="mono font-semibold text-accent">{objective.frontier.score}</span>
                <span className="text-ink-3"> of {detail.ratchet.target}</span>
              </span>
              {fraction !== null && (
                <span className="text-[11px] text-ink-3">
                  {amount(objective.frontier.pool_remaining)} left
                </span>
              )}
            </div>
            {moved !== null && <Progress value={moved} />}
          </div>
        ) : objective.settlement ? (
          <span className="text-[12px] text-ink-2">
            paid <span className="mono text-ink">{amount(objective.settlement.reward)}</span>
          </span>
        ) : objective.piecework ? (
          /* A divided search: the pool drains per novel unit, and what the
             search has got done lives on its own page. Before this branch a
             piecework objective with thousands of paid orbits read "no
             claim yet", because it has no frontier and no single settlement. */
          <div className="flex flex-col gap-1">
            <div className="flex items-baseline justify-between text-[12px] text-ink-2">
              <span>
                <span className="mono font-semibold text-accent">
                  {amount(objective.piecework.paid_total)}
                </span>
                <span className="text-ink-3"> paid per unit</span>
              </span>
              <span className="text-[11px] text-ink-3">
                {amount(objective.piecework.pool_remaining)} left
              </span>
            </div>
            <Progress
              value={
                objective.reward > 0 ? objective.piecework.paid_total / objective.reward : 0
              }
              tone="warn"
            />
            {/* Two dashboards, side by side: what the log has paid for, and
                how the search is being divided this epoch. */}
            <div className="flex flex-wrap gap-x-3 gap-y-0.5">
              <Link
                href={`/task?id=${encodeURIComponent(objective.id)}`}
                className="text-[11.5px] text-accent hover:underline"
              >
                workers and progress →
              </Link>
              <Link
                href={`/coordination?id=${encodeURIComponent(objective.id)}`}
                className="text-[11.5px] text-accent hover:underline"
              >
                who holds which slice →
              </Link>
            </div>
          </div>
        ) : (
          <span className="text-[12px] text-ink-3">no claim yet</span>
        )}
      </td>
      <td className="mono px-3 py-3 text-[12.5px] text-ink-2">{holder ?? "—"}</td>
      <td className="mono px-4 py-3 text-right text-[12px] text-ink-3" title={detail?.created_at}>
        {detail?.created_at?.slice(0, 10) ?? ""}
      </td>
    </tr>
  );
}
