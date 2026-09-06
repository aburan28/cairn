"use client";

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
  Card,
  EmptyState,
  Hash,
  Note,
  Progress,
  SectionHeading,
  Skeleton,
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
  const [base, setBase] = useState(NODE_URL);
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
    // Ask which node to read before reading it. Same-origin when one answers --
    // the daemon serves this page at /ui/, so that is the common case and it
    // costs one /health -- and otherwise the first seed from the published list
    // that is up. On the public site there is no same-origin node at all, and
    // before this the box showed github.io and every request 404'd into the
    // snapshot.
    //
    // Shown *and* used, which is the part worth being careful about: the box
    // has to name the origin the numbers below came from, or a reader comparing
    // two nodes is comparing one node against a label. Empty stays empty for
    // fetching -- relative requests survive a tunnel or a proxy on an unknown
    // path -- and becomes this page's own origin for display, because nobody
    // can retype "" after clearing the box.
    void resolveNode().then((url) => {
      setBase(url || window.location.origin);
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
      if (sort === "goal") return a.goal.localeCompare(b.goal);
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

  return (
    <>
      <header className="mb-6 max-w-[62rem]">
        <h1 className="text-[26px] font-semibold">Objectives</h1>
        <p className="prose-block mt-2">
          Every question this node has been told about, and what remains payable on
          it. A <code className="mono">certificate</code> objective settles once; an{" "}
          <code className="mono">evaluator</code> objective ratchets, paying each
          improvement in proportion to the distance it moved the frontier. Nothing
          here is this page&rsquo;s opinion — the node derived it from its log, and{" "}
          <code className="mono">cairn audit</code> re-derives it from nothing.
        </p>
      </header>

      <Card className="card-pad mb-4">
        <label className="label" htmlFor="node">
          Node
        </label>
        <div className="flex flex-wrap gap-2">
          <input
            id="node"
            className="field field-mono flex-1"
            value={base}
            onChange={(event) => setBase(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") void load(base);
            }}
            spellCheck={false}
          />
          <button className="btn" onClick={() => void load(base)} disabled={loading}>
            {loading ? "reading…" : "Read"}
          </button>
        </div>
        <p className="hint">
          Retarget without a redeploy — comparing one node&rsquo;s answer against a
          peer&rsquo;s is the whole value of the box.
        </p>
      </Card>

      {error && (
        <div className="mb-4">
          <Note title="could not read objectives" tone="bad">
            {error}
          </Note>
        </div>
      )}

      {objectives && objectives.length > 0 && (
        <div className="mb-4 flex flex-wrap items-end gap-3">
          <div className="min-w-52 flex-1">
            <label className="label" htmlFor="search">
              Search
            </label>
            <input
              id="search"
              className="field"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="goal, statement, funder or id"
            />
          </div>
          <div>
            <label className="label" htmlFor="kind">
              Verifier
            </label>
            <select
              id="kind"
              className="field"
              value={kind}
              onChange={(event) => setKind(event.target.value)}
            >
              <option value="all">all kinds</option>
              {kinds.map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="label" htmlFor="sort">
              Sort
            </label>
            <select
              id="sort"
              className="field"
              value={sort}
              onChange={(event) => setSort(event.target.value as Sort)}
            >
              <option value="reward">largest bounty</option>
              <option value="progress">most left to earn</option>
              <option value="goal">goal, A–Z</option>
            </select>
          </div>
          <label className="flex cursor-pointer items-center gap-2 pb-2 text-[13px]">
            <input
              type="checkbox"
              className="accent-[var(--accent)]"
              checked={showSettled}
              onChange={(event) => setShowSettled(event.target.checked)}
            />
            show settled
          </label>
          <div className="ml-auto pb-2 text-[12.5px] text-ink-2">
            <span className="mono text-ink">{amount(remaining)}</span> still payable of{" "}
            <span className="mono">{amount(pool)}</span>
          </div>
        </div>
      )}

      {loading && !objectives && (
        <div className="grid gap-3 md:grid-cols-2">
          {[0, 1, 2, 3].map((n) => (
            <Card key={n} className="card-pad flex flex-col gap-3">
              <Skeleton className="h-4 w-40" />
              <Skeleton className="h-3 w-full" />
              <Skeleton className="h-3 w-3/4" />
              <Skeleton className="h-1.5 w-full" />
            </Card>
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
        <section className="mb-8">
          <SectionHeading count={open.length}>Open</SectionHeading>
          <ul className="grid gap-3 md:grid-cols-2">
            {open.map((objective) => (
              <ObjectiveCard
                key={objective.id}
                objective={objective}
                detail={details[objective.id]}
              />
            ))}
          </ul>
        </section>
      )}

      {settled.length > 0 && (
        <section>
          <SectionHeading count={settled.length}>Settled</SectionHeading>
          <ul className="grid gap-3 md:grid-cols-2">
            {settled.map((objective) => (
              <ObjectiveCard
                key={objective.id}
                objective={objective}
                detail={details[objective.id]}
              />
            ))}
          </ul>
        </section>
      )}
    </>
  );
}

function ObjectiveCard({
  objective,
  detail,
}: {
  objective: Objective;
  detail?: ObjectiveDetail;
}) {
  const fraction = poolFraction(objective);
  const suspect = overspent(objective);
  const moved =
    detail?.ratchet && objective.frontier
      ? ratchetProgress(detail.ratchet, objective.frontier.score)
      : null;

  return (
    <Card as="li" className="card-pad flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-[14px] font-semibold">{objective.goal}</h3>
        <Badge tone={objective.settled ? "neutral" : "accent"}>
          {objective.settled ? "settled" : "open"}
        </Badge>
        <Badge tone="info">{objective.verifier_kind}</Badge>
        <span className="ml-auto">
          <Hash value={objective.id} chars={8} label="id" />
        </span>
      </div>

      {/* The statement is objective-authored text — attacker-supplied, in the
          terms src/mcp.rs uses. React escapes it, and it is kept in its own
          block, visually quoted and explicitly labelled, so that no sentence
          inside it can read as a field this page rendered. */}
      <div>
        <div className="mb-1 text-[11px] tracking-wide text-ink-3 uppercase">
          statement — written by the funder, not checked
        </div>
        <blockquote className="border-l-2 border-edge pl-3 text-[13px] leading-relaxed text-ink-2">
          {objective.statement}
        </blockquote>
      </div>

      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-[12.5px] sm:grid-cols-3">
        <div>
          <dt className="text-[11px] text-ink-3">funder</dt>
          <dd className="mt-0.5">
            <Hash value={objective.funder} chars={8} />
          </dd>
        </div>
        <div>
          <dt className="text-[11px] text-ink-3">funded</dt>
          <dd className="mono mt-0.5 text-ink">{amount(objective.reward)}</dd>
        </div>
        {detail?.created_at && (
          <div>
            <dt className="text-[11px] text-ink-3">posted</dt>
            <dd className="mono mt-0.5" title={detail.created_at}>
              {detail.created_at.slice(0, 10)}
            </dd>
          </div>
        )}
      </dl>

      {/* The pinned checker, by hash. This is the whole reason an objective can
          be worked on before anyone trusts anybody: the code that decides
          payment is fixed at posting time and its hash is inside the
          objective's id, so swapping it means posting a different objective. */}
      {detail?.verifier && (
        <div className="flex flex-wrap items-center gap-1.5 rounded-lg bg-surface-2 px-2.5 py-1.5 text-[12px] text-ink-2">
          <span className="text-ink-3">pins</span>
          <span className="mono">
            {detail.verifier.checker ?? detail.verifier.evaluator ?? "?"}
          </span>
          {(detail.verifier.checker_sha256 ?? detail.verifier.evaluator_sha256) && (
            <>
              <span className="text-ink-3">@</span>
              <Hash
                value={
                  detail.verifier.checker_sha256 ?? detail.verifier.evaluator_sha256 ?? ""
                }
                chars={8}
              />
            </>
          )}
        </div>
      )}

      {objective.frontier ? (
        <div className="flex flex-col gap-3">
          {/* Baseline → current → target, because a bare score is unreadable
              without knowing which direction counts as better. `minimize`
              objectives count *down*, so a bar keyed to raw score would show a
              submitter improving things as though they were losing ground. */}
          {detail?.ratchet && (
            <div className="flex flex-col gap-1.5">
              <div className="flex flex-wrap items-baseline gap-1.5 text-[12.5px]">
                <Badge>{detail.ratchet.direction}</Badge>
                <span className="mono text-ink-3">{detail.ratchet.baseline}</span>
                <span className="text-ink-3">baseline →</span>
                <span className="mono font-semibold text-accent">
                  {objective.frontier.score}
                </span>
                <span className="text-ink-3">now →</span>
                <span className="mono text-ink-3">{detail.ratchet.target}</span>
                <span className="text-ink-3">target</span>
              </div>
              {moved !== null && <Progress value={moved} label="baseline to target" />}
              <p className="text-[11.5px] text-ink-3">
                an improvement must move the score by at least{" "}
                <span className="mono">{detail.ratchet.min_improvement}</span>
              </p>
            </div>
          )}

          {fraction !== null && (
            <Progress
              value={fraction}
              label={`${amount(objective.frontier.pool_remaining)} of ${amount(
                objective.reward,
              )} pool remaining`}
            />
          )}

          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[12.5px] text-ink-2">
            <Link
              href={`/frontier?id=${encodeURIComponent(objective.id)}`}
              className="text-accent hover:underline"
            >
              frontier <span className="mono">{objective.frontier.score}</span>
            </Link>
            <span className="flex items-center gap-1">
              held by <Hash value={objective.frontier.holder} chars={6} />
            </span>
            <span className="mono">{amount(objective.frontier.paid_cumulative)} paid</span>
          </div>

          <div className="flex flex-wrap items-center gap-1 text-[12px] text-ink-2">
            an improvement must cite{" "}
            <Hash value={objective.frontier.must_cite} chars={8} />
          </div>

          {/* The one claim this page makes on its own behalf, matching
              firstBrokenLink on the chain page: paid + remaining cannot exceed
              what was funded, and if it does the node published something its
              own arithmetic does not support. */}
          {suspect && (
            <Note title="this pool does not add up" tone="bad">
              {amount(objective.frontier.paid_cumulative)} paid plus{" "}
              {amount(objective.frontier.pool_remaining)} remaining exceeds the{" "}
              {amount(objective.reward)} funded. Audit this node before trusting any
              figure on this card.
            </Note>
          )}
        </div>
      ) : objective.settlement ? (
        /* A settled certificate: one claim, one payment, and nothing left to
           cite. Without this branch the card wore a "settled" tag directly
           above "no claim yet", which is two facts contradicting each other. */
        <div className="flex flex-wrap items-center gap-1.5 text-[12.5px] text-ink-2">
          settled — <span className="mono font-semibold text-ink">
            {amount(objective.settlement.reward)}
          </span>{" "}
          paid to <Hash value={objective.settlement.submitter} chars={8} /> for claim{" "}
          <Hash value={objective.settlement.claim_id} chars={8} />
        </div>
      ) : (
        <p className="text-[12.5px] text-ink-3">
          no claim yet — the frontier starts at the objective&rsquo;s baseline
        </p>
      )}
    </Card>
  );
}
