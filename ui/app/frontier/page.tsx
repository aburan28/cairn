"use client";

import Link from "next/link";
import { Suspense, useCallback, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  type FrontierMove,
  type ObjectiveResponse,
  NODE_URL,
  ObjectiveNotFound,
  amount,
  fetchMoves,
  fetchObjective,
  overspent,
  ratchetProgress,
  short,
} from "@/lib/frontier";
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

/**
 * One objective's frontier: the best verified result, and every result it
 * displaced.
 *
 * The id arrives as `?id=`, matching `/challenge` — this is a static export
 * embedded in the node binary, so a dynamic path segment would need every id
 * known at build time. See `app/challenge/page.tsx` for the longer version of
 * that note.
 */
export default function Page() {
  return (
    <Suspense
      fallback={
        <div className="flex flex-col gap-3">
          <Skeleton className="h-6 w-40" />
          <Skeleton className="h-4 w-full max-w-lg" />
        </div>
      }
    >
      <FrontierPage />
    </Suspense>
  );
}

function FrontierPage() {
  const params = useSearchParams();
  const id = params.get("id") ?? "";

  const [base, setBase] = useState(NODE_URL);
  const [objective, setObjective] = useState<ObjectiveResponse | null>(null);
  const [moves, setMoves] = useState<FrontierMove[] | null>(null);
  const [problems, setProblems] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [loading, setLoading] = useState(false);

  const load = useCallback(
    async (url: string) => {
      if (!id) return;
      setLoading(true);
      setError(null);
      setNotFound(false);
      try {
        const [obj, history] = await Promise.all([fetchObjective(id, url), fetchMoves(id, url)]);
        setObjective(obj);
        setMoves(history.moves);
        setProblems(history.problems);
      } catch (cause) {
        setObjective(null);
        setMoves(null);
        setProblems([]);
        if (cause instanceof ObjectiveNotFound) {
          setNotFound(true);
        } else {
          setError(cause instanceof Error ? cause.message : String(cause));
        }
      } finally {
        setLoading(false);
      }
    },
    [id],
  );

  useEffect(() => {
    setBase(NODE_URL || window.location.origin);
    void load(NODE_URL);
  }, [load]);

  if (!id) {
    return (
      <>
        <h1 className="text-[26px] font-semibold">Frontier</h1>
        <p className="prose-block mt-2">
          No objective id given. Follow a &ldquo;frontier&rdquo; link from{" "}
          <Link href="/objectives">objectives</Link> rather than opening this page
          directly.
        </p>
      </>
    );
  }

  return (
    <>
      <header className="mb-6 max-w-[62rem]">
        <h1 className="text-[26px] font-semibold">Frontier</h1>
        <p className="prose-block mt-2">
          The best verified result on one objective, and every result it displaced. The
          node writes a frontier record when a claim beats the one before it, and each
          move names the claim it beat — so this is the cairn itself, the pile of
          stones, in order. Every number here is re-derivable with{" "}
          <code className="mono">cairn audit</code>.
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
      </Card>

      <div className="flex flex-col gap-4">
        {notFound && (
          <Note title="no such objective" tone="bad">
            This node knows no objective <code className="mono">{short(id)}</code>.
          </Note>
        )}

        {error && (
          <Note title="could not read this objective" tone="bad">
            {error}
          </Note>
        )}

        {problems.length > 0 && (
          <Note
            title={`${problems.length} line${problems.length === 1 ? "" : "s"} of the log could not be read as a record`}
            tone="bad"
          >
            The moves below were built from the lines that could; a move recorded on one
            of these would be missing. <code className="mono">cairn audit</code> reads
            the same file; run it to see what it makes of them.
            <ul className="mt-1.5 flex flex-col gap-0.5">
              {problems.map((problem) => (
                <li key={problem} className="mono text-[11.5px] text-ink-3">
                  {problem}
                </li>
              ))}
            </ul>
          </Note>
        )}

        {objective && <Detail objective={objective} moves={moves ?? []} />}
      </div>
    </>
  );
}

function Detail({
  objective,
  moves,
}: {
  objective: ObjectiveResponse;
  moves: FrontierMove[];
}) {
  const { record, frontier } = objective;
  const suspect = frontier ? overspent(frontier, record.reward) : false;
  const moved = record.ratchet && frontier ? ratchetProgress(record.ratchet, frontier.score) : null;

  return (
    <>
      <Card className="card-pad flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-[15px] font-semibold">{record.goal}</h2>
          <Badge tone="info">{record.verifier?.kind ?? "?"}</Badge>
        </div>

        <div>
          <div className="mb-1 text-[11px] tracking-wide text-ink-3 uppercase">
            statement — written by the funder, not checked
          </div>
          <blockquote className="border-l-2 border-edge pl-3 text-[13px] leading-relaxed text-ink-2">
            {record.statement}
          </blockquote>
        </div>

        <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-[12.5px] sm:grid-cols-4">
          <div>
            <dt className="text-[11px] text-ink-3">objective</dt>
            <dd className="mt-0.5">
              <Hash value={objective.id} chars={8} />
            </dd>
          </div>
          <div>
            <dt className="text-[11px] text-ink-3">funder</dt>
            <dd className="mt-0.5">
              <Hash value={record.funder} chars={8} />
            </dd>
          </div>
          <div>
            <dt className="text-[11px] text-ink-3">funded</dt>
            <dd className="mono mt-0.5 text-ink">{amount(record.reward)}</dd>
          </div>
          {record.created_at && (
            <div>
              <dt className="text-[11px] text-ink-3">posted</dt>
              <dd className="mono mt-0.5" title={record.created_at}>
                {record.created_at.slice(0, 10)}
              </dd>
            </div>
          )}
        </dl>

        {record.ratchet && frontier && (
          <div className="flex flex-col gap-1.5">
            <div className="flex flex-wrap items-baseline gap-1.5 text-[12.5px]">
              <Badge>{record.ratchet.direction}</Badge>
              <span className="mono text-ink-3">{record.ratchet.baseline}</span>
              <span className="text-ink-3">baseline →</span>
              <span className="mono font-semibold text-accent">{frontier.score}</span>
              <span className="text-ink-3">now →</span>
              <span className="mono text-ink-3">{record.ratchet.target}</span>
              <span className="text-ink-3">target</span>
            </div>
            {moved !== null && <Progress value={moved} label="baseline to target" />}
            <p className="text-[11.5px] text-ink-3">
              an improvement must move the score by at least{" "}
              <span className="mono">{record.ratchet.min_improvement}</span>
            </p>
          </div>
        )}
      </Card>

      {suspect && frontier && (
        <Note title="this pool does not add up" tone="bad">
          {amount(frontier.paid_cumulative)} paid plus {amount(frontier.pool_remaining)}{" "}
          remaining exceeds the {amount(record.reward)} funded. Audit this node before
          trusting any figure on this page.
        </Note>
      )}

      {!frontier && objective.settlement && (
        /* A certificate writes no frontier record, so its one settlement is the
           whole move history. Saying "no claim yet" about it was false. */
        <Note
          title={`settled — ${amount(objective.settlement.reward)} paid to ${objective.settlement.submitter}`}
        >
          <span className="flex flex-wrap items-center gap-1">
            for claim <Hash value={objective.settlement.claim_id} chars={8} />
          </span>
          A certificate settles once and moves no frontier, so there are no moves to
          list.
        </Note>
      )}

      {!frontier && !objective.settlement && (
        <EmptyState title="No claim yet.">
          The frontier starts at the objective&rsquo;s baseline.
        </EmptyState>
      )}

      {frontier && (
        <section>
          <SectionHeading count={moves.length}>Moves, newest first</SectionHeading>
          <ol>
            {[...moves].reverse().map((move, index, all) => (
              <li key={move.seq} className="relative pb-5 pl-7">
                {index < all.length - 1 && (
                  <span className="absolute top-2 bottom-0 left-[5px] w-px bg-edge" aria-hidden />
                )}
                <span
                  className={`absolute top-1.5 left-0 h-2.5 w-2.5 rounded-full ring-4 ring-canvas ${
                    index === all.length - 1 ? "border-2 border-accent bg-canvas" : "bg-accent"
                  }`}
                  aria-hidden
                />
                <div className="flex flex-wrap items-center gap-2">
                  <span className="mono text-[14px] font-semibold">{move.score}</span>
                  <span className="text-[12px] text-ink-3">held by</span>
                  <Hash value={move.holder} chars={8} />
                  {index === 0 && <Badge tone="accent">current</Badge>}
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-[12px] text-ink-2">
                  <span className="flex items-center gap-1">
                    claim <Hash value={move.claimId} chars={8} />
                  </span>
                  <span>
                    paid <span className="mono font-semibold text-ink">{amount(move.paidThisMove)}</span>
                  </span>
                  {!move.consistent && (
                    <span className="text-bad">
                      · disagrees with settlement ({amount(move.settlementReward ?? 0)})
                    </span>
                  )}
                </div>
              </li>
            ))}
          </ol>
          <p className="mt-3 text-[12.5px] text-ink-2">
            <span className="mono">{moves.map((m) => amount(m.paidThisMove)).join(" + ")}</span> ={" "}
            <span className="mono text-ink">{amount(frontier.paid_cumulative)}</span> paid so far
            {record.reward > 0 && <> of {amount(record.reward)} funded</>}.
          </p>
        </section>
      )}
    </>
  );
}
