"use client";

import Link from "next/link";
import { Suspense, useCallback, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  type Frontier,
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

/**
 * One objective's frontier: the best verified result, and every result it
 * displaced.
 *
 * The id arrives as `?id=`, matching `/challenge` — this is a static export
 * embedded in the node binary, so a dynamic path segment would need every id
 * known at build time. See `app/challenge/page.tsx` for the longer version
 * of that note.
 */
export default function Page() {
  return (
    <Suspense fallback={<main><p className="empty">reading…</p></main>}>
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

  const load = useCallback(async (url: string) => {
    if (!id) return;
    setLoading(true);
    setError(null);
    setNotFound(false);
    try {
      const [obj, history] = await Promise.all([
        fetchObjective(id, url),
        fetchMoves(id, url),
      ]);
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
  }, [id]);

  useEffect(() => {
    setBase(NODE_URL || window.location.origin);
    void load(NODE_URL);
  }, [load]);

  if (!id) {
    return (
      <main>
        <h1>frontier</h1>
        <p className="lede">
          No objective id given. Follow a &ldquo;frontier score&rdquo; link
          from <Link href="/objectives">objectives</Link> rather than opening
          this page directly.
        </p>
      </main>
    );
  }

  return (
    <main>
      <h1>frontier</h1>
      <p className="lede">
        The best verified result on one objective, and every result it
        displaced. The node writes a frontier record when a claim beats the
        one before it, and each move names the claim it beat — so this is the
        cairn itself, the pile of stones, in order. Every number here is
        re-derivable with <code>cairn audit</code>.
      </p>

      <div className="row">
        <input
          className="input"
          value={base}
          onChange={(event) => setBase(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") void load(base);
          }}
          aria-label="Node URL"
          spellCheck={false}
        />
        <button className="button" onClick={() => void load(base)} disabled={loading}>
          {loading ? "reading…" : "read"}
        </button>
      </div>

      {notFound && (
        <div className="panel bad">
          <b>no such objective</b>
          This node knows no objective <code>{short(id)}</code>.
        </div>
      )}

      {error && (
        <div className="panel bad">
          <b>could not read this objective</b>
          {error}
        </div>
      )}

      {problems.length > 0 && (
        <div className="panel bad">
          <b>
            {problems.length} line{problems.length === 1 ? "" : "s"} of the log
            could not be read as a record
          </b>
          The moves below were built from the lines that could; a move
          recorded on one of these would be missing. <code>cairn audit</code>{" "}
          reads the same file; run it to see what it makes of them.
          <ul className="claims">
            {problems.map((problem) => (
              <li key={problem}>
                <code className="dim">{problem}</code>
              </li>
            ))}
          </ul>
        </div>
      )}

      {objective && <Detail objective={objective} moves={moves ?? []} />}
    </main>
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

  return (
    <>
      <div className="card">
        <div className="card-head">
          <span className="goal">{record.goal}</span>
          <span className="tag">{record.verifier?.kind ?? "?"}</span>
        </div>
        <blockquote className="statement">
          <span className="dim">statement (untrusted):</span> {record.statement}
        </blockquote>
        <dl className="facts">
          <div>
            <dt>objective</dt>
            <dd>
              <code className="dim" title={objective.id}>
                {short(objective.id)}
              </code>
            </dd>
          </div>
          <div>
            <dt>funder</dt>
            <dd>{record.funder}</dd>
          </div>
          <div>
            <dt>funded</dt>
            <dd>{amount(record.reward)}</dd>
          </div>
          {record.created_at && (
            <div>
              <dt>posted</dt>
              <dd title={record.created_at}>{record.created_at.slice(0, 10)}</dd>
            </div>
          )}
        </dl>
        {record.ratchet && frontier && (
          <div className="ratchet">
            <div className="meta">
              <span className="dim">{record.ratchet.direction}</span>{" "}
              {record.ratchet.baseline}
              <span className="dim"> baseline </span>→{" "}
              <b className="accent">{frontier.score}</b>{" "}
              <span className="dim">now</span> → {record.ratchet.target}
              <span className="dim"> target</span>
            </div>
            {(() => {
              const moved = ratchetProgress(record.ratchet, frontier.score);
              return moved === null ? null : (
                <div
                  className="bar"
                  role="img"
                  aria-label={`${Math.round(moved * 100)}% of the way from baseline to target`}
                >
                  <span style={{ width: `${moved * 100}%` }} />
                </div>
              );
            })()}
            <div className="meta dim">
              an improvement must move the score by at least{" "}
              {record.ratchet.min_improvement}
            </div>
          </div>
        )}
      </div>

      {suspect && frontier && (
        <div className="panel bad">
          <b>this pool does not add up</b>
          {amount(frontier.paid_cumulative)} paid plus{" "}
          {amount(frontier.pool_remaining)} remaining exceeds the{" "}
          {amount(record.reward)} funded. Audit this node before trusting any
          figure on this page.
        </div>
      )}

      {!frontier && objective.settlement && (
        /* A certificate writes no frontier record, so its one settlement is
           the whole move history. Saying "no claim yet" about it was false. */
        <div className="panel">
          <b>
            settled — {amount(objective.settlement.reward)} paid to{" "}
            {objective.settlement.submitter}
          </b>
          <div className="meta">
            for claim{" "}
            <code className="dim" title={objective.settlement.claim_id}>
              {short(objective.settlement.claim_id)}
            </code>
            . A certificate settles once and moves no frontier, so there are no
            moves to list.
          </div>
        </div>
      )}

      {!frontier && !objective.settlement && (
        <p className="empty">
          No claim yet — the frontier starts at the objective&apos;s baseline.
        </p>
      )}

      {frontier && (
        <>
          <h2>
            {moves.length} move{moves.length === 1 ? "" : "s"} — newest first
          </h2>
          <ol className="chain">
            {[...moves].reverse().map((move, index) => (
              <li
                className={index === moves.length - 1 ? "link genesis" : "link"}
                key={move.seq}
              >
                <div>
                  <span className="epoch">{move.score}</span>{" "}
                  <span className="dim">held by</span> {move.holder}
                  {index === 0 && (
                    <span className="tag open" style={{ marginLeft: ".4rem" }}>
                      current
                    </span>
                  )}
                </div>
                <div className="meta">
                  claim <code className="dim">{short(move.claimId)}</code> · paid{" "}
                  <b>{amount(move.paidThisMove)}</b>
                  {!move.consistent && (
                    <span className="bad">
                      {" "}
                      · disagrees with settlement (
                      {amount(move.settlementReward ?? 0)})
                    </span>
                  )}
                </div>
              </li>
            ))}
          </ol>
          <div className="meta" style={{ marginTop: "1.25rem" }}>
            {moves.map((m) => amount(m.paidThisMove)).join(" + ")} ={" "}
            {amount(frontier.paid_cumulative)} paid so far
            {record.reward > 0 && <> of {amount(record.reward)} funded</>}.
          </div>
        </>
      )}
    </>
  );
}
