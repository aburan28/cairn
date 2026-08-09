"use client";

import { useCallback, useEffect, useState } from "react";
import {
  type Objective,
  NODE_URL,
  amount,
  fetchObjectives,
  overspent,
  poolFraction,
  short,
} from "@/lib/objectives";

/**
 * What this node will pay for, and how far each question has got.
 *
 * The companion to the chain page. That one answers "have I forked"; this one
 * answers "is there anything here worth working on", which is the question
 * somebody arriving at a node actually has.
 *
 * A client component for the same reason: which node it reads has to be
 * changeable without a redeploy, because comparing two nodes is the point.
 */
export default function Page() {
  const [base, setBase] = useState(NODE_URL);
  const [objectives, setObjectives] = useState<Objective[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async (url: string) => {
    setLoading(true);
    setError(null);
    try {
      setObjectives(await fetchObjectives(url));
    } catch (cause) {
      setObjectives(null);
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load(NODE_URL);
  }, [load]);

  const open = objectives?.filter((o) => !o.settled) ?? [];
  const settled = objectives?.filter((o) => o.settled) ?? [];

  return (
    <main>
      <h1>objectives</h1>
      <p className="lede">
        Every question this node has been told about, and what remains payable
        on it. A <code>certificate</code> objective settles once; an{" "}
        <code>evaluator</code> objective ratchets, paying each improvement in
        proportion to the distance it moved the frontier. Nothing here is this
        page&apos;s opinion — the node derived it from its log, and{" "}
        <code>proofwork audit</code> re-derives it from nothing.
      </p>

      <div className="row">
        <input
          value={base}
          onChange={(event) => setBase(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") void load(base);
          }}
          aria-label="Node URL"
          spellCheck={false}
        />
        <button onClick={() => void load(base)} disabled={loading}>
          {loading ? "reading…" : "read"}
        </button>
      </div>

      {error && (
        <div className="panel bad">
          <b>could not read objectives</b>
          {error}
        </div>
      )}

      {objectives && objectives.length === 0 && (
        <p className="empty">
          This node knows of no objectives. Fund one with{" "}
          <code>proofwork post &lt;objective.json&gt;</code>.
        </p>
      )}

      {open.length > 0 && (
        <>
          <h2>open — {open.length}</h2>
          <ul className="cards">
            {open.map((objective) => (
              <ObjectiveCard key={objective.id} objective={objective} />
            ))}
          </ul>
        </>
      )}

      {settled.length > 0 && (
        <>
          <h2>settled — {settled.length}</h2>
          <ul className="cards">
            {settled.map((objective) => (
              <ObjectiveCard key={objective.id} objective={objective} />
            ))}
          </ul>
        </>
      )}
    </main>
  );
}

function ObjectiveCard({ objective }: { objective: Objective }) {
  const fraction = poolFraction(objective);
  const suspect = overspent(objective);

  return (
    <li className="card">
      <div className="card-head">
        <span className="goal">{objective.goal}</span>
        <span className={objective.settled ? "tag settled" : "tag open"}>
          {objective.settled ? "settled" : "open"}
        </span>
        <span className="tag kind">{objective.verifier_kind}</span>
      </div>

      {/* The statement is objective-authored text -- attacker-supplied, in the
          terms src/bin/mcp.rs uses. React escapes it, and it is kept in its own
          block rather than interleaved with the node's own numbers so that no
          sentence inside it can read as a field this page rendered. */}
      <blockquote className="statement">{objective.statement}</blockquote>

      <dl className="facts">
        <div>
          <dt>funder</dt>
          <dd>{objective.funder}</dd>
        </div>
        <div>
          <dt>funded</dt>
          <dd>{amount(objective.reward)}</dd>
        </div>
        <div>
          <dt>id</dt>
          <dd>
            <code className="dim" title={objective.id}>
              {short(objective.id)}
            </code>
          </dd>
        </div>
      </dl>

      {objective.frontier ? (
        <div className="frontier">
          <div className="meta">
            frontier score <b className="accent">{objective.frontier.score}</b>{" "}
            held by{" "}
            <code className="dim" title={objective.frontier.holder}>
              {short(objective.frontier.holder)}
            </code>
          </div>

          {fraction !== null && (
            <div
              className="bar"
              role="img"
              aria-label={`${amount(objective.frontier.pool_remaining)} of ${amount(
                objective.reward,
              )} remaining`}
            >
              <span style={{ width: `${fraction * 100}%` }} />
            </div>
          )}

          <div className="meta">
            {amount(objective.frontier.pool_remaining)} remaining ·{" "}
            {amount(objective.frontier.paid_cumulative)} paid
          </div>

          <div className="meta">
            an improvement must cite{" "}
            <code className="dim" title={objective.frontier.must_cite}>
              {short(objective.frontier.must_cite)}
            </code>
          </div>

          {/* The one claim this page makes on its own behalf, matching
              firstBrokenLink on the chain page: paid + remaining cannot exceed
              what was funded, and if it does the node published something its
              own arithmetic does not support. */}
          {suspect && (
            <div className="panel bad">
              <b>this pool does not add up</b>
              {amount(objective.frontier.paid_cumulative)} paid plus{" "}
              {amount(objective.frontier.pool_remaining)} remaining exceeds the{" "}
              {amount(objective.reward)} funded. Audit this node before trusting
              any figure on this card.
            </div>
          )}
        </div>
      ) : (
        <div className="meta dim">
          no claim yet — the frontier starts at the objective&apos;s baseline
        </div>
      )}
    </li>
  );
}
