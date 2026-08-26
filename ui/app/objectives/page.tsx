"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
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
  const [details, setDetails] = useState<Record<string, ObjectiveDetail>>({});
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

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
    // Show *which* origin, rather than the empty string NODE_URL now holds.
    // Empty is right for fetching -- it keeps every request relative, so the
    // page works behind a tunnel or a proxy on an unknown path -- and wrong for
    // displaying, because nobody can retype "" after they clear the box.
    setBase(NODE_URL || window.location.origin);
    void load(NODE_URL);
  }, [load]);

  // Both are the node's fields. Deriving `open` as `!settled` here was how
  // a ratchet with most of its pool left ended up under "settled": the node's
  // `settled` meant "a settlement record exists", and a ratchet writes one on
  // every paying move. The node now publishes both, and the rule lives there.
  const open = objectives?.filter((o) => o.open) ?? [];
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
        <code>cairn audit</code> re-derives it from nothing.
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
          <code>cairn post &lt;objective.json&gt;</code>.
        </p>
      )}

      {open.length > 0 && (
        <>
          <h2>open — {open.length}</h2>
          <ul className="cards">
            {open.map((objective) => (
              <ObjectiveCard
                key={objective.id}
                objective={objective}
                detail={details[objective.id]}
              />
            ))}
          </ul>
        </>
      )}

      {settled.length > 0 && (
        <>
          <h2>settled — {settled.length}</h2>
          <ul className="cards">
            {settled.map((objective) => (
              <ObjectiveCard
                key={objective.id}
                objective={objective}
                detail={details[objective.id]}
              />
            ))}
          </ul>
        </>
      )}
    </main>
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
        {detail?.created_at && (
          <div>
            <dt>posted</dt>
            <dd title={detail.created_at}>{detail.created_at.slice(0, 10)}</dd>
          </div>
        )}
      </dl>

      {/* The pinned checker, by hash. This is the whole reason an objective can
          be worked on before anyone trusts anybody: the code that decides
          payment is fixed at posting time and its hash is inside the
          objective's id, so swapping it means posting a different objective. */}
      {detail?.verifier && (
        <div className="meta dim verifier">
          pins{" "}
          <code>
            {detail.verifier.checker ?? detail.verifier.evaluator ?? "?"}
          </code>
          {(detail.verifier.checker_sha256 ??
            detail.verifier.evaluator_sha256) && (
            <>
              {" @ "}
              <code
                title={
                  detail.verifier.checker_sha256 ??
                  detail.verifier.evaluator_sha256
                }
              >
                {short(
                  detail.verifier.checker_sha256 ??
                    detail.verifier.evaluator_sha256 ??
                    "",
                )}
              </code>
            </>
          )}
        </div>
      )}

      {objective.frontier ? (
        <div className="frontier">
          {/* Baseline -> current -> target, because a bare score is unreadable
              without knowing which direction counts as better. `minimize`
              objectives count *down*, so a bar keyed to raw score would show a
              submitter improving things as though they were losing ground. */}
          {detail?.ratchet && (
            <div className="ratchet">
              <div className="meta">
                <span className="dim">{detail.ratchet.direction}</span>{" "}
                {detail.ratchet.baseline}
                <span className="dim"> baseline </span>→{" "}
                <b className="accent">{objective.frontier.score}</b>{" "}
                <span className="dim">now</span> →{" "}
                {detail.ratchet.target}
                <span className="dim"> target</span>
              </div>
              {(() => {
                const moved = ratchetProgress(
                  detail.ratchet,
                  objective.frontier.score,
                );
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
                {detail.ratchet.min_improvement}
              </div>
            </div>
          )}

          <div className="meta">
            <Link href={`/frontier?id=${encodeURIComponent(objective.id)}`}>
              frontier score <b className="accent">{objective.frontier.score}</b>
            </Link>{" "}
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
      ) : objective.settlement ? (
        /* A settled certificate: one claim, one payment, and nothing left to
           cite. Without this branch the card wore a "settled" tag directly
           above "no claim yet", which is two facts contradicting each other. */
        <div className="meta">
          settled — <b>{amount(objective.settlement.reward)}</b> paid to{" "}
          <code className="dim" title={objective.settlement.submitter}>
            {objective.settlement.submitter}
          </code>{" "}
          for claim{" "}
          <code className="dim" title={objective.settlement.claim_id}>
            {short(objective.settlement.claim_id)}
          </code>
        </div>
      ) : (
        <div className="meta dim">
          no claim yet — the frontier starts at the objective&apos;s baseline
        </div>
      )}
    </li>
  );
}
