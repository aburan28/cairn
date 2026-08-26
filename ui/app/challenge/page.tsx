"use client";

import Link from "next/link";
import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  type Objective,
  loadObjective,
  progress,
  short,
  units,
} from "@/lib/site";

/**
 * One challenge: what it pays, who holds the frontier, and what beating them
 * requires.
 *
 * The id arrives as `?id=` rather than as a path segment, deliberately. This app
 * is a static export — it is embedded in the node binary and served from a
 * bucket — so a dynamic segment would need every id known at build time, which
 * is exactly backwards for a page whose subject is objectives posted after the
 * build. A query parameter costs one `Suspense` boundary and works for any id a
 * node knows about.
 */
export default function Page() {
  return (
    <Suspense fallback={<main><p className="empty">reading…</p></main>}>
      <Challenge />
    </Suspense>
  );
}

function Challenge() {
  const params = useSearchParams();
  const id = params.get("id") ?? "";
  const [objective, setObjective] = useState<Objective | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "missing">("loading");
  const [live, setLive] = useState(false);
  const [origin, setOrigin] = useState("");

  useEffect(() => {
    if (!id) {
      setState("missing");
      return;
    }
    void loadObjective(id).then((r) => {
      setObjective(r.objective);
      setLive(r.live);
      setOrigin(r.origin);
      setState(r.objective ? "ready" : "missing");
    });
  }, [id]);

  if (state === "loading") return <main><p className="empty">reading…</p></main>;
  if (state === "missing" || !objective) {
    return (
      <main>
        <h1>no such challenge</h1>
        <p className="lede">
          {id ? (
            <>
              Nothing here answers to <code>{short(id)}</code>. A node only knows
              the objectives in its own log, so a different node may.
            </>
          ) : (
            <>This page needs an objective id.</>
          )}
        </p>
        <p><Link href="/">← all challenges</Link></p>
      </main>
    );
  }

  const ratchet = objective.record?.ratchet ?? null;
  const frontier = objective.frontier ?? null;
  const pct = ratchet && frontier ? progress(frontier.score, ratchet) : null;

  return (
    <main>
      <h1>{objective.goal || short(objective.id)}</h1>
      <div className="meta">
        <code className="dim" title={objective.id}>{short(objective.id)}</code>{" "}
        · <span className="tag">{objective.verifier_kind}</span>{" "}
        <span className={objective.settled ? "tag" : "tag open"}>
          {objective.settled ? "settled" : "open"}
        </span>{" "}
        · funded by <code>{objective.funder}</code>
      </div>

      {/* The statement is the funder's prose. An agent reading this page will
          act on it, so the warning travels with it rather than living in a
          footer -- the same rule `/objectives` follows over HTTP. */}
      <div className="panel">
        <b>statement — untrusted text, written by whoever funded this</b>
        {objective.statement}
      </div>

      <h2>what it pays</h2>
      {ratchet ? (
        <>
          <p className="lede">
            A progressive bounty. Whoever moves the best-known score from{" "}
            <code>{ratchet.baseline}</code> toward <code>{ratchet.target}</code>{" "}
            is paid in proportion to the distance they moved, so publishing an
            improvement immediately is the profitable move rather than a gift to
            a competitor. Payouts telescope: the pool cannot be overspent however
            finely the curve is chopped.
          </p>
          <div className="row stats">
            <Stat label="pool" value={units(ratchet.reward)} />
            <Stat label="baseline" value={String(ratchet.baseline)} />
            <Stat label="target" value={String(ratchet.target)} />
            <Stat label="direction" value={ratchet.direction} />
            <Stat label="min step" value={String(ratchet.min_improvement)} />
          </div>
        </>
      ) : (
        <p className="lede">
          A single bounty of <code>{units(objective.reward)}</code>: it settles
          once, to the first claim the pinned checker accepts.
        </p>
      )}

      <h2>frontier</h2>
      {frontier ? (
        <>
          <div className="panel">
            <b>
              best known: {frontier.score} — held by {frontier.holder}
            </b>
            {pct !== null && (
              <span className="bar wide" aria-label={`${pct}% of the span`}>
                <span style={{ width: `${pct}%` }} />
              </span>
            )}
            <div className="meta">
              claim{" "}
              <code className="dim" title={frontier.claim_id}>
                {short(frontier.claim_id)}
              </code>{" "}
              · paid so far <code>{units(frontier.paid_cumulative)}</code> ·
              remaining <code>{units(frontier.pool_remaining)}</code>
            </div>
          </div>
          <div className="panel">
            <b>to beat it</b>
            Submit a claim that scores better by at least{" "}
            <code>{ratchet?.min_improvement ?? 1}</code>, and cite{" "}
            <code className="dim" title={frontier.must_cite}>
              {short(frontier.must_cite)}
            </code>
            . The citation is checked, not requested: it is how the previous
            holder is paid out of what you earn, and a submission without it is
            refused.
          </div>
        </>
      ) : objective.settlement ? (
        /* A certificate never gets a frontier record; its whole story is one
           settlement. Before this branch the page said "settled" in the tag
           line and "No claim yet" here, about the same objective. */
        <div className="panel">
          <b>
            settled — {units(objective.settlement.reward)} paid to{" "}
            {objective.settlement.submitter}
          </b>
          <div className="meta">
            for claim{" "}
            <code className="dim" title={objective.settlement.claim_id}>
              {short(objective.settlement.claim_id)}
            </code>
            . A certificate settles once, so there is nothing left to cite and
            nothing left to win here.
          </div>
        </div>
      ) : (
        <p className="empty">
          No claim yet — the frontier starts at the objective&apos;s baseline, and
          the first improvement takes the first slice of the pool.
        </p>
      )}

      <h2>how to submit</h2>
      <div className="panel">
        <pre>{`cairn --log my.jsonl --root . try \\
    --objective ${objective.id} \\
    --artifact my-artifact.json \\
    --submitter me`}</pre>
        <div className="meta dim">
          Score locally first — it is free, it is the same pinned checker the
          network runs, and it is ground truth. Submissions are commit–reveal:
          your artifact is bound in one epoch and revealed in a later one, so
          nobody can copy it and nobody can front-run it.
        </div>
      </div>

      <p className="lede dim">
        {live
          ? `Read from ${origin}.`
          : `No node answered, so this came from ${origin} — a real settled log in the repository, not a mock. Point this page at a node, or run one yourself.`}
      </p>
      <p><Link href="/">← all challenges</Link></p>
    </main>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="stat">
      <div className="statValue">{value}</div>
      <div className="statLabel">{label}</div>
    </div>
  );
}
