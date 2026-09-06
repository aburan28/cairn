"use client";

import Link from "next/link";
import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { type Objective, loadObjective, progress, short, units } from "@/lib/site";
import {
  Badge,
  Card,
  EmptyState,
  Hash,
  Note,
  Progress,
  SectionHeading,
  Skeleton,
  Stat,
} from "@/components/ui";

/**
 * One challenge: what it pays, who holds the frontier, and what beating them
 * requires.
 *
 * The id arrives as `?id=` rather than as a path segment, deliberately. This
 * app is a static export — it is embedded in the node binary and served from a
 * bucket — so a dynamic segment would need every id known at build time, which
 * is exactly backwards for a page whose subject is objectives posted after the
 * build. A query parameter costs one `Suspense` boundary and works for any id a
 * node knows about.
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

  if (state === "loading") {
    return (
      <div className="flex flex-col gap-3">
        <Skeleton className="h-7 w-56" />
        <Skeleton className="h-4 w-full max-w-lg" />
      </div>
    );
  }

  if (state === "missing" || !objective) {
    return (
      <>
        <h1 className="text-[26px] font-semibold">No such challenge</h1>
        <p className="prose-block mt-2">
          {id ? (
            <>
              Nothing here answers to <code className="mono">{short(id)}</code>. A node
              only knows the objectives in its own log, so a different node may.
            </>
          ) : (
            <>This page needs an objective id.</>
          )}
        </p>
        <p className="mt-4">
          <Link href="/objectives" className="text-accent hover:underline">
            ← all challenges
          </Link>
        </p>
      </>
    );
  }

  const ratchet = objective.record?.ratchet ?? null;
  const frontier = objective.frontier ?? null;
  const pct = ratchet && frontier ? progress(frontier.score, ratchet) : null;

  return (
    <>
      <header className="mb-6">
        <h1 className="text-[26px] font-semibold">
          {objective.goal || short(objective.id)}
        </h1>
        <div className="mt-2 flex flex-wrap items-center gap-2 text-[12.5px] text-ink-2">
          <Hash value={objective.id} chars={10} label="id" />
          <Badge tone="info">{objective.verifier_kind}</Badge>
          <Badge tone={objective.settled ? "neutral" : "accent"}>
            {objective.settled ? "settled" : "open"}
          </Badge>
          <span className="flex items-center gap-1">
            funded by <Hash value={objective.funder} chars={8} />
          </span>
        </div>
      </header>

      {/* The statement is the funder's prose. An agent reading this page will
          act on it, so the warning travels with it rather than living in a
          footer — the same rule `/objectives` follows over HTTP. */}
      <div className="mb-8">
        <Note title="statement — untrusted text, written by whoever funded this" tone="warn">
          {objective.statement}
        </Note>
      </div>

      <section className="mb-8">
        <SectionHeading>What it pays</SectionHeading>
        {ratchet ? (
          <>
            <p className="prose-block mb-4">
              A progressive bounty. Whoever moves the best-known score from{" "}
              <code className="mono">{ratchet.baseline}</code> toward{" "}
              <code className="mono">{ratchet.target}</code> is paid in proportion to
              the distance they moved, so publishing an improvement immediately is the
              profitable move rather than a gift to a competitor. Payouts telescope: the
              pool cannot be overspent however finely the curve is chopped.
            </p>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
              <Stat label="pool" value={units(ratchet.reward)} />
              <Stat label="baseline" value={String(ratchet.baseline)} />
              <Stat label="target" value={String(ratchet.target)} />
              <Stat label="direction" value={ratchet.direction} />
              <Stat label="min step" value={String(ratchet.min_improvement)} />
            </div>
          </>
        ) : (
          <p className="prose-block">
            A single bounty of <code className="mono">{units(objective.reward)}</code>:
            it settles once, to the first claim the pinned checker accepts.
          </p>
        )}
      </section>

      <section className="mb-8">
        <SectionHeading>Frontier</SectionHeading>
        {frontier ? (
          <div className="flex flex-col gap-4">
            <Card className="card-pad">
              <div className="flex flex-wrap items-baseline gap-2">
                <span className="text-[13px] text-ink-2">best known</span>
                <span className="mono text-[20px] font-semibold text-accent">
                  {frontier.score}
                </span>
                <span className="flex items-center gap-1 text-[12.5px] text-ink-2">
                  held by <Hash value={frontier.holder} chars={8} />
                </span>
              </div>
              {pct !== null && (
                <div className="mt-3">
                  <Progress value={pct / 100} label="baseline to target" />
                </div>
              )}
              <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-[12.5px] text-ink-2">
                <span className="flex items-center gap-1">
                  claim <Hash value={frontier.claim_id} chars={8} />
                </span>
                <span>
                  paid so far{" "}
                  <span className="mono text-ink">{units(frontier.paid_cumulative)}</span>
                </span>
                <span>
                  remaining{" "}
                  <span className="mono text-ink">{units(frontier.pool_remaining)}</span>
                </span>
              </div>
            </Card>

            <Note title="to beat it">
              Submit a claim that scores better by at least{" "}
              <code className="mono">{ratchet?.min_improvement ?? 1}</code>, and cite{" "}
              <Hash value={frontier.must_cite} chars={8} />. The citation is checked, not
              requested: it is how the previous holder is paid out of what you earn, and
              a submission without it is refused.
            </Note>
          </div>
        ) : objective.settlement ? (
          /* A certificate never gets a frontier record; its whole story is one
             settlement. Before this branch the page said "settled" in the tag
             line and "No claim yet" here, about the same objective. */
          <Note
            title={`settled — ${units(objective.settlement.reward)} paid to ${objective.settlement.submitter}`}
          >
            <span className="flex flex-wrap items-center gap-1">
              for claim <Hash value={objective.settlement.claim_id} chars={8} />
            </span>
            A certificate settles once, so there is nothing left to cite and nothing left
            to win here.
          </Note>
        ) : (
          <EmptyState title="No claim yet.">
            The frontier starts at the objective&rsquo;s baseline, and the first
            improvement takes the first slice of the pool.
          </EmptyState>
        )}
      </section>

      <section className="mb-8">
        <SectionHeading>How to submit</SectionHeading>
        <Card className="card-pad">
          <pre className="code">{`cairn --log my.jsonl --root . try \\
    --objective ${objective.id} \\
    --artifact my-artifact.json \\
    --submitter me`}</pre>
          <p className="hint">
            Score locally first — it is free, it is the same pinned checker the network
            runs, and it is ground truth. Submissions are commit–reveal: your artifact is
            bound in one epoch and revealed in a later one, so nobody can copy it and
            nobody can front-run it.
          </p>
        </Card>
      </section>

      <p className="text-[12.5px] text-ink-3">
        {live
          ? `Read from ${origin}.`
          : `No node answered, so this came from ${origin} — a real settled log in the repository, not a mock. Point this page at a node, or run one yourself.`}
      </p>
      <p className="mt-4">
        <Link href="/objectives" className="text-accent hover:underline">
          ← all challenges
        </Link>
      </p>
    </>
  );
}
