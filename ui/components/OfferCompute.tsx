"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import type { NetworkResponse } from "@/lib/network";
import type { Objective } from "@/lib/site";
import type { Underserved } from "@/lib/goals";
import type { Bridge } from "@/lib/draft";
import { goalPay, pickGoal } from "@/lib/contribute";
import { objectiveTitle } from "@/lib/title";
import { WorkPanel } from "@/components/WorkPanel";
import { Badge } from "@/components/ui";

/**
 * The Contribute page's Offer compute sheet: pick an open goal, then start a
 * worker on this Mac. With no goal to pick it says why -- still reading, the
 * node did not answer, or the node really has none -- because "no open goal"
 * printed over a failed read sent people looking for a problem that was not
 * there.
 */
export function OfferCompute({
  network,
  objectives,
  live,
  onRetry,
  requestedObjective,
  underserved,
  origin,
  bridge,
  busy,
  onShare,
  onWork,
}: {
  network: NetworkResponse | null;
  /** Open goals only. */
  objectives: Objective[];
  /** Whether `/objectives` answered: `null` while the first read is out. */
  live: boolean | null;
  onRetry: () => void;
  requestedObjective: string | null;
  underserved: Underserved[];
  origin: string;
  bridge: Bridge | null;
  busy: boolean;
  onShare: () => void;
  onWork: (objective?: string) => void;
}) {
  const [objective, setObjective] = useState("");
  const scarce = underserved.flatMap((row) => row.objectives);

  useEffect(() => {
    const next = pickGoal(objectives, objective, requestedObjective, underserved.flatMap((row) => row.objectives));
    if (next !== objective) setObjective(next);
  }, [objectives, underserved, objective, requestedObjective]);

  const chosen = objectives.find((row) => row.id === objective) ?? null;

  return (
    <div className="flex flex-col gap-4 text-[13px]">
      <p className="leading-relaxed text-ink-2">
        Pick an open goal, then start a worker on this Mac. The worker takes a slice of the search, runs the solver you
        chose in Cairn.app, and sends its answers for checking.
      </p>

      {chosen ? (
        <>
          <div>
            <label className="label" htmlFor="offer-goal">
              Goal to work on
            </label>
            <select id="offer-goal" className="field" value={chosen.id} onChange={(event) => setObjective(event.target.value)}>
              {objectives.map((row) => (
                <option key={row.id} value={row.id}>
                  {objectiveTitle(row)}
                </option>
              ))}
            </select>
            <GoalFacts objective={chosen} underserved={scarce.includes(chosen.id)} />
          </div>
          <WorkPanel
            objective={chosen.id}
            base={origin}
            embedded
            onChooseSolver={bridge && !busy ? () => onWork(chosen.id) : undefined}
          />
        </>
      ) : (
        <NoGoal live={live} onRetry={onRetry} />
      )}

      {network?.node.reach && !network.node.reach.lan && (
        <div className="rounded-lg border border-edge bg-surface-2 p-3 text-[12.5px] text-ink-2">
          Other machines cannot reach this node yet.
          {bridge && (
            <button type="button" className="btn btn-sm mt-2 block" onClick={onShare} disabled={busy}>
              Share this node on my network
            </button>
          )}
        </div>
      )}

      {chosen && (
        <p className="text-[12px] leading-relaxed text-ink-3">
          CPU use is measured on this Mac. Search rate comes from worker reports and appears only when the solver measures
          steps. Only checked answers are paid, never idle time.
        </p>
      )}
    </div>
  );
}

/** What the chosen goal pays and how much of it is left, under the select. */
export function GoalFacts({ objective, underserved }: { objective: Objective; underserved: boolean }) {
  const pay = goalPay(objective);
  const n = (value: number) => <span className="mono text-ink-2">{value.toLocaleString("en-US")}</span>;
  return (
    <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px] text-ink-3">
      {pay.kind === "bounty" ? (
        <span>Bounty {n(pay.reward)}</span>
      ) : (
        <span>
          {n(pay.unitPrice)} per unit
          {pay.left != null && pay.units != null && (
            <>
              {" "}· {n(pay.left)} of {pay.units.toLocaleString("en-US")} left
            </>
          )}
        </span>
      )}
      {underserved && <Badge tone="warn" title="Few workers are on this goal for what it pays">needs workers</Badge>}
      <Link href={`/challenge?id=${encodeURIComponent(objective.id)}`} className="ml-auto text-accent hover:underline">
        Details →
      </Link>
    </div>
  );
}

/** The sheet with no goal to offer: still reading, unreadable, or empty. */
export function NoGoal({ live, onRetry }: { live: boolean | null; onRetry: () => void }) {
  if (live === null) {
    return (
      <div className="rounded-lg border border-edge bg-surface-2 p-4 text-ink-3" aria-live="polite">
        Reading open goals from this node…
      </div>
    );
  }
  if (!live) {
    return (
      <div className="rounded-lg border border-warn/40 bg-surface-2 p-4" role="status">
        <div className="font-medium text-ink">Could not read this node&rsquo;s goals</div>
        <p className="mt-1 leading-relaxed text-ink-2">
          The node did not answer. It may still be starting; this panel tries again every 20 seconds.
        </p>
        <button type="button" className="btn btn-sm mt-3" onClick={onRetry}>
          Try again now
        </button>
      </div>
    );
  }
  return (
    <div className="rounded-lg border border-edge bg-surface-2 p-4">
      <div className="font-medium text-ink">No open goal on this node</div>
      <p className="mt-1 leading-relaxed text-ink-2">
        Goals arrive when someone funds one here, or when this node syncs the log from a peer that has them. If you
        expected one, check that this node has peers.
      </p>
      <div className="mt-3 flex flex-wrap gap-2">
        <Link href="/network" className="btn btn-sm">
          Check peers
        </Link>
        <Link href="/submit" className="btn btn-sm btn-ghost">
          Fund a question →
        </Link>
      </div>
    </div>
  );
}
