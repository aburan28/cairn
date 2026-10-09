"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { type NetworkResponse, fetchNetwork, primaryRole } from "@/lib/network";
import { type Objective, loadObjectives } from "@/lib/site";
import { type Underserved, fetchGoals } from "@/lib/goals";
import {
  type AppRole,
  type AppSheet,
  PAY_LABEL,
  ROLES,
  ROLE_TOGGLE,
  type RoleId,
  type RoleInfo,
  openSheet,
  setRole,
} from "@/lib/contribute";
import { type Bridge, appBridge } from "@/lib/draft";
import { objectiveTitle } from "@/lib/title";
import { AgentConnect } from "@/components/agents";
import { WorkPanel } from "@/components/WorkPanel";
import { useNode } from "@/components/hooks";
import { Badge, Note, PageHeader, Sheet } from "@/components/ui";

/**
 * Ways to take part, what each pays, and -- one click away -- doing it.
 *
 * Every role is a button. It opens a panel that asks what it needs to and
 * then does the thing: inside Cairn.app it flips the app's toggle or opens
 * its sheet. A browser cannot control a process on the reader's machine.
 *
 * What an offer is not is proof. The roster shows what a machine says it
 * offers; only the answers a challenge's checker accepts are paid, so a
 * machine that offers a day and finds nothing earns nothing. The page says
 * so beside the button, because the alternative -- implying that offering is
 * earning -- is the one claim here the log could not back.
 */
export default function Page() {
  const base = useNode();
  const [network, setNetwork] = useState<NetworkResponse | null>(null);
  const [objectives, setObjectives] = useState<Objective[]>([]);
  const [underserved, setUnderserved] = useState<Underserved[]>([]);
  const [origin, setOrigin] = useState("");
  const [bridge, setBridge] = useState<Bridge | null>(null);
  const [open, setOpen] = useState<RoleId | null>(null);
  const [requestedObjective, setRequestedObjective] = useState<string | null>(null);
  /** The change the app is restarting the node for, until the page reloads. */
  const [restarting, setRestarting] = useState<{ role: AppRole; on: boolean } | null>(null);
  const [appError, setAppError] = useState<string | null>(null);

  useEffect(() => {
    setOrigin(window.location.origin);
    setBridge(appBridge());
    setRequestedObjective(new URLSearchParams(window.location.search).get("objective"));
    // `#compute` and friends open their panel, so "Offer compute →" on the
    // Network page lands on the form rather than on a card to find.
    const fromHash = window.location.hash.replace("#", "");
    const ids: Record<string, RoleId> = { compute: "compute", agent: "experimenter", check: "validator", relay: "relay", fund: "funder" };
    if (ids[fromHash]) setOpen(ids[fromHash]);
  }, []);

  useEffect(() => {
    if (base === null) return;
    void Promise.all([
      fetchNetwork(base).catch(() => null),
      loadObjectives(base),
      fetchGoals(base).catch(() => null),
    ]).then(([net, feed, goals]) => {
      setNetwork(net);
      setObjectives(feed.live ? feed.objectives.filter((o) => o.open) : []);
      setUnderserved(goals?.underserved ?? []);
    });
  }, [base]);

  const declared = new Set<string>(network?.node.roles.declared ?? []);

  const toggle = useCallback(
    async (role: AppRole, on: boolean) => {
      if (!bridge) return;
      setAppError(null);
      try {
        await setRole(bridge, role, on);
        // The app restarts the node and reloads this page when it is back.
        setRestarting({ role, on });
      } catch (cause) {
        const message = cause instanceof Error ? cause.message : String(cause);
        if (message !== "Cancelled.") setAppError(message);
      }
    },
    [bridge],
  );

  const sheet = useCallback(
    async (name: AppSheet, objective?: string) => {
      if (!bridge) return;
      setAppError(null);
      try {
        await openSheet(bridge, name, objective);
      } catch (cause) {
        setAppError(cause instanceof Error ? cause.message : String(cause));
      }
    },
    [bridge],
  );

  const role = network ? primaryRole(network.node) : null;
  const active = ROLES.find((r) => r.id === open) ?? null;

  return (
    <>
      <PageHeader
        title="Contribute"
        subtitle="Ways to take part and what each one pays. Pick one to start; only a challenge's pinned checker decides who is paid."
      />

      {role && network && (
        <p className="mb-4 text-[12.5px] text-ink-2">
          This node is a <b className="text-ink">{role.title}</b>
          {role.also.length > 0 && <> and {role.also.join(", ")}</>}
          {network.node.reach && !network.node.reach.lan && <> · reachable from this computer only</>}.{" "}
          <Link href="/network" className="text-accent hover:underline">
            Network →
          </Link>
        </p>
      )}

      {restarting && (
        <div className="mb-4">
          <Note title="Restarting the node">
            Cairn.app is starting the node again with{" "}
            <b className="text-ink">{ROLES.find((r) => r.start.inApp?.role === restarting.role)?.title ?? restarting.role}</b>{" "}
            {restarting.on ? "on" : "off"}. This page comes back on its own.
          </Note>
        </div>
      )}
      {appError && (
        <div className="mb-4">
          <Note title="Cairn.app said no" tone="warn">
            {appError}
          </Note>
        </div>
      )}

      <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {ROLES.map((info) => (
          <RoleCard
            key={info.id}
            role={info}
            on={info.declares ? declared.has(info.declares) : false}
            onOpen={() => {
              setOpen(info.id);
              history.replaceState(null, "", `#${HASH[info.id]}`);
            }}
          />
        ))}
      </section>

      {active && (
        <Sheet
          title={active.title}
          onClose={() => {
            setOpen(null);
            history.replaceState(null, "", window.location.pathname);
          }}
        >
          {active.id === "compute" && (
            <OfferCompute
              network={network}
              objectives={objectives}
              requestedObjective={requestedObjective}
              underserved={underserved}
              origin={base || origin}
              bridge={bridge}
              busy={restarting !== null}
              onShare={() => void toggle("worker-host", true)}
              onWork={(objective) => void sheet("work", objective)}
            />
          )}
          {active.id === "experimenter" && <Solve objectives={objectives} bridge={bridge} />}
          {active.id === "validator" && (
            <Toggled role={active} on={declared.has("verifier")} bridge={bridge} busy={restarting !== null} onToggle={toggle}>
              <p>
                You re-run each answer&rsquo;s checker on your own machine and sign what it said, staking 50,000 units per
                check. The stake comes back after six epochs; if your check is shown wrong, whoever caught it takes it.
                Checks are what lift a result to <i>backed by a bond</i> on the Knowledge page.
              </p>
              {!bridge && (
                <p className="mt-3">Open this node in Cairn.app and turn on checking in Settings.</p>
              )}
            </Toggled>
          )}
          {active.id === "relay" && (
            <Toggled role={active} on={declared.has("relay")} bridge={bridge} busy={restarting !== null} onToggle={toggle}>
              <p>
                Your node accepts connections from other nodes and serves them the log, so the network stays connected
                when others are behind routers. It costs bandwidth and opens a port to the internet.
              </p>
              {!bridge && <p className="mt-3">Open this node in Cairn.app and turn on relaying in Settings.</p>}
              <p className="mt-3 text-ink-3">
                Whether strangers can reach it is on the Network page, under <i>from outside</i>.
              </p>
            </Toggled>
          )}
          {active.id === "funder" && <Fund />}
        </Sheet>
      )}
    </>
  );
}

const HASH: Record<RoleId, string> = {
  compute: "compute",
  experimenter: "agent",
  validator: "check",
  relay: "relay",
  funder: "fund",
};

const ACTION: Record<RoleId, string> = {
  experimenter: "Start solving",
  compute: "Offer compute",
  validator: "Check answers",
  relay: "Relay for the network",
  funder: "Fund a question",
};

function RoleCard({ role, on, onOpen }: { role: RoleInfo; on: boolean; onOpen: () => void }) {
  const tone = role.pay === "paid" ? "accent" : role.pay === "bonded" ? "warn" : "neutral";
  return (
    <button
      type="button"
      onClick={onOpen}
      className="card card-pad flex cursor-pointer flex-col gap-2 text-left transition-colors hover:border-edge-strong hover:bg-surface-2"
    >
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-[14px] font-semibold text-ink">{role.title}</h2>
        <Badge tone={tone}>{PAY_LABEL[role.pay]}</Badge>
        {on && <Badge title="This node does this now">on here</Badge>}
      </div>
      <p className="text-[13px] leading-relaxed text-ink-2">{role.does}</p>
      <p className="text-[12.5px] leading-relaxed text-ink-3">{role.payDetail}</p>
      <span className="mt-auto pt-1 text-[12.5px] font-medium text-accent">{ACTION[role.id]} →</span>
    </button>
  );
}

// -- offer compute ---------------------------------------------------------------

function OfferCompute({
  network,
  objectives,
  requestedObjective,
  underserved,
  origin,
  bridge,
  busy,
  onShare,
  onWork,
}: {
  network: NetworkResponse | null;
  objectives: Objective[];
  requestedObjective: string | null;
  underserved: Underserved[];
  origin: string;
  bridge: Bridge | null;
  busy: boolean;
  onShare: () => void;
  onWork: (objective?: string) => void;
}) {
  const [objective, setObjective] = useState("");

  useEffect(() => {
    if (objective || objectives.length === 0) return;
    if (requestedObjective && objectives.some((row) => row.id === requestedObjective)) {
      setObjective(requestedObjective);
      return;
    }
    const scarce = underserved.flatMap((row) => row.objectives).find((id) => objectives.some((row) => row.id === id));
    setObjective(scarce ?? objectives[0].id);
  }, [objectives, underserved, objective, requestedObjective]);

  return (
    <div className="flex flex-col gap-4 text-[13px]">
      <p className="text-ink-2">
        Choose a goal, then start a worker on this Mac. The worker takes a slice of the search,
        runs the solver you chose in Cairn.app, and sends its answers for verification.
      </p>
      <label className="flex flex-col gap-1 text-[12px] text-ink-3">
        Goal to work on
        <select className="field" value={objective} onChange={(event) => setObjective(event.target.value)} disabled={!objectives.length}>
          {objectives.length === 0 && <option value="">No open goal on this node</option>}
          {objectives.map((row) => <option key={row.id} value={row.id}>{objectiveTitle(row)}</option>)}
        </select>
      </label>
      {objective && <WorkPanel objective={objective} base={origin} />}
      {bridge && (
        <button type="button" className="btn btn-sm self-start" disabled={busy || !objective} onClick={() => onWork(objective)}>
          Choose or change solver…
        </button>
      )}
      {!bridge && (
        <p className="text-ink-2">
          Open this node in Cairn.app on the computer that will do the work. Choose a goal and
          a solver there, then use the Start and Stop controls above.
        </p>
      )}
      {network?.node.reach && !network.node.reach.lan && (
        <div className="rounded-lg border border-edge bg-surface-2 p-3 text-ink-2">
          Other machines cannot reach this node yet.
          {bridge && (
            <button type="button" className="btn btn-sm mt-2 block" onClick={onShare} disabled={busy}>
              Share this node on my network
            </button>
          )}
        </div>
      )}
      <p className="text-[12px] text-ink-3">
        CPU use is measured on this Mac. Search rate comes from worker reports and appears only when
        its solver measures steps. Rewards count verified results in the log, never idle time.
      </p>
    </div>
  );
}

// -- the others ------------------------------------------------------------------

function Solve({ objectives, bridge }: { objectives: Objective[]; bridge: Bridge | null }) {
  const richest = [...objectives].sort((a, b) => b.reward - a.reward).slice(0, 4);
  return (
    <div className="flex flex-col gap-5 text-[13px]">
      <p className="text-ink-2">
        Answer open challenges by hand, with a program, or with an agent. Scoring a candidate first is free and uses the
        same checker that decides payment; a copy of someone else&rsquo;s answer earns nothing.
      </p>
      <div>
        <div className="label">Open on this node</div>
        {richest.length === 0 ? (
          <p className="text-ink-3">Nothing open right now.</p>
        ) : (
          <ul className="flex flex-col gap-1.5">
            {richest.map((o) => (
              <li key={o.id} className="flex items-baseline gap-2">
                <Link href={`/challenge?id=${encodeURIComponent(o.id)}`} className="min-w-0 flex-1 truncate text-accent hover:underline">
                  {objectiveTitle(o)}
                </Link>
                <span className="mono shrink-0 text-[12px] text-ink-3">{o.reward.toLocaleString("en-US")}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
      <div>
        <div className="label">With an agent</div>
        <AgentConnect bridge={bridge} />
      </div>
      <div>
        <div className="label">By hand</div>
        <p className="text-ink-2">Open a challenge to see its answer format and pinned checker, then connect an agent to score and submit your answer.</p>
      </div>
    </div>
  );
}

function Toggled({
  role,
  on,
  bridge,
  busy,
  onToggle,
  children,
}: {
  role: RoleInfo;
  on: boolean;
  bridge: Bridge | null;
  busy: boolean;
  onToggle: (role: AppRole, on: boolean) => void;
  children: React.ReactNode;
}) {
  const inApp = role.start.inApp?.role;
  return (
    <div className="flex flex-col gap-4 text-[13px] leading-relaxed text-ink-2">
      <div>{children}</div>
      <p className="text-[12.5px]">
        <b className="text-ink">Risk.</b> {role.risk}
      </p>
      {bridge && inApp ? (
        <div>
          <button type="button" className={`btn ${on ? "" : "btn-primary"}`} onClick={() => onToggle(inApp, !on)} disabled={busy}>
            {on ? ROLE_TOGGLE[inApp].on : ROLE_TOGGLE[inApp].off}
          </button>
          <p className="hint">Cairn.app asks first, then restarts the node with it {on ? "off" : "on"}.</p>
        </div>
      ) : (
        role.start.app && <p className="text-[12px] text-ink-3">In Cairn.app: {role.start.app}.</p>
      )}
    </div>
  );
}

function Fund() {
  return (
    <div className="flex flex-col gap-3 text-[13px]">
      <p className="text-ink-2">
        You set the bounty aside when you post, and it goes to whoever the checker accepts. It cannot be changed afterwards.
      </p>
      <Link href="/submit" className="card card-pad block transition-colors hover:border-edge-strong hover:bg-surface-2">
        <div className="font-medium text-ink">A single question →</div>
        <div className="mt-1 text-[12.5px] text-ink-2">
          One answer settles it, or each improvement on a score is paid. Write it, pin how answers are checked, sign it.
        </div>
      </Link>
      <Link
        href="/coordination#launch"
        className="card card-pad block transition-colors hover:border-edge-strong hover:bg-surface-2"
      >
        <div className="font-medium text-ink">A coordinated task →</div>
        <div className="mt-1 text-[12.5px] text-ink-2">
          A big search split across many machines, each paid per piece it finishes. Describe it and your agent sets it up.
        </div>
      </Link>
    </div>
  );
}
