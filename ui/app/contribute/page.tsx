"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { type NetworkResponse, fetchNetwork, primaryRole } from "@/lib/network";
import { type Objective, loadObjectives } from "@/lib/site";
import { type Underserved, fetchGoals } from "@/lib/goals";
import {
  type AppRole,
  type AppSheet,
  type Offer,
  PAY_LABEL,
  ROLES,
  ROLE_TOGGLE,
  type RoleId,
  type RoleInfo,
  describeOffer,
  lanState,
  openSheet,
  setRole,
  workCommand,
} from "@/lib/contribute";
import { type Bridge, appBridge } from "@/lib/draft";
import { objectiveTitle } from "@/lib/title";
import { AgentConnect } from "@/components/agents";
import { useNode } from "@/components/hooks";
import { Badge, Command, Note, PageHeader, Sheet } from "@/components/ui";

/**
 * Ways to take part, what each pays, and -- one click away -- doing it.
 *
 * Every role is a button. It opens a panel that asks what it needs to and
 * then does the thing: inside Cairn.app it flips the app's toggle or opens
 * its sheet; anywhere else it hands over the exact command, filled in from
 * this node. Offering compute is the one that asks the most -- which GPUs,
 * how many threads, how many hours a day, on what -- and `cairn work` honours
 * all of it (`src/agent/work.rs`): the solver is shown only the GPUs offered,
 * told its thread count, and paused when the day's hours are used.
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
                <>
                  <p className="mt-3">Make a key, then start the node with it:</p>
                  <Command className="mt-1.5" text={"cairn identity --out validator.identity.json\ncairn run --attest-identity validator.identity.json"} />
                </>
              )}
            </Toggled>
          )}
          {active.id === "relay" && (
            <Toggled role={active} on={declared.has("relay")} bridge={bridge} busy={restarting !== null} onToggle={toggle}>
              <p>
                Your node accepts connections from other nodes and serves them the log, so the network stays connected
                when others are behind routers. It costs bandwidth and opens a port to the internet.
              </p>
              {!bridge && <Command className="mt-3" text="cairn run --listen 0.0.0.0:9000" />}
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

const GPU_CHOICES = [0, 1, 2, 3, 4, 5, 6, 7] as const;

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
  const cpus = network?.node.hardware.cpus ?? 8;
  const [where, setWhere] = useState<"here" | "other">("here");
  const [gpus, setGpus] = useState<number[]>([]);
  const [threads, setThreads] = useState(Math.max(1, Math.floor(cpus / 2)));
  const [hours, setHours] = useState(8);
  const [objective, setObjective] = useState("");
  const [worker, setWorker] = useState("");
  const [device, setDevice] = useState("");
  const [solver, setSolver] = useState("");
  const [url, setUrl] = useState("");

  // Follow an objective-specific Contribute link when possible. Otherwise
  // default to the richest open angle with the fewest live workers.
  useEffect(() => {
    if (objective || objectives.length === 0) return;
    if (requestedObjective && objectives.some((o) => o.id === requestedObjective)) {
      setObjective(requestedObjective);
      return;
    }
    const scarce = underserved.flatMap((row) => row.objectives).find((id) => objectives.some((o) => o.id === id));
    setObjective(scarce ?? objectives[0].id);
  }, [objectives, underserved, objective, requestedObjective]);

  const lan = lanState(network?.node.reach, origin);
  const urls = useMemo(() => (lan.state === "lan" ? lan.urls : []), [lan]);
  useEffect(() => {
    if (!url) setUrl(where === "here" ? origin : (urls[0] ?? ""));
  }, [where, urls, origin, url]);

  const offer: Offer = { gpus, threads, hoursPerDay: hours, device: device || null };
  const leader = network?.node.fleet?.signs_as ?? null;
  const command = workCommand({ node: url, objective: objective || null, worker, solver, leader, offer });
  const target = objectives.find((o) => o.id === objective);

  return (
    <div className="flex flex-col gap-5 text-[13px]">
      <p className="text-ink-2">
        Put a machine to work on a challenge. It takes its own slice each epoch, runs a solver you supply, and is paid for
        what the challenge&rsquo;s checker accepts.
      </p>

      <div className="segmented self-start" role="group" aria-label="Which machine">
        <button type="button" aria-pressed={where === "here"} onClick={() => { setWhere("here"); setUrl(""); }}>
          This computer
        </button>
        <button type="button" aria-pressed={where === "other"} onClick={() => { setWhere("other"); setUrl(""); }}>
          Another machine
        </button>
      </div>

      {where === "other" && lan.state === "local" && (
        <Note title="Only this computer can reach this node" tone="warn">
          Another machine cannot connect until the node listens on your network.
          {bridge ? (
            <div className="mt-2">
              <button type="button" className="btn btn-primary btn-sm" onClick={onShare} disabled={busy}>
                Share this node on my network
              </button>
            </div>
          ) : (
            <>
              {" "}
              Start it with <code className="mono">cairn run --serve 0.0.0.0:8080</code>. Anyone on that network can then
              read the log and post answers; nobody can change what has settled.
            </>
          )}
        </Note>
      )}

      <fieldset className="flex flex-col gap-1.5">
        <legend className="label">GPUs to offer</legend>
        <div className="flex flex-wrap gap-1.5">
          <button
            type="button"
            className={`btn btn-sm ${gpus.length === 0 ? "btn-primary" : ""}`}
            onClick={() => setGpus([])}
          >
            None
          </button>
          {GPU_CHOICES.map((n) => (
            <button
              key={n}
              type="button"
              className={`btn btn-sm mono ${gpus.includes(n) ? "btn-primary" : ""}`}
              onClick={() => setGpus(gpus.includes(n) ? gpus.filter((g) => g !== n) : [...gpus, n].sort((a, b) => a - b))}
              aria-pressed={gpus.includes(n)}
            >
              GPU {n}
            </button>
          ))}
        </div>
        <span className="hint">
          The solver sees only these, as <span className="mono">CUDA_VISIBLE_DEVICES</span> and{" "}
          <span className="mono">HIP_VISIBLE_DEVICES</span>; the rest of the machine&rsquo;s GPUs stay yours.
        </span>
      </fieldset>

      <label className="flex flex-col gap-1.5">
        <span className="label mb-0 flex justify-between">
          CPU threads <span className="mono text-ink">{threads}</span>
        </span>
        <input type="range" min={1} max={Math.max(cpus, 1)} value={threads} onChange={(e) => setThreads(Number(e.target.value))} />
        <span className="hint">
          Told to the solver as <span className="mono">OMP_NUM_THREADS</span> and{" "}
          <span className="mono">CAIRN_THREADS</span>
          {network?.node.hardware.cpus && where === "here" ? `; this computer has ${network.node.hardware.cpus}.` : "."}
        </span>
      </label>

      <label className="flex flex-col gap-1.5">
        <span className="label mb-0 flex justify-between">
          Hours a day <span className="mono text-ink">{hours >= 24 ? "all day" : hours}</span>
        </span>
        <input type="range" min={1} max={24} value={hours} onChange={(e) => setHours(Number(e.target.value))} />
        <span className="hint">
          It pauses when today&rsquo;s hours are used and starts again at midnight UTC, still sending what it already
          committed so nothing goes unpaid.
        </span>
      </label>

      <div className="grid gap-3 sm:grid-cols-2">
        <label className="flex flex-col gap-1 text-[12px] text-ink-3 sm:col-span-2">
          Work on
          <select className="field" value={objective} onChange={(e) => setObjective(e.target.value)} disabled={!objectives.length}>
            {objectives.length === 0 && <option value="">no open challenge on this node</option>}
            {objectives.map((o) => (
              <option key={o.id} value={o.id}>
                {objectiveTitle(o)}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-[12px] text-ink-3">
          Machine name
          <input className="field" value={worker} placeholder="garage-gpu" onChange={(e) => setWorker(e.target.value)} spellCheck={false} />
        </label>
        <label className="flex flex-col gap-1 text-[12px] text-ink-3">
          What it is
          <input className="field" value={device} placeholder="RTX 4090" onChange={(e) => setDevice(e.target.value)} />
        </label>
        <label className="flex flex-col gap-1 text-[12px] text-ink-3 sm:col-span-2">
          Solver command
          <input className="field field-mono" value={solver} placeholder="./your-solver" onChange={(e) => setSolver(e.target.value)} spellCheck={false} />
        </label>
        {where === "other" && (
          <label className="flex flex-col gap-1 text-[12px] text-ink-3 sm:col-span-2">
            This node, as the other machine reaches it
            <input className="field field-mono" value={url} placeholder="http://<this computer>:8080" onChange={(e) => setUrl(e.target.value)} spellCheck={false} />
          </label>
        )}
      </div>

      <div className="rounded-lg border border-accent-line bg-accent-soft px-3 py-2.5 text-[12.5px] text-ink">
        Offering <b>{describeOffer(offer)}</b>
        {target ? (
          <>
            {" "}
            to <b>{objectiveTitle(target)}</b>.
          </>
        ) : (
          "."
        )}
      </div>

      <div className="flex flex-col gap-2">
        <div className="text-[12.5px] font-medium text-ink">
          {where === "here" ? "Start it in a terminal on this computer" : "Start it on that machine"}
        </div>
        <Command text={command} />
        {bridge && where === "here" && (
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" className="btn btn-sm" onClick={() => onWork(objective || undefined)} disabled={busy}>
              Or use Work on This Mac…
            </button>
            <span className="text-[11.5px] text-ink-3">Cairn.app&rsquo;s sheet runs the same worker, without the limits above.</span>
          </div>
        )}
        <p className="hint">
          Each round the solver gets its slice as JSON on stdin and prints answers, one JSON object per line. The machine
          appears on the Network page within a minute, with what it offered.
        </p>
      </div>

      <div className="rounded-lg border border-edge bg-surface-2 px-3 py-2.5 text-[12px] leading-relaxed text-ink-2">
        <b className="text-ink">How the work is proven.</b> An offer is what a machine says; nothing checks it, and nothing
        pays for it. What pays is an answer the challenge&rsquo;s pinned checker accepts — committed, revealed an epoch
        later, and recorded in the log — so the only proof of work that counts is the work.
        {leader && " This node leads a fleet: it signs for the machines on its network and is paid for what they find."}
      </div>
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
        <Command text="cairn try <challenge id> --submitter <you> --artifact answer.json" />
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
