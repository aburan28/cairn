"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { type NetworkResponse, fetchNetwork } from "@/lib/network";
import { type Objective, loadObjectives, resolveNode } from "@/lib/site";
import {
  type AppRole,
  type AppSheet,
  DECLARED_BY_ROLE,
  PAY_LABEL,
  ROLES,
  ROLE_TOGGLE,
  type RoleInfo,
  lanState,
  openSheet,
  setRole,
  workCommand,
} from "@/lib/contribute";
import { type Bridge, appBridge } from "@/lib/draft";
import { objectiveTitle } from "@/lib/title";
import { Badge, Box, CopyButton, Note, PageHeader, Skeleton } from "@/components/ui";

/**
 * Ways to take part, what each pays, and how to start.
 *
 * Inside Cairn.app every role is a button: the app flips the toggle, opens
 * the sheet, or starts the worker, because a window whose whole point is
 * that there is no terminal must not answer "how do I start" with a shell
 * line. In a browser tab there is no app to ask, so the same card says
 * where the control is in the app and what the command is.
 *
 * Everything about *this node* comes from `GET /network`: which roles it
 * declares, the contradictions the node itself found in that declaration,
 * and where its HTTP side can be reached from. The role descriptions are
 * `lib/contribute.ts`, which is written against what the rules pay today.
 */
export default function Page() {
  const [base, setBase] = useState<string | null>(null);
  const [network, setNetwork] = useState<NetworkResponse | null>(null);
  const [networkError, setNetworkError] = useState<string | null>(null);
  const [objectives, setObjectives] = useState<Objective[]>([]);
  const [live, setLive] = useState(false);
  const [origin, setOrigin] = useState("");
  const [bridge, setBridge] = useState<Bridge | null>(null);
  /** The change the app is restarting the node for, until the page reloads. */
  const [restarting, setRestarting] = useState<{ role: AppRole; on: boolean } | null>(null);
  const [appError, setAppError] = useState<string | null>(null);

  useEffect(() => {
    setOrigin(window.location.origin);
    setBridge(appBridge());
    void resolveNode().then(async (url) => {
      setBase(url);
      const [net, feed] = await Promise.all([
        fetchNetwork(url).catch((cause: unknown) => {
          setNetworkError(cause instanceof Error ? cause.message : String(cause));
          return null;
        }),
        loadObjectives(url),
      ]);
      setNetwork(net);
      setLive(feed.live);
      setObjectives(feed.live ? feed.objectives.filter((o) => o.open) : []);
    });
  }, []);

  const declared = new Set<string>(network?.node.roles.declared ?? []);

  async function toggle(role: AppRole, on: boolean) {
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
  }

  async function open(sheet: AppSheet, objective?: string) {
    if (!bridge) return;
    setAppError(null);
    try {
      await openSheet(bridge, sheet, objective);
    } catch (cause) {
      setAppError(cause instanceof Error ? cause.message : String(cause));
    }
  }

  return (
    <>
      <PageHeader
        title="Contribute"
        subtitle="Ways to take part, what each one pays today, and how to start. Only an objective's pinned checker decides who is paid; no role changes that."
      />

      <div className="flex flex-col gap-5">
        <ThisNode network={network} error={networkError} loading={base === null} />

        {restarting && (
          <Note title="restarting the node">
            Cairn.app is starting the node again with{" "}
            <b className="text-ink">
              {ROLES.find((r) => r.start.inApp?.role === restarting.role)?.title ?? restarting.role}
            </b>{" "}
            {restarting.on ? "on" : "off"}. This page comes back on its own.
          </Note>
        )}
        {appError && (
          <Note title="Cairn.app said no" tone="warn">
            {appError}
          </Note>
        )}

        <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {ROLES.map((role) => (
            <RoleCard
              key={role.id}
              role={role}
              on={role.declares ? declared.has(role.declares) : false}
              bridge={bridge}
              busy={restarting !== null}
              onToggle={toggle}
              onOpen={open}
            />
          ))}
        </section>

        <AddMachine
          network={network}
          objectives={objectives}
          live={live}
          base={base ?? ""}
          origin={origin}
          bridge={bridge}
          busy={restarting !== null}
          onShare={() => toggle("worker-host", true)}
          onOpen={open}
        />

        <p className="text-[12px] text-ink-3">
          Why validators and relays are not paid yet, and what would change that:{" "}
          <span className="mono">docs/design/roles-and-rewards.md</span>.
        </p>
      </div>
    </>
  );
}

function ThisNode({
  network,
  error,
  loading,
}: {
  network: NetworkResponse | null;
  error: string | null;
  loading: boolean;
}) {
  if (error) {
    return (
      <Note title="this node did not describe itself" tone="warn">
        {error} The roles below still apply; this page just cannot say which this node has on.
      </Note>
    );
  }
  if (!network) {
    return (
      <Box title="This node">
        <Skeleton className={loading ? "h-4 w-64" : "h-4 w-48"} />
      </Box>
    );
  }
  const { roles, warnings, reach } = network.node;
  const lan = lanState(reach, "");
  return (
    <Box title="This node">
      <dl className="kv">
        <dt>declares</dt>
        <dd className="flex flex-wrap gap-1.5">
          {roles.declared.length === 0 ? (
            <span className="text-ink-3">no roles</span>
          ) : (
            roles.declared.map((role) => <Badge key={role}>{role}</Badge>)
          )}
        </dd>
        <dt>reachable from</dt>
        <dd>
          {lan.state === "lan"
            ? lan.urls.length
              ? "your network"
              : "your network (address not found)"
            : lan.state === "local"
              ? "this computer only"
              : "unknown on this node version"}
        </dd>
        <dt>can check</dt>
        <dd>
          {network.node.verifiers.servable.length
            ? network.node.verifiers.servable.join(", ")
            : "no verifier kind on this machine"}
        </dd>
      </dl>
      {warnings.length > 0 && (
        <ul className="mt-3 flex flex-col gap-1 text-[12.5px] text-warn">
          {warnings.map((warning) => (
            <li key={warning}>{warning}</li>
          ))}
        </ul>
      )}
    </Box>
  );
}

function RoleCard({
  role,
  on,
  bridge,
  busy,
  onToggle,
  onOpen,
}: {
  role: RoleInfo;
  on: boolean;
  bridge: Bridge | null;
  busy: boolean;
  onToggle: (role: AppRole, on: boolean) => void;
  onOpen: (sheet: AppSheet) => void;
}) {
  const tone = role.pay === "paid" ? "accent" : role.pay === "bonded" ? "warn" : "neutral";
  const inApp = bridge ? role.start.inApp : undefined;
  return (
    <article className="card card-pad flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-[14px] font-semibold text-ink">{role.title}</h2>
        <Badge tone={tone}>{PAY_LABEL[role.pay]}</Badge>
        {on && <Badge title="This node declares this role">on here</Badge>}
      </div>
      <p className="text-[13px] leading-relaxed text-ink-2">{role.does}</p>
      <p className="text-[12.5px] leading-relaxed text-ink-2">
        <b className="font-medium text-ink">How it pays.</b> {role.payDetail}
      </p>
      <p className="text-[12.5px] leading-relaxed text-ink-3">
        <b className="font-medium text-ink-2">Risk.</b> {role.risk}
      </p>
      <div className="mt-auto flex flex-col gap-1.5 pt-1 text-[12px]">
        {inApp ? (
          <div className="flex flex-wrap items-center gap-2">
            {inApp.open && (
              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={() => onOpen(inApp.open!.sheet)}
                disabled={busy}
              >
                {inApp.open.label}
              </button>
            )}
            {inApp.role && (
              <button
                type="button"
                className={inApp.open ? "btn btn-sm" : on ? "btn btn-sm" : "btn btn-primary btn-sm"}
                onClick={() => onToggle(inApp.role!, !on)}
                disabled={busy}
                title={
                  on
                    ? "Turns this role off and restarts the node"
                    : "Turns this role on and restarts the node; Cairn.app asks first"
                }
              >
                {on ? ROLE_TOGGLE[inApp.role].on : ROLE_TOGGLE[inApp.role].off}
              </button>
            )}
          </div>
        ) : (
          <>
            {role.start.app && (
              <div className="text-ink-2">
                <span className="text-ink-3">In Cairn.app: </span>
                {role.start.app}
              </div>
            )}
            {role.start.cli && (
              <div className="relative">
                <pre className="code pr-9 text-[11.5px]">{role.start.cli}</pre>
                <div className="absolute top-1.5 right-1.5">
                  <CopyButton value={role.start.cli} />
                </div>
              </div>
            )}
          </>
        )}
        {role.start.page && (
          <Link href={role.start.page.href} className="text-accent hover:underline">
            {role.start.page.label} →
          </Link>
        )}
      </div>
    </article>
  );
}

/**
 * The second-machine walkthrough: is this node reachable from the LAN, and
 * if so, what that machine does to join -- in its own Cairn.app, or with
 * the exact `cairn work` line for the objective picked here.
 */
function AddMachine({
  network,
  objectives,
  live,
  base,
  origin,
  bridge,
  busy,
  onShare,
  onOpen,
}: {
  network: NetworkResponse | null;
  objectives: Objective[];
  live: boolean;
  base: string;
  origin: string;
  bridge: Bridge | null;
  busy: boolean;
  onShare: () => void;
  onOpen: (sheet: AppSheet, objective?: string) => void;
}) {
  const lan = lanState(network?.node.reach, base || origin);
  const [objective, setObjective] = useState<string>("");
  const [worker, setWorker] = useState("");
  const [solver, setSolver] = useState("");
  const [url, setUrl] = useState<string>("");

  useEffect(() => {
    if (!objective && objectives.length) setObjective(objectives[0].id);
  }, [objectives, objective]);
  const urls = lan.state === "lan" ? lan.urls : [];
  const leader = network?.node.fleet?.signs_as ?? null;
  useEffect(() => {
    if (!url && urls.length) setUrl(urls[0]);
  }, [urls, url]);

  const command = useMemo(
    () => workCommand({ node: url, objective: objective || null, worker, solver, leader }),
    [url, objective, worker, solver, leader],
  );
  const working = (network?.compute.workers ?? []).filter((w) => w.status === "live");

  return (
    <Box title="Add a machine on your network">
      <div className="flex flex-col gap-4 text-[13px]">
        {lan.state === "local" ? (
          <Note title="only this computer can reach this node" tone="warn">
            Another machine cannot connect until the node listens on your network.{" "}
            {bridge ? (
              <>
                Anyone on that network can then read the log and post answers; nobody can
                change what has settled.
                <div className="mt-2">
                  <button type="button" className="btn btn-primary btn-sm" onClick={onShare} disabled={busy}>
                    Share this node on my network
                  </button>
                </div>
              </>
            ) : (
              <>
                In Cairn.app: Contribute ▸ <b>Share this node on my network</b> (or Settings ▸
                Roles ▸ Worker host), then restart the node. From a terminal:{" "}
                <code className="mono">cairn run --serve 0.0.0.0:8080</code>. Anyone on that
                network can then read the log and post answers; nobody can change what has
                settled.
              </>
            )}
          </Note>
        ) : lan.state === "unknown" ? (
          <Note title="this node does not say where it can be reached" tone="warn">
            It is older than this page. If you started it with{" "}
            <code className="mono">--serve 0.0.0.0:8080</code>, use this computer&rsquo;s LAN
            address below.
          </Note>
        ) : null}

        <ol className="flex flex-col gap-3">
          <li>
            <b className="text-ink">1. Put Cairn on the other machine.</b>{" "}
            <span className="text-ink-2">
              A Mac: install Cairn from the same disk image, which brings Cairn.app. Anything
              else, with internet: the install line on the Overview. Without: copy the{" "}
              <code className="mono">cairn</code> binary across — it is one file with nothing to
              install beside it.
            </span>
          </li>
          <li className="flex flex-col gap-2">
            <b className="text-ink">2. Pick what it works on, and its name.</b>
            <div className="grid gap-2 sm:grid-cols-2">
              <label className="flex flex-col gap-1 text-[12px] text-ink-3">
                Objective
                <select
                  className="field"
                  value={objective}
                  onChange={(e) => setObjective(e.target.value)}
                  disabled={!objectives.length}
                >
                  {objectives.length === 0 && (
                    <option value="">{live ? "no open objectives" : "no node answered"}</option>
                  )}
                  {objectives.map((o) => (
                    <option key={o.id} value={o.id}>
                      {objectiveTitle(o)}
                    </option>
                  ))}
                </select>
              </label>
              <label className="flex flex-col gap-1 text-[12px] text-ink-3">
                Node address
                {urls.length > 1 ? (
                  <select className="field field-mono" value={url} onChange={(e) => setUrl(e.target.value)}>
                    {urls.map((u) => (
                      <option key={u}>{u}</option>
                    ))}
                  </select>
                ) : (
                  <input
                    className="field field-mono"
                    value={url}
                    placeholder="http://<this computer>:8080"
                    onChange={(e) => setUrl(e.target.value)}
                    spellCheck={false}
                  />
                )}
              </label>
              <label className="flex flex-col gap-1 text-[12px] text-ink-3">
                Machine name (shown on the roster, and paid)
                <input
                  className="field"
                  value={worker}
                  placeholder="garage-gpu"
                  onChange={(e) => setWorker(e.target.value)}
                  spellCheck={false}
                />
              </label>
              <label className="flex flex-col gap-1 text-[12px] text-ink-3">
                Solver command
                <input
                  className="field field-mono"
                  value={solver}
                  placeholder="./your-solver"
                  onChange={(e) => setSolver(e.target.value)}
                  spellCheck={false}
                />
              </label>
            </div>
          </li>
          <li className="flex flex-col gap-2">
            <b className="text-ink">3. Start it there.</b>
            {bridge ? (
              <>
                <span className="text-[12.5px] text-ink-2">
                  In Cairn.app on that machine: <b className="text-ink">Contribute ▸ Work on this
                  Mac…</b>, with the node address and the objective above, its name, and the
                  solver chosen on that machine. To try the solver here first:
                </span>
                <div>
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => onOpen("work", objective || undefined)}
                    disabled={busy}
                  >
                    Work on this Mac…
                  </button>
                </div>
                <details className="text-[12.5px] text-ink-2">
                  <summary className="cursor-pointer text-ink-3">
                    Without Cairn.app on that machine (Linux, a rented GPU)
                  </summary>
                  <div className="relative mt-2">
                    <pre className="code pr-9 text-[11.5px]">{command}</pre>
                    <div className="absolute top-2 right-2">
                      <CopyButton value={command} />
                    </div>
                  </div>
                </details>
              </>
            ) : (
              <div className="relative">
                <pre className="code pr-9 text-[11.5px]">{command}</pre>
                <div className="absolute top-2 right-2">
                  <CopyButton value={command} />
                </div>
              </div>
            )}
            <span className="text-[12.5px] text-ink-2">
              Each round the solver gets its slice of the work as JSON on stdin and prints
              candidate answers, one JSON object per line. The worker commits them, reveals them
              after the epoch turns, and reports in so the machine shows as <i>working now</i> on
              the challenge page. The checker decides what is paid.
              {leader ? (
                <>
                  {" "}
                  This node leads a fleet, so a machine on its network names it as the
                  submitter: the node signs each machine&rsquo;s records and is paid for them,
                  while each machine keeps its own slice and its own line on the roster.
                </>
              ) : (
                <> Each machine is paid under its own name.</>
              )}
            </span>
          </li>
        </ol>

        <div className="text-[12.5px] text-ink-2">
          <b className="text-ink">Working offline.</b> A network with no internet works the same:
          {bridge ? (
            <> Settings ▸ Network ▸ Offline.</>
          ) : (
            <>
              {" "}
              start the node with <code className="mono">CAIRN_SEEDS=off</code> (Cairn.app:
              Settings ▸ Network ▸ Offline).
            </>
          )}{" "}
          Nodes on the same network find each other by their LAN beacon, and workers only ever
          need the node&rsquo;s address.
        </div>

        <div className="text-[12.5px] text-ink-2">
          <b className="text-ink">Working now:</b>{" "}
          {working.length === 0 ? (
            <span className="text-ink-3">no machine is reporting in to this node.</span>
          ) : (
            <>
              {working.map((w) => w.worker).join(", ")}{" "}
              <Link href="/network" className="text-accent hover:underline">
                on the Network page →
              </Link>
            </>
          )}
        </div>
      </div>
    </Box>
  );
}
