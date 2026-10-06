"use client";

import Link from "next/link";
import { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { type Objective, loadObjective, progress, resolveNode, short, units } from "@/lib/site";
import { type Participant, ago, eventsFor, indexObjectives, participants } from "@/lib/events";
import { type LogRecord, fetchLog } from "@/lib/log";
import { type ProgressResponse, fetchProgress } from "@/lib/progress";
import { isFollowing, onFollowingChange, setFollowing } from "@/lib/follow";
import { goalSlug, objectiveTitle } from "@/lib/title";
import { openSheet, workCommand } from "@/lib/contribute";
import { type Bridge, appBridge } from "@/lib/draft";
import { EventRow, shortActor } from "@/components/events";
import {
  Badge,
  Box,
  CopyButton,
  Hash,
  PageHeader,
  Progress,
  Skeleton,
  Stat,
  StatusPill,
} from "@/components/ui";

/**
 * The Claude Code stanza from docs/agents.md, with placeholder paths. The
 * other two clients spell the same three arguments differently and the doc
 * has them; one copy here is enough to get someone started, and three would
 * be three things to keep in step with the doc.
 */
const MCP_STANZA = `{
  "mcpServers": {
    "cairn": {
      "command": "/abs/path/to/cairn",
      "args": ["--log", "/abs/path/to/cairn.jsonl", "--root", "/abs/path/to/repo", "mcp"]
    }
  }
}`;

/**
 * The tool calls, with this objective's id filled in.
 *
 * `cites` is included only when there is a frontier to cite, and then with
 * the claim id the node published -- a submission against a ratcheted
 * objective that omits it is refused, and that is the rule an agent most
 * often trips over. The capability half is deliberately left as a
 * placeholder: it is session-local proof the id came from a server field,
 * and this page cannot mint one.
 */
function mcpCalls(id: string, mustCite: string | undefined): string {
  const cite = mustCite
    ? `,\n  "cites": [{ "claim_id": "${mustCite}", "capability": "<from frontier_status>" }]`
    : "";
  return `get_objective   { "objective_id": "${id}" }
score_candidate { "objective_id": "${id}", "artifact": { … } }
submit_claim    { "objective_id": "${id}", "submitter": "me", "artifact": { … }${cite} }`;
}

/**
 * `try` scores without writing. `commit` binds the artifact in this epoch and
 * prints the nonce; `reveal` opens it in a later one, and that is where the
 * citation goes -- `commit` takes none, because the commitment hash covers
 * the artifact and the submitter and nothing else.
 */
function cliCalls(id: string, mustCite: string | undefined): string {
  const cite = mustCite ? ` \\\n    --cites ${mustCite}` : "";
  return `cairn --log my.jsonl --root . try ${id} \\
    --submitter me --artifact my-artifact.json

cairn --log my.jsonl --root . commit ${id} \\
    --submitter me --artifact my-artifact.json
# … the epoch turns …
cairn --log my.jsonl --root . reveal ${id} \\
    --submitter me --artifact my-artifact.json --nonce <from commit>${cite}`;
}

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
  const [base, setBase] = useState<string | null>(null);
  const [followed, setFollowed] = useState(false);

  useEffect(() => {
    if (!id) {
      setState("missing");
      return;
    }
    void resolveNode().then(async (url) => {
      setBase(url);
      const r = await loadObjective(id, url);
      setObjective(r.objective);
      setLive(r.live);
      setOrigin(r.origin);
      setState(r.objective ? "ready" : "missing");
    });
  }, [id]);

  useEffect(() => {
    if (!id) return;
    setFollowed(isFollowing(id));
    return onFollowingChange(() => setFollowed(isFollowing(id)));
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
  const verifier = objective.record?.verifier ?? {};
  const checker = text(verifier.checker) ?? text(verifier.evaluator);
  const checkerHash = text(verifier.checker_sha256) ?? text(verifier.evaluator_sha256);
  const paid = frontier?.paid_cumulative ?? objective.settlement?.reward ?? 0;
  const remaining = frontier?.pool_remaining ?? (objective.settled ? 0 : objective.reward);
  const slug = goalSlug(objective.goal);

  return (
    <>
      <PageHeader
        crumb={{ href: "/objectives", label: "Objectives" }}
        title={objectiveTitle(objective)}
        meta={
          <>
            <StatusPill settled={objective.settled} />
            {slug && <Badge title={objective.goal}>{slug}</Badge>}
            <Badge tone="accent">{objective.verifier_kind}</Badge>
            <span>
              funded by <span className="mono text-ink">{objective.funder}</span>
            </span>
          </>
        }
        actions={
          <button
            type="button"
            className={`btn btn-sm ${followed ? "btn-primary" : ""}`}
            aria-pressed={followed}
            title={
              followed
                ? "Stop following. This only changes this browser."
                : "Keep this page's activity live, and list it on the Overview. Stored in this browser only."
            }
            onClick={() => setFollowed(setFollowing(objective.id, !followed))}
          >
            {followed ? "Following" : "Follow"}
          </button>
        }
      />

      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Bounty" value={units(ratchet?.reward ?? objective.reward)} tone="accent" />
        {ratchet && frontier ? (
          <Stat
            label="Best score"
            value={String(frontier.score)}
            from={`${ratchet.direction} from ${ratchet.baseline} toward ${ratchet.target}`}
          />
        ) : (
          <Stat
            label="Status"
            value={objective.settled ? "Settled" : "Open"}
            from={objective.settled ? "nothing left to win" : "first accepted answer wins"}
          />
        )}
        <Stat label="Paid out" value={units(paid)} tone="accent" />
        <Stat
          label="Still payable"
          value={units(remaining)}
          tone={remaining > 0 ? "accent" : "neutral"}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="flex min-w-0 flex-col gap-4">
          {/* The statement is the funder's prose. An agent reading this page
              will act on it, so the warning travels with it rather than living
              in a footer — the same rule `/objectives` follows over HTTP. The
              title above is this statement's first sentence, so the same
              warning covers it. */}
          <Box
            title="What is being asked"
            aside={
              <span className="text-[11px] font-normal text-warn">
                written by the funder, not checked
              </span>
            }
          >
            <Statement text={objective.statement} />
          </Box>

          <Activity
            id={objective.id}
            objective={objective}
            base={base}
            live={live}
            followed={followed}
          />

          <Box
            title={objective.piecework ? "Search" : objective.settled ? "Result" : "Best answer so far"}
            aside={
              objective.piecework ? (
                <Link
                  href={`/task?id=${encodeURIComponent(objective.id)}`}
                  className="text-[11.5px] font-normal text-accent hover:underline"
                >
                  workers and progress →
                </Link>
              ) : undefined
            }
          >
            {frontier ? (
              <div className="flex flex-col gap-3">
                <dl className="kv">
                  <dt>best known</dt>
                  <dd className="mono text-[15px] font-semibold">{frontier.score}</dd>
                  <dt>held by</dt>
                  <dd className="mono">{frontier.holder}</dd>
                  <dt>claim</dt>
                  <dd>
                    <Hash value={frontier.claim_id} chars={10} />
                  </dd>
                  {ratchet && (
                    <>
                      <dt>to beat it</dt>
                      <dd>
                        improve by{" "}
                        <span className="mono">{ratchet.min_improvement}</span> and cite the
                        claim above; the citation is checked, and it is how the holder is paid
                      </dd>
                    </>
                  )}
                </dl>
                {pct !== null && <Progress value={pct / 100} label="baseline to target" />}
                <Link
                  href={`/frontier?id=${encodeURIComponent(objective.id)}`}
                  className="text-[12.5px] text-accent hover:underline"
                >
                  Every move on this objective →
                </Link>
              </div>
            ) : objective.settlement ? (
              /* A certificate never gets a frontier record; its whole story is
                 one settlement. */
              <dl className="kv">
                <dt>paid</dt>
                <dd className="mono font-semibold">{units(objective.settlement.reward)}</dd>
                <dt>to</dt>
                <dd className="mono">{objective.settlement.submitter}</dd>
                <dt>for claim</dt>
                <dd>
                  <Hash value={objective.settlement.claim_id} chars={10} />
                </dd>
              </dl>
            ) : objective.piecework ? (
              /* A divided search has no frontier to hold and no single
                 settlement: it pays per novel unit until the pool is dry. */
              <div className="flex flex-col gap-3">
                <dl className="kv">
                  <dt>pays</dt>
                  <dd className="mono">
                    {units(objective.piecework.unit_price)} per novel unit
                    {objective.piecework.units && (
                      <span className="text-ink-3">
                        {" "}
                        · divided into {units(objective.piecework.units)} units
                      </span>
                    )}
                  </dd>
                  <dt>paid so far</dt>
                  <dd className="mono font-semibold">{units(objective.piecework.paid_total)}</dd>
                  <dt>paid claims</dt>
                  <dd className="mono">{units(objective.piecework.paid_units)}</dd>
                  <dt>pool left</dt>
                  <dd className="mono">{units(objective.piecework.pool_remaining)}</dd>
                </dl>
                <Progress
                  value={objective.reward > 0 ? objective.piecework.paid_total / objective.reward : 0}
                  label="of the funded pool paid out"
                  tone="warn"
                />
              </div>
            ) : (
              <p className="text-[13px] text-ink-2">
                No accepted answer yet. The first one takes{" "}
                {ratchet ? "the first slice of the pool" : "the whole bounty"}.
              </p>
            )}
          </Box>

          {/* Only while there is something to win. */}
          {!objective.settled && (
            <WorkOnThis
              id={objective.id}
              mustCite={frontier?.must_cite}
              piecework={Boolean(objective.piecework)}
              base={base}
            />
          )}
        </div>

        <aside className="flex min-w-0 flex-col gap-4">
          <Box title="Details">
            <dl className="kv">
              <dt>objective</dt>
              <dd>
                <Hash value={objective.id} chars={10} />
              </dd>
              {objective.goal && (
                <>
                  <dt>goal</dt>
                  <dd className="mono text-[12px]">{objective.goal}</dd>
                </>
              )}
              <dt>verifier</dt>
              <dd className="mono">{objective.verifier_kind}</dd>
              {checker && (
                <>
                  <dt>pins</dt>
                  <dd className="mono text-[12px]">{checker}</dd>
                </>
              )}
              {checkerHash && (
                <>
                  <dt>checker hash</dt>
                  <dd>
                    <Hash value={checkerHash} chars={10} />
                  </dd>
                </>
              )}
              {ratchet && (
                <>
                  <dt>direction</dt>
                  <dd className="mono">{ratchet.direction}</dd>
                  <dt>baseline</dt>
                  <dd className="mono">{ratchet.baseline}</dd>
                  <dt>target</dt>
                  <dd className="mono">{ratchet.target}</dd>
                  <dt>min step</dt>
                  <dd className="mono">{ratchet.min_improvement}</dd>
                </>
              )}
              <dt>funder</dt>
              <dd className="mono">{objective.funder}</dd>
              {objective.record?.created_at && (
                <>
                  <dt>posted</dt>
                  <dd className="mono" title={objective.record.created_at}>
                    {objective.record.created_at.slice(0, 10)}
                  </dd>
                </>
              )}
            </dl>
          </Box>
          <p className="px-1 text-[11.5px] leading-relaxed text-ink-3">
            {live
              ? `Read from ${origin}.`
              : `No node answered, so this is from ${origin}, a real settled log that ships in the repository.`}
          </p>
        </aside>
      </div>
    </>
  );
}

/**
 * The statement, folded to its first lines when it is long. A full statement
 * runs to a screen of curve parameters, and above the roster it pushed the
 * part of the page people come here for below the fold.
 */
function Statement({ text: body }: { text: string }) {
  const [open, setOpen] = useState(false);
  const long = body.length > 360;
  return (
    <div>
      <p
        className={`text-[14px] leading-relaxed text-ink [overflow-wrap:anywhere] ${
          long && !open ? "line-clamp-4" : ""
        }`}
      >
        {body}
      </p>
      {long && (
        <button
          type="button"
          className="mt-2 text-[12px] text-accent hover:underline"
          onClick={() => setOpen(!open)}
        >
          {open ? "Show less" : "Read the whole statement"}
        </button>
      )}
    </div>
  );
}

/** How often a followed challenge re-reads the node. */
const FOLLOW_REFRESH_MS = 15_000;

/**
 * Who is on this challenge, and what has happened on it.
 *
 * Two sources, kept apart the way `/task` keeps them: the log says who
 * committed, answered and was paid -- recomputable by anyone -- and
 * `/progress` says which workers are heartbeating right now, which is what
 * they claim about themselves and is checked by nobody. A worker is "working
 * now" only on the second; everything else on the row is the first.
 *
 * The whole log is fetched and filtered here because the node has no
 * per-objective event route. On a large log that is the expensive part, which
 * is why it refreshes on its own only for a challenge somebody follows.
 */
function Activity({
  id,
  objective,
  base,
  live,
  followed,
}: {
  id: string;
  objective: Objective;
  base: string | null;
  live: boolean;
  followed: boolean;
}) {
  const [records, setRecords] = useState<LogRecord[] | null>(null);
  const [work, setWork] = useState<ProgressResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [all, setAll] = useState(false);
  const [now, setNow] = useState(() => Date.now());

  const refresh = useCallback(async () => {
    if (base === null) return;
    try {
      const log = await fetchLog(base);
      setRecords(log.records);
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
    // A node older than `/progress` still has a log; the roster just has no
    // "working now" column then.
    setWork(await fetchProgress(id, base).catch(() => null));
    setNow(Date.now());
  }, [base, id]);

  useEffect(() => {
    if (!live) return;
    void refresh();
    if (!followed) return;
    const timer = setInterval(() => void refresh(), FOLLOW_REFRESH_MS);
    return () => clearInterval(timer);
  }, [live, followed, refresh]);

  const index = useMemo(() => indexObjectives([objective]), [objective]);
  const events = useMemo(
    () => (records ? eventsFor(records, id, index) : []),
    [records, id, index],
  );
  const byPerson = useMemo(() => participants(events), [events]);
  const roster = useMemo(() => mergeRoster(byPerson, work), [byPerson, work]);
  const recordBySeq = useMemo(
    () => new Map((records ?? []).map((r) => [r.seq, r] as const)),
    [records],
  );
  const newest = [...events].reverse();
  const shown = all ? newest : newest.slice(0, 8);
  const workingNow = roster.filter((r) => r.status === "working").length;

  if (!live) {
    return (
      <Box title="Who is working on this">
        <p className="text-[13px] text-ink-2">
          No node answered, so there is nobody to show. Who is working on a challenge and
          what has happened on it come from a live node&rsquo;s log.
        </p>
      </Box>
    );
  }

  return (
    <>
      <Box
        title={
          <>
            Who is working on this{" "}
            <span className="mono ml-1 font-normal text-ink-3">{roster.length}</span>
          </>
        }
        aside={
          <span className="text-[11px] font-normal text-ink-3">
            {workingNow > 0 ? `${workingNow} working now` : "nobody heartbeating right now"}
          </span>
        }
        flush
      >
        {roster.length === 0 ? (
          <p className="px-4 py-6 text-[13px] text-ink-2">
            Nobody has committed an answer yet.{" "}
            {objective.settled ? null : <>Be the first: see <b>Join this challenge</b> below.</>}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[24rem] border-collapse text-left text-[12.5px]">
              <thead>
                <tr className="border-b border-edge bg-surface-2 text-ink-2">
                  <th className="px-4 py-2 font-medium">Who</th>
                  <th className="px-3 py-2 font-medium">Answers</th>
                  <th className="px-3 py-2 text-right font-medium">Paid</th>
                  <th className="px-4 py-2 text-right font-medium">Last active</th>
                </tr>
              </thead>
              <tbody className="divide-edge-y">
                {roster.map((row) => (
                  <tr key={row.name}>
                    <td className="px-4 py-2">
                      <span className="mono font-medium text-ink" title={row.name}>
                        {shortActor(row.name)}
                      </span>
                      <span className="ml-2 inline-flex flex-wrap gap-1 align-middle">
                        {row.leads && <Badge tone="accent">leading</Badge>}
                        <RosterStatus status={row.status} />
                      </span>
                      {row.device && (
                        <div className="text-[11px] text-ink-3">{row.device}</div>
                      )}
                    </td>
                    <td className="px-3 py-2 text-ink-2">
                      {row.person ? (
                        <>
                          <span className="mono">{row.person.revealed}</span> sent
                          {row.person.accepted > 0 && (
                            <span className="text-accent"> · {row.person.accepted} accepted</span>
                          )}
                          {row.person.rejected > 0 && (
                            <span className="text-bad"> · {row.person.rejected} rejected</span>
                          )}
                          {row.person.committed > row.person.revealed && (
                            <span className="text-ink-3">
                              {" "}
                              · {row.person.committed - row.person.revealed} sealed
                            </span>
                          )}
                        </>
                      ) : (
                        <span className="text-ink-3">none in the log yet</span>
                      )}
                    </td>
                    <td className="mono px-3 py-2 text-right whitespace-nowrap text-ink">
                      {row.person && row.person.paid > 0 ? units(row.person.paid) : "—"}
                    </td>
                    <td className="px-4 py-2 text-right text-ink-3 whitespace-nowrap">
                      {row.lastSeen ? ago(row.lastSeen, now) : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Box>

      <Box
        title={
          <>
            Activity <span className="mono ml-1 font-normal text-ink-3">{events.length}</span>
          </>
        }
        aside={
          <span className="text-[11px] font-normal text-ink-3">
            {followed ? "following · refreshes every 15 s" : "follow to keep this live"}
          </span>
        }
        flush
      >
        {error ? (
          <p className="px-4 py-6 text-[13px] text-bad">{error}</p>
        ) : records === null ? (
          <div className="flex flex-col gap-2 px-4 py-4">
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-4 w-1/2" />
          </div>
        ) : events.length === 0 ? (
          <p className="px-4 py-6 text-[13px] text-ink-2">Nothing has happened here yet.</p>
        ) : (
          <>
            <ul className="divide-edge-y">
              {shown.map((event) => (
                <EventRow
                  key={event.seq}
                  event={event}
                  record={recordBySeq.get(event.seq)}
                  now={now}
                />
              ))}
            </ul>
            {newest.length > shown.length || all ? (
              <div className="border-t border-edge px-4 py-2">
                <button
                  type="button"
                  className="text-[12px] text-accent hover:underline"
                  onClick={() => setAll(!all)}
                >
                  {all ? "Show the latest only" : `Show all ${newest.length} events`}
                </button>
              </div>
            ) : null}
          </>
        )}
      </Box>
    </>
  );
}

type RosterRow = {
  name: string;
  status: "working" | "quiet" | "left" | "log";
  person: Participant | null;
  device: string | null;
  leads: boolean;
  lastSeen: string | null;
};

/** The log's participants and the node's live heartbeats, joined on name. */
function mergeRoster(people: Participant[], work: ProgressResponse | null): RosterRow[] {
  const rows = new Map<string, RosterRow>();
  for (const person of people) {
    rows.set(person.name, {
      name: person.name,
      status: "log",
      person,
      device: null,
      leads: person.leads,
      lastSeen: person.lastSeen,
    });
  }
  for (const worker of work?.reported.workers ?? []) {
    const status = worker.status === "live" ? "working" : worker.status === "stale" ? "quiet" : "left";
    const row = rows.get(worker.worker);
    if (row) {
      row.status = status;
      row.device = worker.device;
      if (!row.lastSeen || worker.received_at > row.lastSeen) row.lastSeen = worker.received_at;
    } else {
      rows.set(worker.worker, {
        name: worker.worker,
        status,
        person: null,
        device: worker.device,
        leads: false,
        lastSeen: worker.received_at,
      });
    }
  }
  const rank = { working: 0, quiet: 1, log: 2, left: 3 };
  return [...rows.values()].sort(
    (a, b) => rank[a.status] - rank[b.status] || (b.lastSeen ?? "").localeCompare(a.lastSeen ?? ""),
  );
}

function RosterStatus({ status }: { status: RosterRow["status"] }) {
  switch (status) {
    case "working":
      return <Badge tone="accent" title="Heartbeating to this node now. Self-reported.">working now</Badge>;
    case "quiet":
      return <Badge tone="warn" title="Has not heartbeated for a few minutes.">quiet</Badge>;
    case "left":
      return <Badge title="Stopped heartbeating.">stopped</Badge>;
    default:
      // Known only from the log: nothing to add beside the name.
      return null;
  }
}

/** A verifier field, if it is a string. The record's shape is the funder's. */
function text(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined;
}

/**
 * How to submit, as two tabs rather than two side-by-side cards of prose.
 *
 * The terminal comes first: it is the one that needs nothing configured.
 */
function WorkOnThis({
  id,
  mustCite,
  piecework,
  base,
}: {
  id: string;
  mustCite: string | undefined;
  piecework: boolean;
  base: string | null;
}) {
  const [tab, setTab] = useState<"worker" | "cli" | "mcp">(piecework ? "worker" : "cli");
  // Inside Cairn.app the worker and the agent are a button each: the app
  // runs `cairn work` and writes the agent's stanza, so the page has no
  // reason to hand either to a terminal the window does not have.
  const [bridge, setBridge] = useState<Bridge | null>(null);
  const [appError, setAppError] = useState<string | null>(null);
  useEffect(() => setBridge(appBridge()), []);
  const node = base || (typeof window !== "undefined" ? window.location.origin : "");
  const cli = cliCalls(id, mustCite);
  const calls = mcpCalls(id, mustCite);

  function ask(sheet: "work" | "agents") {
    if (!bridge) return;
    setAppError(null);
    openSheet(bridge, sheet, sheet === "work" ? id : undefined).catch((cause: unknown) => {
      setAppError(cause instanceof Error ? cause.message : String(cause));
    });
  }

  return (
    <Box
      title="Join this challenge"
      aside={
        <span className="hidden text-[11px] font-normal text-ink-3 sm:inline">
          nobody assigns you: anyone may work it, and the checker decides who is paid
        </span>
      }
      flush
    >
      <ol className="flex flex-col gap-1 border-b border-edge px-4 py-3 text-[12.5px] text-ink-2">
        <li>
          <b className="text-ink">1. Score it locally.</b> Free, records nothing, and runs the
          same checker that decides payment.
        </li>
        <li>
          <b className="text-ink">2. Commit.</b> Seals your answer in this epoch so nobody can
          copy it before you reveal.
        </li>
        <li>
          <b className="text-ink">3. Reveal.</b> After the epoch turns. You are paid when that
          epoch settles.
        </li>
      </ol>
      <div className="tabs" role="tablist">
        <button
          type="button"
          role="tab"
          aria-selected={tab === "worker"}
          className="tab"
          onClick={() => setTab("worker")}
        >
          Run a machine
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === "cli"}
          className="tab"
          onClick={() => setTab("cli")}
        >
          Terminal
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === "mcp"}
          className="tab"
          onClick={() => setTab("mcp")}
        >
          Agent over MCP
        </button>
      </div>
      <div className="box-body flex flex-col gap-3">
        {tab === "worker" ? (
          <>
            <p className="text-[12.5px] text-ink-2">
              Put a machine on this challenge with your own solver. Each round it gets its slice
              of the work on stdin and prints candidate answers, one JSON object per line;{" "}
              <span className="mono">cairn work</span> commits them, reveals them after the epoch
              turns, cites the best answer when there is one, and reports in so the machine shows
              above as <i>working now</i>. Run one per machine, each with its own name.
              {piecework && (
                <>
                  {" "}
                  This is a divided search, so machines with different names take different
                  slices.
                </>
              )}
            </p>
            {bridge ? (
              <>
                <div>
                  <button type="button" className="btn btn-primary btn-sm" onClick={() => ask("work")}>
                    Work on this Mac…
                  </button>
                </div>
                <details className="text-[12.5px] text-ink-2">
                  <summary className="cursor-pointer text-ink-3">
                    On another machine without Cairn.app
                  </summary>
                  <div className="mt-2">
                    <CodeBlock value={workCommand({ node, objective: id, worker: "" })} />
                  </div>
                </details>
              </>
            ) : (
              <CodeBlock value={workCommand({ node, objective: id, worker: "" })} />
            )}
            {appError && <p className="text-[12px] text-warn">{appError}</p>}
            <p className="text-[12px] text-ink-3">
              Another machine on your network needs this node shared there first:{" "}
              <Link href="/contribute" className="text-accent hover:underline">
                Contribute
              </Link>{" "}
              has the address and the steps.
            </p>
          </>
        ) : tab === "cli" ? (
          <>
            <p className="text-[12.5px] text-ink-2">
              <span className="mono">try</span> scores without touching the log. Then commit,
              wait for the epoch to turn, and reveal.
            </p>
            <CodeBlock value={cli} />
          </>
        ) : (
          <>
            <p className="text-[12.5px] text-ink-2">
              Add the stanza to Claude Code, Codex or OpenCode, then run{" "}
              <span className="mono">get_objective → score_candidate → submit_claim</span>.{" "}
              The developer documentation has the other clients&rsquo; spellings.
            </p>
            {bridge ? (
              <>
                <div>
                  <button type="button" className="btn btn-primary btn-sm" onClick={() => ask("agents")}>
                    Connect an agent…
                  </button>
                  <span className="ml-2 text-[12px] text-ink-3">
                    Cairn.app writes the stanza with this Mac&rsquo;s real paths.
                  </span>
                </div>
                {appError && <p className="text-[12px] text-warn">{appError}</p>}
              </>
            ) : (
              <CodeBlock value={MCP_STANZA} />
            )}
            <CodeBlock value={calls} />
          </>
        )}
      </div>
    </Box>
  );
}

function CodeBlock({ value }: { value: string }) {
  return (
    <div className="relative">
      <pre className="code pr-9 text-[11.5px]">{value}</pre>
      <div className="absolute top-2 right-2">
        <CopyButton value={value} />
      </div>
    </div>
  );
}
