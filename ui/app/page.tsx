"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  type ChainFacts,
  type CheckpointFacts,
  type Feed,
  type Sourced,
  REPO,
  SNAPSHOT,
  loadChain,
  loadCheckpoint,
  loadObjectives,
  progress,
  provenance,
  short,
  units,
} from "@/lib/site";
import { type LogRecord, fetchLog } from "@/lib/log";
import { type LogEvent, eventsFor, indexObjectives } from "@/lib/events";
import { following, onFollowingChange } from "@/lib/follow";
import { goalSlug, objectiveTitle } from "@/lib/title";
import { EventRow } from "@/components/events";
import { useNode } from "@/components/hooks";
import { type NetworkResponse, fetchNetwork, primaryRole } from "@/lib/network";
import {
  Badge,
  Box,
  Card,
  CopyButton,
  Hash,
  Note,
  PageHeader,
  Progress,
  SectionHeading,
  Stat,
  StatusPill,
} from "@/components/ui";

/**
 * The landing page.
 *
 * A client component, like every page here, because the numbers on it come from
 * a node at read time rather than from a build. That is the whole difference
 * between this and a marketing page: nothing here is typed in, and the command
 * that re-derives all of it is printed underneath.
 *
 * Three requests, not one, and each falls back on its own. The stats come from
 * `/objectives`, the link count from `/chain`, the merkle root from
 * `/checkpoint` — and a node can answer the first and not the third, because
 * `cairn checkpoint` is a thing an operator chooses to run. So every stat and
 * the checkpoint panel say where they came from.
 */
export default function Page() {
  const [feed, setFeed] = useState<Feed | null>(null);
  const [chain, setChain] = useState<Sourced<ChainFacts> | null>(null);
  const [checkpoint, setCheckpoint] = useState<Sourced<CheckpointFacts> | null>(null);
  const [followed, setFollowed] = useState<string[]>([]);
  const [records, setRecords] = useState<LogRecord[] | null>(null);

  useEffect(() => {
    // Independently, so a slow `/log`-sized answer on one does not hold the
    // others, and a failure on one is that one's fallback and nobody else's.
    void loadObjectives().then(setFeed);
    void loadChain().then(setChain);
    void loadCheckpoint().then(setCheckpoint);
    setFollowed(following());
    return onFollowingChange(() => setFollowed(following()));
  }, []);

  // The log only when somebody follows something: it is the one fetch here
  // whose size grows with the network's history.
  useEffect(() => {
    if (!feed?.live || followed.length === 0) return;
    void fetchLog().then((log) => setRecords(log.records)).catch(() => setRecords(null));
  }, [feed, followed.length]);

  const objectives = feed?.objectives ?? SNAPSHOT.objectives;
  // `open` is the node's field, not `!settled` computed here: the node is the
  // one place the rule lives, and for a while `settled` meant "a settlement
  // record exists", which a ratchet satisfies from its first paid slice.
  const open = objectives.filter((o) => o.open);
  const pool = objectives.reduce((sum, o) => sum + o.reward, 0);
  // A ratchet's payouts are summed in its frontier and its `settlement` is
  // null; a certificate has no frontier and one `settlement`. Adding both
  // therefore never counts a payment twice, and leaving either out did.
  const paid = objectives.reduce(
    (sum, o) => sum + (o.frontier?.paid_cumulative ?? 0) + (o.settlement?.reward ?? 0),
    0,
  );

  // While a request is in flight the page shows the snapshot, and says
  // "reading…" rather than labelling it as the snapshot: the label is a claim
  // about where a number came from, and until the node answers or fails that
  // claim is not yet true.
  const objectivesFrom = feed ? provenance(feed) : "reading…";
  const chainFrom = chain ? provenance(chain) : "reading…";
  const checkpointFrom = checkpoint ? provenance(checkpoint) : "reading…";
  const links = chain?.value.links ?? SNAPSHOT.chain.links;
  const signed = checkpoint?.value ?? SNAPSHOT.checkpoint;

  const followedObjectives = feed?.live ? objectives.filter((o) => followed.includes(o.id)) : [];
  const followIndex = indexObjectives(followedObjectives);
  const recent: Array<{ event: LogEvent; title: string }> = records
    ? followedObjectives
        .flatMap((o) =>
          eventsFor(records, o.id, followIndex).map((event) => ({ event, title: objectiveTitle(o) })),
        )
        .sort((a, b) => b.event.seq - a.event.seq)
        .slice(0, 6)
    : [];
  const now = Date.now();

  const notes = [feed?.warning, chain?.note, checkpoint?.note].filter(
    (note): note is string => typeof note === "string",
  );

  return (
    <>
      {/* The pitch is for a visitor to the public site. Inside Cairn.app the
          reader already installed it, and the page opens on the numbers. */}
      <section className="site-only mb-8 max-w-[62rem]">
        <h1 className="text-[clamp(1.5rem,3.2vw,2rem)] leading-[1.15] font-semibold">
          A research network where{" "}
          <span className="text-accent">verified results</span> are the unit of
          account.
        </h1>
        <p className="prose-block mt-3 text-[15px]">
          Post a question with a pinned checker and a bounty. Anyone who moves the
          answer forward is paid in proportion to how far they moved it, and every
          payment is re-derivable from the log by anyone who has a copy of it.{" "}
          <Link href="/how-it-works">How it works</Link>.
        </p>
        <div className="mt-5 flex flex-wrap items-center gap-2">
          <Link href="/submit" className="btn btn-primary">
            Post a challenge
          </Link>
          <Link href="/objectives" className="btn">
            Browse objectives
          </Link>
        </div>
        <div className="relative mt-5 max-w-[46rem]">
          <pre className="code pr-9">
            {`curl -fsSL ${REPO}/releases/latest/download/install.sh | sh`}
          </pre>
          <div className="absolute top-2 right-2">
            <CopyButton value={`curl -fsSL ${REPO}/releases/latest/download/install.sh | sh`} />
          </div>
        </div>
        <p className="hint max-w-[46rem]">
          Linux and macOS, amd64 and arm64. The download&rsquo;s sha256 only catches
          corruption; the check that means something is re-deriving the log, below.
          On a phone, Add to Home Screen or use the native reader.
        </p>
      </section>

      <div className="app-only">
        <PageHeader title="Overview" subtitle={objectivesFrom} />
      </div>

      <YourNode />

      <div className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5">
        <Stat label="Objectives" value={String(objectives.length)} from={objectivesFrom} />
        <Stat
          label="Open"
          value={String(open.length)}
          from={open.length ? "worth working on" : "all settled"}
        />
        <Stat label="Pool" value={units(pool)} from="funded, all time" tone="accent" />
        <Stat label="Paid out" value={units(paid)} from="to accepted claims" tone="accent" />
        <Stat label="Chain links" value={String(links)} from={chainFrom} tone="warn" />
      </div>

      {/* A node that answered in a shape this page does not read, or that
          answered `/objectives` and has no checkpoint. Said here rather than
          folded silently into the fallback, because the first is a bug and the
          second is the reason the panel below is labelled. */}
      {notes.length > 0 && (
        <div className="mb-5">
          <Note title="showing the snapshot for part of this page" tone="warn">
            {notes.map((note) => (
              <div key={note}>{note}</div>
            ))}
          </Note>
        </div>
      )}

      {followedObjectives.length > 0 && (
        <Box
          className="mb-4"
          title={
            <>
              Following{" "}
              <span className="mono ml-1 font-normal text-ink-3">{followedObjectives.length}</span>
            </>
          }
          aside={<span className="text-[11px] font-normal text-ink-3">latest on the challenges you follow</span>}
          flush
        >
          {recent.length === 0 ? (
            <p className="px-4 py-4 text-[13px] text-ink-2">Nothing has happened on them yet.</p>
          ) : (
            <ul className="divide-edge-y">
              {recent.map(({ event, title }) => (
                <EventRow key={event.seq} event={event} objectiveTitle={title} now={now} />
              ))}
            </ul>
          )}
        </Box>
      )}

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_22rem]">
        <Box
          title={
            <>
              Challenges <span className="mono ml-1 font-normal text-ink-3">{objectives.length}</span>
            </>
          }
          aside={
            <Link href="/objectives" className="text-[12px] font-normal text-accent hover:underline">
              All objectives →
            </Link>
          }
          flush
        >
          {objectives.length === 0 ? (
            <p className="px-4 py-8 text-center text-ink-3">No objectives yet.</p>
          ) : (
            <ul className="divide-edge-y">
              {objectives.map((o) => {
                const ratchet = o.record?.ratchet ?? null;
                const pct = ratchet && o.frontier ? progress(o.frontier.score, ratchet) : null;
                return (
                  <li key={o.id}>
                    <Link
                      href={`/challenge?id=${encodeURIComponent(o.id)}`}
                      className="group flex items-start gap-4 px-4 py-3 transition-colors hover:bg-surface-2"
                      title={`Funder's statement, not checked: ${o.statement}`}
                    >
                      <div className="min-w-0 flex-1">
                        {/* The title is the statement's first sentence: the
                            funder's words, which the challenge page labels as
                            unchecked. The slug stays beside it as an id. */}
                        <div className="line-clamp-2 font-medium text-ink [overflow-wrap:anywhere] group-hover:underline">
                          {objectiveTitle(o)}
                        </div>
                        <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-[12px] text-ink-3">
                          <StatusPill settled={o.settled} />
                          {goalSlug(o.goal) && <span className="mono">{goalSlug(o.goal)}</span>}
                          <span aria-hidden>·</span>
                          <span>
                            {o.frontier
                              ? `best ${o.frontier.score}`
                              : o.settlement
                                ? `paid to ${o.settlement.submitter}`
                                : o.piecework
                                  ? `${units(o.piecework.paid_units)} claims paid`
                                  : "no answer yet"}
                          </span>
                          {followed.includes(o.id) && <Badge>following</Badge>}
                        </div>
                        {pct !== null && (
                          <div className="mt-2 max-w-64">
                            <Progress value={pct / 100} />
                          </div>
                        )}
                      </div>
                      <div className="shrink-0 text-right">
                        <div className="mono text-ink">{units(o.reward)}</div>
                        <div className="text-[11px] text-ink-3">bounty</div>
                      </div>
                    </Link>
                  </li>
                );
              })}
            </ul>
          )}
        </Box>

        <Box title="Checkpoint" className="self-start">
          <dl className="kv">
            <dt>merkle root</dt>
            <dd>
              <Hash value={signed.root} chars={8} />
            </dd>
            <dt>height</dt>
            <dd className="mono">{signed.height}</dd>
            <dt>signed</dt>
            <dd className="mono text-[12px]">{signed.issued_at.replace("T", " ").slice(0, 16)}</dd>
            <dt>by</dt>
            <dd>
              <Hash value={signed.public_key} chars={8} />
            </dd>
          </dl>
          {/* The label is the point of the panel. A live node's root and the
              bundled log's signature are different facts, and the sentence that
              says which this is must sit beside the number. */}
          <p className="mt-3 text-[11.5px] leading-relaxed text-ink-3">{checkpointFrom}</p>
          <p className="mt-3 text-[12.5px] text-ink-2">
            Each settlement can be independently checked against the recorded log.
          </p>
        </Box>
      </div>

      <section className="site-only mt-10">
        <SectionHeading>Three ways in</SectionHeading>
        {/* The three roles the protocol actually has, with the one command each
            starts from. Anything longer belongs on /how-it-works or in the
            repository — a landing page that tries to be the manual stops being
            readable and starts going stale. */}
        <ul className="grid gap-3 lg:grid-cols-3">
          <Card as="li" className="card-pad flex flex-col gap-2">
            <h3 className="text-[14px] font-semibold">Fund a question</h3>
            <p className="text-[13px] leading-relaxed text-ink-2">
              Scaffold an objective, pin a checker by hash, attach a bounty. The rules
              of a funded bounty cannot be changed afterwards — editing the checker
              posts a <i>different</i> objective, and claims against the original stop
              resolving.
            </p>
            <pre className="code mt-auto">cairn scaffold my-challenge --kind certificate</pre>
            <p className="hint">
              Or <Link href="/submit" className="text-accent hover:underline">post one from
              this page</Link>, signed by a wallet.
            </p>
          </Card>
          <Card as="li" className="card-pad flex flex-col gap-2">
            <h3 className="text-[14px] font-semibold">Solve one</h3>
            <p className="text-[13px] leading-relaxed text-ink-2">
              Point an agent at a node over MCP — Claude Code, Codex and OpenCode all
              speak it, so it is one integration rather than three. Scoring a candidate
              is free and runs the same pinned verifier that decides payment, so every
              objective is an eval with a ground-truth reward signal.
            </p>
            <pre className="code mt-auto">cairn run</pre>
            <p className="hint">
              One stdio MCP server, live on the network. Agent setup is available
              in the project's developer documentation.
            </p>
          </Card>
          <Card as="li" className="card-pad flex flex-col gap-2">
            <h3 className="text-[14px] font-semibold">Run a node</h3>
            <p className="text-[13px] leading-relaxed text-ink-2">
              One process serves MCP, syncs with peers, serves the log over HTTP with
              this reader, and admits what arrives — because it is the process holding
              the write lock. Readers fetch the log and re-derive everything themselves,
              which is the point: they need not trust the server that served it.
            </p>
            <pre className="code mt-auto">cairn run</pre>
            <p className="hint">
              Loopback by default; add a peer to join the network.
            </p>
          </Card>
        </ul>
      </section>

      <p className="site-only prose-block mt-8 text-[13px]">
        A second implementation re-derives the same log independently, and{" "}
        448 frozen conformance vectors{" "}
        pin the byte encoding both must agree on. That is what &ldquo;verified&rdquo; is
        doing in the first sentence on this page.
      </p>
    </>
  );
}

/**
 * The node serving this page, in one line: what it is and what is connected
 * to it. Only when the page *is* served by a node (same-origin): on the public
 * site the reader may be talking to somebody's seed, and calling that "your
 * node" would be a claim about the visitor that is false.
 */
function YourNode() {
  const base = useNode();
  const [network, setNetwork] = useState<NetworkResponse | null>(null);
  useEffect(() => {
    if (base !== "") return;
    fetchNetwork(base)
      .then(setNetwork)
      .catch(() => setNetwork(null));
  }, [base]);
  if (!network) return null;
  const role = primaryRole(network.node);
  const mcp = network.node.mcp;
  const agent = mcp?.serving && mcp.client ? mcp.client.name : "none attached";
  const hosts = network.compute.hosts?.registered ?? 0;
  return (
    <Link
      href="/network"
      className="card card-pad mb-5 flex flex-wrap items-center gap-x-8 gap-y-3 transition-colors hover:border-edge-strong hover:bg-surface-2"
    >
      <div>
        <div className="text-[11px] font-semibold tracking-[0.08em] text-ink-3 uppercase">Your node</div>
        <div className="flex items-center gap-2 text-[20px] font-semibold text-ink">
          <span className="h-2 w-2 rounded-full bg-accent" aria-hidden />
          {role.title}
        </div>
      </div>
      <NodeFact label="Agent" value={agent} />
      <NodeFact
        label="Machines working"
        value={String(network.compute.live)}
        hint={hosts > 0 ? `${hosts} registered with it` : undefined}
      />
      <NodeFact label="Other nodes connected" value={network.peers.available ? String(network.peers.reached) : "not syncing"} />
      <span className="ml-auto text-[12.5px] text-accent">Network →</span>
    </Link>
  );
}

function NodeFact({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="min-w-0">
      <div className="text-[11.5px] text-ink-3">{label}</div>
      <div className="truncate text-[14px] font-medium text-ink">{value}</div>
      {hint && <div className="text-[11px] text-ink-3">{hint}</div>}
    </div>
  );
}
