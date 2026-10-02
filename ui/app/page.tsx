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
  repoLink,
  short,
  units,
} from "@/lib/site";
import {
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

  useEffect(() => {
    // Independently, so a slow `/log`-sized answer on one does not hold the
    // others, and a failure on one is that one's fallback and nobody else's.
    void loadObjectives().then(setFeed);
    void loadChain().then(setChain);
    void loadCheckpoint().then(setCheckpoint);
  }, []);

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
          On a phone, Add to Home Screen, or use the native reader in{" "}
          <a className="text-accent hover:underline" href={repoLink("gui/ios/")}>
            gui/ios
          </a>
          .
        </p>
      </section>

      <div className="app-only">
        <PageHeader title="Overview" subtitle={objectivesFrom} />
      </div>

      <div className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <Stat label="Objectives" value={String(objectives.length)} from={objectivesFrom} />
        <Stat
          label="Open"
          value={String(open.length)}
          from={open.length ? "worth working on" : "all settled"}
          tone={open.length ? "accent" : "neutral"}
        />
        <Stat label="Pool" value={units(pool)} from="funded, all time" tone="violet" />
        <Stat label="Paid out" value={units(paid)} from="to accepted claims" tone="info" />
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
                      className="group flex items-center gap-4 px-4 py-3 transition-colors hover:bg-surface-2"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="truncate font-semibold text-ink group-hover:text-accent">
                            {o.goal || short(o.id)}
                          </span>
                          <StatusPill settled={o.settled} />
                        </div>
                        {/* Quoted and dimmed: the funder wrote it, and the
                            objective's own page carries it under its
                            "not checked" label. */}
                        <p
                          className="mt-0.5 truncate text-[12.5px] text-ink-3"
                          title={`Funder's statement, not checked: ${o.statement}`}
                        >
                          &ldquo;{o.statement}&rdquo;
                        </p>
                      </div>
                      <div className="hidden w-32 shrink-0 sm:block">
                        {pct !== null ? (
                          <Progress value={pct / 100} />
                        ) : (
                          <span className="text-[12px] text-ink-3">
                            {o.frontier
                              ? `best ${o.frontier.score}`
                              : o.settlement
                                ? `paid to ${o.settlement.submitter}`
                                : "no claim yet"}
                          </span>
                        )}
                      </div>
                      <span className="mono w-24 shrink-0 text-right text-ink">{units(o.reward)}</span>
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
          <details className="mt-3 text-[12.5px]">
            <summary className="cursor-pointer text-accent">Re-derive it yourself</summary>
            <p className="mt-2 text-ink-2">
              Every settlement recomputed from the records, each batch checked against
              the anchor it recorded:
            </p>
            <pre className="code mt-2 text-[11.5px]">{`git clone ${REPO}
cd cairn
cairn --log launch/cairn.jsonl --root . audit`}</pre>
          </details>
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
              One stdio MCP server, live on the network.{" "}
              <a className="text-accent hover:underline" href={repoLink("docs/agents.md")}>
                agents.md
              </a>{" "}
              has the config stanza for each client.
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
              Loopback by default; pass a bootstrap file to join peers.{" "}
              <a className="text-accent hover:underline" href={repoLink("docs/serving.md")}>
                serving.md
              </a>{" "}
              and{" "}
              <a className="text-accent hover:underline" href={repoLink("docs/p2p.md")}>
                p2p.md
              </a>
              .
            </p>
          </Card>
        </ul>
      </section>

      <p className="site-only prose-block mt-8 text-[13px]">
        A second implementation in{" "}
        <a href={repoLink("reference/rust/")}>
          <code className="mono">reference/rust/</code>
        </a>{" "}
        re-derives the same log independently, and{" "}
        <a href={repoLink("conformance/README.md")}>448 frozen conformance vectors</a>{" "}
        pin the byte encoding both must agree on. That is what &ldquo;verified&rdquo; is
        doing in the first sentence on this page.
      </p>
    </>
  );
}
