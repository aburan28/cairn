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
import { Badge, Card, Hash, Note, Progress, SectionHeading, Stat } from "@/components/ui";

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
      <section className="mb-10 max-w-[62rem]">
        <h1 className="text-[clamp(1.6rem,4vw,2.35rem)] leading-[1.15] font-semibold">
          A research network where{" "}
          <span className="text-accent">verified results</span> are the unit of
          account.
        </h1>
        <p className="prose-block mt-4 text-[15px]">
          Post a question with a pinned checker and a bounty. Anyone who moves the
          answer forward is paid in proportion to how far they moved it, and every
          payment is re-derivable from the log by anyone who has a copy of it.
        </p>
        <p className="prose-block mt-3">
          A cairn is a marker each traveller adds a stone to, and the pile is the
          record of the route. An improvement must cite the result it beat, so
          attribution is a rule rather than an etiquette — and the citation pays.{" "}
          <Link href="/how-it-works">How it works</Link>.
        </p>

        <div className="mt-6 flex flex-wrap gap-2">
          <Link href="/submit" className="btn btn-primary">
            Post a challenge
          </Link>
          <Link href="/objectives" className="btn">
            Browse objectives
          </Link>
        </div>
      </section>

      <Card className="card-pad mb-8">
        <div className="note-title">install</div>
        <pre className="code mt-1">
          {`curl -fsSL ${REPO}/releases/latest/download/install.sh | sh`}
        </pre>
        <p className="hint">
          Linux and macOS, amd64 and arm64. Checks the tarball against its published
          sha256 — which detects a corrupted download and nothing more, because both
          files come from the same server. The check that means something is the one
          at the bottom of this page.
        </p>
        <p className="hint">
          On a phone, Add to Home Screen — this reader is a standalone web app,
          same pages, no service worker — or the native reader in{" "}
          <a className="text-accent hover:underline" href={repoLink("gui/ios/")}>
            gui/ios
          </a>
          . Neither runs a node; both read one.
        </p>
      </Card>

      <div className="mb-8 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <Stat label="objectives" value={String(objectives.length)} from={objectivesFrom} />
        <Stat label="open" value={String(open.length)} from={objectivesFrom} />
        <Stat label="pool" value={units(pool)} from={objectivesFrom} />
        <Stat label="paid out" value={units(paid)} from={objectivesFrom} />
        <Stat label="chain links" value={String(links)} from={chainFrom} />
      </div>

      {/* A node that answered in a shape this page does not read, or that
          answered `/objectives` and has no checkpoint. Said here rather than
          folded silently into the fallback, because the first is a bug and the
          second is the reason the panel below is labelled. */}
      {notes.length > 0 && (
        <div className="mb-8">
          <Note title="showing the snapshot for part of this page" tone="warn">
            {notes.map((note) => (
              <div key={note}>{note}</div>
            ))}
          </Note>
        </div>
      )}

      <section className="mb-12">
        <SectionHeading
          count={objectives.length}
          aside={
            <Link href="/objectives" className="text-[12.5px] text-accent hover:underline">
              all objectives →
            </Link>
          }
        >
          Challenges
        </SectionHeading>

        {objectives.length === 0 ? (
          <p className="py-8 text-ink-3">No objectives yet.</p>
        ) : (
          <ul className="grid gap-3 md:grid-cols-2">
            {objectives.map((o) => {
              const ratchet = o.record?.ratchet ?? null;
              const pct = ratchet && o.frontier ? progress(o.frontier.score, ratchet) : null;
              return (
                <Card as="li" key={o.id} className="card-pad flex flex-col gap-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <Link
                      href={`/challenge?id=${encodeURIComponent(o.id)}`}
                      className="text-[14px] font-semibold text-ink hover:text-accent"
                    >
                      {o.goal || short(o.id)}
                    </Link>
                    <Badge tone={o.settled ? "neutral" : "accent"}>
                      {o.settled ? "settled" : "open"}
                    </Badge>
                    <Badge tone="info">{o.verifier_kind}</Badge>
                  </div>

                  {/* Labelled untrusted wherever it is shown. The funder wrote
                      it, and an agent reading this page has no other warning. */}
                  <p className="text-[13px] leading-relaxed text-ink-2">
                    <span className="text-ink-3">statement (untrusted): </span>
                    {o.statement.slice(0, 160)}
                    {o.statement.length > 160 ? "…" : ""}
                  </p>

                  <div className="mt-auto flex flex-wrap items-center gap-x-3 gap-y-1 text-[12.5px] text-ink-2">
                    <span>
                      pool <span className="mono text-ink">{units(o.reward)}</span>
                    </span>
                    {o.frontier ? (
                      <>
                        <Link
                          href={`/frontier?id=${encodeURIComponent(o.id)}`}
                          className="text-accent hover:underline"
                        >
                          best <span className="mono">{o.frontier.score}</span>
                        </Link>
                        <span className="flex items-center gap-1 text-ink-3">
                          held by <Hash value={o.frontier.holder} chars={6} />
                        </span>
                      </>
                    ) : o.settlement ? (
                      <span className="flex flex-wrap items-center gap-1 text-ink-3">
                        settled — <span className="mono text-ink">{units(o.settlement.reward)}</span>{" "}
                        paid to <Hash value={o.settlement.submitter} chars={6} /> for claim{" "}
                        <Hash value={o.settlement.claim_id} chars={6} />
                      </span>
                    ) : (
                      <span className="text-ink-3">no claim yet</span>
                    )}
                  </div>

                  {pct !== null && (
                    <Progress value={pct / 100} label="frontier across the span" />
                  )}
                </Card>
              );
            })}
          </ul>
        )}
      </section>

      <section className="mb-12">
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

      <section>
        <SectionHeading>Check it before you trust it</SectionHeading>
        <p className="prose-block mb-4">
          Every number above says where it came from: a node that answered, or{" "}
          {SNAPSHOT.source} — a real settled log that ships in the repository, not a
          mock. Either way, re-derive it yourself. This recomputes every settlement
          from the records and checks each batch against the anchor it recorded:
        </p>
        <Card className="card-pad">
          <pre className="code">{`git clone ${REPO}
cd cairn
cairn --log launch/cairn.jsonl --root . audit`}</pre>
          <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-[12.5px] text-ink-2">
            <span className="flex items-center gap-1">
              merkle root <Hash value={signed.root} chars={10} />
            </span>
            <span>signed at height {signed.height}</span>
            <span className="mono">{signed.issued_at}</span>
            <span className="flex items-center gap-1">
              by <Hash value={signed.public_key} chars={8} />
            </span>
          </div>
          {/* The label is the point of the panel. A live node's root and the
              bundled log's signature are different facts, and the sentence that
              says which this is must sit beside the number, not three
              paragraphs up. */}
          <p className="hint">
            {checkpointFrom}
            {checkpoint?.live && (
              <>
                {" "}
                — the command above audits the bundled log; this node&rsquo;s own log
                is at <Link href="/log" className="text-accent hover:underline">/log</Link>{" "}
                and its chain at{" "}
                <Link href="/chain" className="text-accent hover:underline">/chain</Link>.
              </>
            )}
          </p>
        </Card>
        <p className="prose-block mt-4 text-[13px]">
          A second implementation in{" "}
          <a href={repoLink("reference/rust/")}>
            <code className="mono">reference/rust/</code>
          </a>{" "}
          re-derives the same log independently, and{" "}
          <a href={repoLink("conformance/README.md")}>448 frozen conformance vectors</a>{" "}
          pin the byte encoding both must agree on. That is what &ldquo;verified&rdquo;
          is doing in the first sentence on this page —{" "}
          <Link href="/how-it-works">the long version</Link>.
        </p>
      </section>
    </>
  );
}
