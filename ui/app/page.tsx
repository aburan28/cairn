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
 * the checkpoint panel say where they came from. Before this, one sentence said
 * "the numbers above came from <node>" while the link count and the root beside
 * it always came from the snapshot.
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
  const open = objectives.filter((o) => !o.settled);
  const pool = objectives.reduce((sum, o) => sum + o.reward, 0);
  const paid = objectives.reduce((sum, o) => sum + (o.frontier?.paid_cumulative ?? 0), 0);

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
    <main>
      <h1>cairn</h1>
      <p className="lede">
        A research network where <b>verified results are the unit of account</b>.
        Post a question with a pinned checker and a bounty; anyone who moves the
        answer forward is paid in proportion to how far they moved it, and every
        payment is re-derivable from the log by anyone who has it.
      </p>
      <p className="lede">
        A cairn is a marker each traveller adds a stone to, and the pile is the
        record of the route. An improvement must cite the result it beat, so
        attribution is a rule rather than an etiquette — and the citation pays.{" "}
        <Link href="/how-it-works">How it works</Link>.
      </p>

      <div className="panel">
        <b>install</b>
        <pre>{`curl -fsSL ${REPO}/releases/latest/download/install.sh | sh`}</pre>
        <div className="meta dim">
          Linux and macOS, amd64 and arm64. Checks the tarball against its
          published sha256 — which detects a corrupted download and nothing
          more, because both files come from the same server. The check that
          means something is the one below.
        </div>
      </div>

      <div className="row stats">
        <Stat label="objectives" value={String(objectives.length)} from={objectivesFrom} />
        <Stat label="open" value={String(open.length)} from={objectivesFrom} />
        <Stat label="pool" value={units(pool)} from={objectivesFrom} />
        <Stat label="paid out" value={units(paid)} from={objectivesFrom} />
        <Stat label="chain links" value={String(links)} from={chainFrom} />
      </div>

      {/* A node that answered in a shape this page does not read, or that
          answered `/objectives` and has no checkpoint. Said here rather than
          folded silently into the fallback, because the first is a bug and
          the second is the reason the panel below is labelled. */}
      {notes.length > 0 && (
        <div className="panel">
          <b>showing the snapshot for part of this page</b>
          {notes.map((note) => (
            <div className="meta" key={note}>
              {note}
            </div>
          ))}
        </div>
      )}

      <h2>challenges</h2>
      {objectives.length === 0 ? (
        <p className="empty">No objectives yet.</p>
      ) : (
        <ul className="cards">
          {objectives.map((o) => {
            const ratchet = o.record?.ratchet ?? null;
            const pct =
              ratchet && o.frontier ? progress(o.frontier.score, ratchet) : null;
            return (
              <li key={o.id} className="card">
                <div>
                  <Link href={`/challenge?id=${encodeURIComponent(o.id)}`}>
                    <b>{o.goal || short(o.id)}</b>
                  </Link>{" "}
                  <span className={o.settled ? "tag" : "tag open"}>
                    {o.settled ? "settled" : "open"}
                  </span>{" "}
                  <span className="tag">{o.verifier_kind}</span>
                </div>
                <div className="meta">
                  {/* Labelled untrusted wherever it is shown. The funder wrote
                      it, and an agent reading this page has no other warning. */}
                  <span className="dim">statement (untrusted): </span>
                  {o.statement.slice(0, 150)}
                  {o.statement.length > 150 ? "…" : ""}
                </div>
                <div className="meta">
                  pool <code>{units(o.reward)}</code>
                  {o.frontier ? (
                    <>
                      {" · "}
                      <Link href={`/frontier?id=${encodeURIComponent(o.id)}`}>
                        best <code className="accent">{o.frontier.score}</code>
                      </Link>
                      {" held by "}
                      <code>{o.frontier.holder}</code>
                      {pct !== null && (
                        <span className="bar" aria-label={`${pct}% of the span`}>
                          <span style={{ width: `${pct}%` }} />
                        </span>
                      )}
                    </>
                  ) : (
                    <span className="dim"> · no claim yet</span>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}

      <h2>three ways in</h2>
      {/* The three roles the protocol actually has, with the one command each
          starts from. Anything longer belongs on /how-it-works or in the
          repository -- a landing page that tries to be the manual stops being
          readable and starts going stale. */}
      <ul className="cards ways">
        <li className="card">
          <b>fund a question</b>
          <div className="meta">
            Scaffold an objective, pin a checker by hash, attach a bounty. The
            rules of a funded bounty cannot be changed afterwards — editing the
            checker posts a <i>different</i> objective, and claims against the
            original stop resolving.
          </div>
          <pre>cairn scaffold my-challenge --kind certificate</pre>
        </li>
        <li className="card">
          <b>solve one</b>
          <div className="meta">
            Point an agent at a node over MCP — Claude Code, Codex and OpenCode
            all speak it, so it is one integration rather than three. Scoring a
            candidate is free and runs the same pinned verifier that decides
            payment, so every objective is an eval with a ground-truth reward
            signal.
          </div>
          <pre>cairn-mcp</pre>
          <div className="meta dim">
            <a href={repoLink("docs/agents.md")}>agents.md</a> has the config
            stanza for each client.
          </div>
        </li>
        <li className="card">
          <b>run a node</b>
          <div className="meta">
            One process syncs with peers, serves the log over HTTP, and admits
            what arrives — because it is the process holding the write lock.
            Readers fetch the log and re-derive everything themselves, which is
            the point: they need not trust the server that served it.
          </div>
          <pre>cairn-p2p --serve 0.0.0.0:8080 …</pre>
          <div className="meta dim">
            <a href={repoLink("docs/serving.md")}>serving.md</a> and{" "}
            <a href={repoLink("docs/p2p.md")}>p2p.md</a>.
          </div>
        </li>
      </ul>

      <h2>check it before you trust it</h2>
      <p className="lede">
        Every number above says where it came from: a node that answered, or{" "}
        {SNAPSHOT.source} — a real settled log that ships in the repository,
        not a mock. Either way, re-derive it yourself. This recomputes every
        settlement from the records and checks each batch against the anchor
        it recorded:
      </p>
      <div className="panel">
        <pre>{`git clone ${REPO}
cd distributed-researcher
cairn --log launch/cairn.jsonl --root . audit`}</pre>
        <div className="meta">
          merkle root{" "}
          <code className="accent" title={signed.root}>
            {short(signed.root)}
          </code>{" "}
          · signed at height {signed.height} · {signed.issued_at} · by{" "}
          <code title={signed.public_key}>{short(signed.public_key)}</code>
        </div>
        {/* The label is the point of the panel. A live node's root and the
            bundled log's signature are different facts, and the sentence that
            says which this is must sit beside the number, not three paragraphs
            up. The command above audits the bundled log either way — a live
            node's log is at its /log, and its own reader is at /chain. */}
        <div className="meta dim">
          {checkpointFrom}
          {checkpoint?.live &&
            " — the command above audits the bundled log; this node's own log is at /log and its chain at "}
          {checkpoint?.live && <Link href="/chain">/chain</Link>}
          {checkpoint?.live && "."}
        </div>
      </div>
      <p className="lede dim">
        A second implementation in{" "}
        <a href={repoLink("reference/rust/")}>
          <code>reference/rust/</code>
        </a>{" "}
        re-derives the same log independently, and{" "}
        <a href={repoLink("conformance/README.md")}>
          448 frozen conformance vectors
        </a>{" "}
        pin the byte encoding both must agree on. That is what
        &ldquo;verified&rdquo; is doing in the first sentence on this page —{" "}
        <Link href="/how-it-works">the long version</Link>.
      </p>
    </main>
  );
}

function Stat({ label, value, from }: { label: string; value: string; from: string }) {
  return (
    <div className="stat">
      <div className="statValue">{value}</div>
      <div className="statLabel">{label}</div>
      <div className="statFrom dim">{from}</div>
    </div>
  );
}
