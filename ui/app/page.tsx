"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  type Feed,
  REPO,
  SNAPSHOT,
  loadObjectives,
  progress,
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
 */
export default function Page() {
  const [feed, setFeed] = useState<Feed | null>(null);

  useEffect(() => {
    void loadObjectives().then(setFeed);
  }, []);

  const objectives = feed?.objectives ?? SNAPSHOT.objectives;
  const open = objectives.filter((o) => !o.settled);
  const pool = objectives.reduce((sum, o) => sum + o.reward, 0);
  const paid = objectives.reduce((sum, o) => sum + (o.frontier?.paid_cumulative ?? 0), 0);

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
        <Stat label="objectives" value={String(objectives.length)} />
        <Stat label="open" value={String(open.length)} />
        <Stat label="pool" value={units(pool)} />
        <Stat label="paid out" value={units(paid)} />
        <Stat label="chain links" value={String(SNAPSHOT.links)} />
      </div>

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
        {feed?.live
          ? `The numbers above came from ${feed.origin}.`
          : `No node answered, so the numbers above come from ${SNAPSHOT.source} — a real settled log that ships in the repository, not a mock.`}{" "}
        Either way, re-derive them yourself. This recomputes every settlement
        from the records and checks each batch against the anchor it recorded:
      </p>
      <div className="panel">
        <pre>{`git clone ${REPO}
cd distributed-researcher
cairn --log launch/cairn.jsonl --root . audit`}</pre>
        <div className="meta">
          merkle root{" "}
          <code className="accent" title={SNAPSHOT.merkle_root}>
            {short(SNAPSHOT.merkle_root)}
          </code>{" "}
          · signed at height {SNAPSHOT.height} · {SNAPSHOT.issued_at}
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

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="stat">
      <div className="statValue">{value}</div>
      <div className="statLabel">{label}</div>
    </div>
  );
}
