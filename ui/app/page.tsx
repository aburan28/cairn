"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  type Feed,
  SNAPSHOT,
  loadObjectives,
  progress,
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
        attribution is a rule rather than an etiquette — and the citation pays.
      </p>

      <div className="panel">
        <b>install</b>
        <pre>
          curl -fsSL
          https://github.com/aburan28/distributed-researcher/releases/latest/download/install.sh
          | sh
        </pre>
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
                      {" · "}best <code className="accent">{o.frontier.score}</code>
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

      <h2>check it before you trust it</h2>
      <p className="lede">
        {feed?.live
          ? `The numbers above came from ${feed.origin}.`
          : `No node answered, so the numbers above come from ${SNAPSHOT.source} — a real settled log that ships in the repository, not a mock.`}{" "}
        Either way, re-derive them yourself. This recomputes every settlement
        from the records and checks each batch against the anchor it recorded:
      </p>
      <div className="panel">
        <pre>{`git clone https://github.com/aburan28/distributed-researcher
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
        A second implementation in <code>reference/rust/</code> re-derives the
        same log independently, and 448 frozen conformance vectors pin the byte
        encoding both must agree on. That is what &ldquo;verified&rdquo; is doing
        in the first sentence on this page.
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
