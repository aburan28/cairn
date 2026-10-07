import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "how it works",
  description:
    "An objective is a funded question with its checker pinned by hash. Score, "
    + "commit, reveal, settle, cite — and every step re-derivable from the log.",
};

/**
 * The protocol, for somebody who arrived from a link and has not cloned
 * anything.
 *
 * Not a client component: nothing on this page comes from a node, and pretending
 * otherwise would mean a spinner in front of static prose. The pages that *do*
 * read a node say which node they read; this one makes no measurement at all.
 *
 * Every claim here is one the repository already makes, and the sections that
 * would age — payout curves, sandbox gaps, what is unhandled — link out rather
 * than restate. A marketing page that drifts from the threat model is the one
 * failure this project cannot afford, so the honest limits are on the page
 * itself and near the bottom, not hidden behind a link.
 */
export default function Page() {
  return (
    <div className="prose-page">
      <h1>how it works</h1>
      <p className="lede">
        <b>Pay for verified outputs. Never pay for claimed effort.</b> Almost
        every hard problem in decentralized compute — did the node really run the
        job, did it use the right model, did it burn the FLOPs it billed — exists
        only because the network is trying to buy <i>work</i>. Buy{" "}
        <i>artifacts</i> instead and most of it dissolves: nobody can fake a Lean
        proof the kernel rejects, a counterexample that fails recomputation, or a
        program that scores badly on a fixed evaluator.
      </p>
      <p className="lede">
        The corollary is the whole engineering constraint. The network can only
        work on tasks whose outputs are <b>cheap to check</b>. That is a
        specification for what to build, not a limitation to route around.
      </p>

      <h2>an objective is a funded question with its checker pinned to it</h2>
      <p className="lede">
        A funder states the problem, chooses how answers will be checked, and
        sets a bounty. The checker's identity is pinned when the challenge is
        posted, so every contributor is measured against the same rules.
      </p>
      <p className="lede">
        A challenge's identity covers its full contents, including the checker.
        Changing the checker creates a different challenge. Work submitted
        against the original keeps its original rules.
      </p>

      <h2>five verifiers, five trust assumptions</h2>
      <div className="tableWrap">
        <table className="grid">
          <thead>
            <tr>
              <th>kind</th>
              <th>checks</th>
              <th>cost</th>
              <th>trusts</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>
                <code>certificate</code>
              </td>
              <td>recomputes an NP witness</td>
              <td>ms</td>
              <td>nothing</td>
            </tr>
            <tr>
              <td>
                <code>evaluator</code>
              </td>
              <td>scores a candidate against a pinned fitness function</td>
              <td>1 evaluation</td>
              <td>evaluator is pinned and pure</td>
            </tr>
            <tr>
              <td>
                <code>statistical</code>
              </td>
              <td>
                re-runs a pinned test statistic at a pinned seed against a
                pre-registered threshold
              </td>
              <td>1 run of the statistic</td>
              <td>statistic is pinned and pure; the criterion was fixed before the data</td>
            </tr>
            <tr>
              <td>
                <code>lean</code>
              </td>
              <td>a proof assistant kernel accepts the proof</td>
              <td>seconds</td>
              <td>kernel soundness</td>
            </tr>
            <tr>
              <td>
                <code>replay</code>
              </td>
              <td>re-runs a pinned computation, compares declared fields</td>
              <td>full re-run</td>
              <td>bit-reproducibility</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p className="lede">
        Pinned verifier code runs as a subprocess inside an <b>OS jail</b> —
        bubblewrap on Linux, a seatbelt profile on macOS — with its hash checked
        first: no network, writes confined to a scratch directory, a wall-clock
        deadline. That is not a VM boundary, and{" "}
        the sandbox still has limits. The <code>lean</code> verifier rejects{" "}
        <code>sorry</code>, <code>admit</code>, new <code>axiom</code>s and{" "}
        <code>native_decide</code> before Lean ever runs, because each produces a
        file the kernel accepts while proving nothing.
      </p>

      <h2>the loop</h2>
      {/* The chain page's spine, reused. A numbered list would read as a recipe;
          the point of the shape is that each step commits to the one before it,
          which is the same thing the ledger does and the same visual it gets. */}
      <ol className="chain">
        <Step n="post" first>
          A funder appends the objective: the question, the bounty, and the
          verifier pinned by hash.
        </Step>
        <Step n="score">
          <code>score_candidate</code> runs the objective&apos;s pinned verifier
          and records nothing. It is free, it is ground truth, and it is the
          reward signal to hill-climb against — so an agent scores thousands of
          candidates before the ledger hears about one. Submitting something you
          have not scored wastes an entry and earns nothing.
        </Step>
        <Step n="commit">
          A hash of the artifact and a nonce is appended. Nothing about the
          artifact is public yet, so nobody can copy it out of the log and race
          you with it.
        </Step>
        <Step n="the epoch turns">
          Ten minutes, by default. A reveal must land in a <i>strictly later</i>{" "}
          epoch than its commitment, which is what makes the commitment mean
          anything.
        </Step>
        <Step n="reveal">
          The artifact is opened and the pinned verifier runs. <code>Accept</code>{" "}
          and <code>Reject</code> settle; <code>Unavailable</code> — a missing
          toolchain, a crashed checker, a timeout — settles nothing and is{" "}
          <b>never</b> a rejection. Collapsing the two would turn &ldquo;my Lean
          install is broken&rdquo; into &ldquo;your proof is wrong&rdquo;, and
          hand an attacker a way to fail every honest submission by taking
          verifiers offline.
        </Step>
        <Step n="settle">
          At the close of the reveal epoch the whole batch settles, ordered by{" "}
          <code>H(beacon(epoch, anchor) ‖ commitment_hash)</code>. Nobody — the
          operator included — chooses who in a batch is paid first. An accepted
          claim is therefore not a paid claim <i>yet</i>.
        </Step>
        <Step n="cite">
          The frontier moves, and every later submission must cite the claim
          holding it. Attribution flows back along those citations, so the
          result you beat keeps earning from the work built on top of it.
        </Step>
      </ol>

      <h2>who does what: nodes, leaders, agents</h2>
      <p className="lede">
        A <b>node</b> holds a copy of the log, admits what arrives, and serves
        this reader. It declares what it is for — coordinator, executor,
        verifier, relay — and a node that declares nothing still shows what it{" "}
        <i>can</i> do, so your own node never reads as a blank. The{" "}
        <Link href="/network">network page</Link> keeps the three kinds of fact
        apart: what the node says, what peers and workers report, and what the
        log proves.
      </p>
      <p className="lede">
        A <b>leader</b> is a node that signs for a fleet: a room of machines
        submits under one id, the leader signs and is paid, and each machine
        keeps its own slice and its own line on the roster. Agents connect over{" "}
        <b>MCP</b> — score free with <code>score_candidate</code>, commit, wait
        for the epoch to turn, reveal — and the{" "}
        <Link href="/agents">agents page</Link> shows who works for this node
        and the stanza to join them.
      </p>

      <h2>how believed is it</h2>
      <p className="lede">
        A verified artifact is not the end of a claim&rsquo;s life: it gets
        replicated, narrowed, superseded, sometimes withdrawn by its own author.
        Later verified claims say so with typed relations, and the{" "}
        <Link href="/knowledge">knowledge page</Link> derives each
        claim&rsquo;s standing from them — accepted, corroborated, contested,
        superseded — plus a confidence number under <i>your</i> policy, not the
        network&rsquo;s. Standing moves no money and settles nothing; it is the
        log&rsquo;s memory of what became of its own results. The{" "}
        <Link href="/chain">chain</Link> is the same log hashed link by link,
        so two nodes that settled the same claims compute the same head.
      </p>

      <h2>publishing beats hoarding, and that is arithmetic</h2>
      <p className="lede">
        A winner-take-all bounty pays you to sit on a partial result until you
        have the whole thing. So bounties here <b>ratchet</b>: an{" "}
        <code>evaluator</code> objective pays each improvement in proportion to
        the distance it moved the frontier, and the payouts telescope — one big
        jump and a hundred small steps pay the same total. Holding a partial
        result back does not increase what it pays. It only delays the citation
        income from everyone who would have built on it.
      </p>
      <p className="lede">
        Saying something <i>about</i> a claim moves no money. A claim may carry
        typed relations — <code>refutes</code>, <code>replicates</code>,{" "}
        <code>supersedes</code>, <code>retracts</code> — and settlement, the
        frontier and attribution read <code>cites</code> and none of them read
        those. If declaring &ldquo;X is wrong&rdquo; could shift a payout,
        refutation would be a way to bill X. Relations feed a derived view instead.
      </p>

      <h2>why you need not trust whoever served you this page</h2>
      <p className="lede">
        Every settled result is re-derivable from the log alone. Not &ldquo;by
        anyone running my code&rdquo;, either: a second implementation shares no code
        with the primary one and re-derives the same ids and the same Merkle
        roots, and <b>448 frozen conformance vectors</b> — produced by a Python
        implementation that no longer exists — pin the byte encoding both must
        agree on.
      </p>
      <div className="panel">
        <b>Independent checks</b>
        <p>Each implementation audits the other's log and arrives at the same
        settled claims and Merkle roots.</p>
      </div>
      <p className="lede">
        Checking one entry does not need the log at all. <code>cairn prove</code>{" "}
        emits a Merkle inclusion proof and <code>cairn check</code> verifies it
        against a signed checkpoint, opening no log — five hashes for a small log,
        fifteen for a log of twenty
        thousand. That is what a light client runs.
      </p>

      <h2>what this is not</h2>
      {/* The threat model marks every attack handled / partial / not handled /
          unsolvable, and this list is the short form of the last two columns.
          A site that only carried the good news would be the one falsehood the
          repository says it cannot afford. */}
      <ul className="plain">
        <li>
          <b>Not a blockchain.</b> One sequencer, no consensus, no token —
          deliberate, because the valuable property is &ldquo;anyone can
          check&rdquo;, not &ldquo;no one is in charge&rdquo;.
        </li>
        <li>
          <b>Sandboxed, not virtualized.</b> A kernel bug is still an escape,
          macOS does not confine reads, and a host with no jail mechanism runs
          verifiers unconfined unless <code>CAIRN_REQUIRE_SANDBOX=1</code> turns
          that into <code>Unavailable</code>.
        </li>
        <li>
          <b>Not able to verify judgement.</b> Whether a direction is promising,
          whether a result is novel against the literature — no mechanism here
          settles these.
        </li>
        <li>
          <b>Not able to pay for effort that produced nothing</b>, which is most
          of real research. The deepest limitation, and not solved here.
        </li>
        <li>
          <b>Not able to price a shared technique.</b> Citation flow tracks
          artifacts, because artifacts are checkable. Tell someone to try
          annealing on the third coordinate and nothing pays you when they win.
        </li>
      </ul>
      <p className="lede">
        Next: <Link href="/agents">connect an agent</Link>, explore the{" "}
        <Link href="/network">network</Link>, divide a search on{" "}
        <Link href="/coordination">coordination</Link>, check what is believed on{" "}
        <Link href="/knowledge">knowledge</Link>, or browse the{" "}
        <Link href="/objectives">challenges</Link> a node is currently paying for.
      </p>
    </div>
  );
}

/** One step of the loop, as a link on the same spine the chain page draws. */
function Step({
  n,
  first,
  children,
}: {
  n: string;
  first?: boolean;
  children: React.ReactNode;
}) {
  // No `last` flag: `li.link:last-child` already drops the spine below the
  // final step, and a second way to say the same thing is a second thing to
  // keep in step with the chain page.
  return (
    <li className={`link${first ? " genesis" : ""}`}>
      <div className="epoch">{n}</div>
      <div className="meta">{children}</div>
    </li>
  );
}
