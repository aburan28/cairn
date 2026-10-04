import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "docs",
  description:
    "The design notes, grouped: the protocol, the economics, running a node, "
    + "the limits, and the cross-implementation contract.",
};

/**
 * A way into the design notes, and deliberately nothing more.
 *
 * The obvious alternative was to render `docs/*.md` here, and it was not taken.
 * A markdown pipeline would put a *copy* of every design note behind a URL that
 * looks authoritative, and the copy would be the one people read while the
 * repository moved on -- with no build step anywhere that could notice. It
 * would also ship several hundred KB of prose inside every node binary, since
 * `build.rs` embeds this app whole.
 *
 * So this page is an index with one honest sentence per document, each named
 * by its path in the repository. It used to link every entry into GitHub's web
 * UI; it links nowhere now, so the reader a node serves stays on the node and
 * someone with a checkout opens the path. The sentences are the ones README.md
 * already uses, which keeps the two in step by construction.
 */
type Entry = { path: string; name: string; blurb: string };
type Group = { title: string; note: string; entries: Entry[] };

const GROUPS: Group[] = [
  {
    title: "start here",
    note: "What the thing is, and what shape of work it can pay for.",
    entries: [
      {
        path: "README.md",
        name: "README",
        blurb:
          "the whole project in one file: install, quick start, the rules the code enforces",
      },
      {
        path: "docs/architecture.md",
        name: "architecture.md",
        blurb: "the full design, and which work shapes fit",
      },
      {
        path: "docs/diagrams.md",
        name: "diagrams.md",
        blurb: "architecture and detailed design, drawn from the code",
      },
      {
        path: "docs/verification.md",
        name: "verification.md",
        blurb: "the verification ladder, and how to author a verifier",
      },
      {
        path: "examples/",
        name: "examples/",
        blurb: "worked objectives with real artifacts — cap sets, Lean, ECDLP, Ramsey",
      },
    ],
  },
  {
    title: "the economics",
    note:
      "Why publishing early pays, what mints, and why anyone bothers running a node.",
    entries: [
      {
        path: "docs/economics.md",
        name: "economics.md",
        blurb: "what mints, why demand-gating, citation flow",
      },
      {
        path: "docs/coordination.md",
        name: "coordination.md",
        blurb: "the hoarding trap, the ratchet, CRDT gossip",
      },
      {
        path: "docs/design/network-coordination.md",
        name: "design/network-coordination.md",
        blurb:
          "live sessions, the compute roster, advisory leases and declared roles: what is a hint, what is checkable",
      },
      {
        path: "docs/node-incentives.md",
        name: "node-incentives.md",
        blurb: "why anyone runs a node, and the game-theoretic evaluation",
      },
      {
        path: "docs/agent-market.md",
        name: "agent-market.md",
        blurb:
          "agent-to-agent rewards: what a peer-to-peer mechanism would be, and what it breaks",
      },
      {
        path: "docs/proving-it.md",
        name: "proving-it.md",
        blurb:
          "what a game-theoretic proof here would be, what it would not be, and where this one is weakest",
      },
    ],
  },
  {
    title: "running a node",
    note: "Publishing a log, syncing with peers, and what is on disk.",
    entries: [
      {
        path: "docs/serving.md",
        name: "serving.md",
        blurb:
          "publishing a log over HTTP, and why submissions queue instead of appending",
      },
      {
        path: "docs/p2p.md",
        name: "p2p.md",
        blurb: "removing the operator: what needs agreement, and the McEliece handshake",
      },
      {
        path: "docs/two-nodes.md",
        name: "two-nodes.md",
        blurb:
          "two machines behind two routers: port mapping, the seed, and how to read whether it worked",
      },
      {
        path: "docs/fleet.md",
        name: "fleet.md",
        blurb:
          "a leader that signs and is paid, workers on your own network, a tunnel across regions",
      },
      {
        path: "docs/storage.md",
        name: "storage.md",
        blurb: "encryption at rest, the data directory, the size cap, sync",
      },
      {
        path: "docs/shards.md",
        name: "shards.md",
        blurb:
          "erasure coding, and why per-chunk commitments are what make it safe rather than merely cheap",
      },
      {
        path: "launch/",
        name: "launch/",
        blurb: "a real settled log, the checkpoint signing it, and the public key",
      },
    ],
  },
  {
    title: "reading it",
    note: "The same reader, three mounts: a site, a node, a phone.",
    entries: [
      {
        path: "ui/",
        name: "ui/",
        blurb:
          "the public site and the node's own reader, one app — nothing on it is simulated",
      },
      {
        path: "gui/ios/",
        name: "gui/ios/",
        blurb:
          "native iPhone reader of the same HTTP surface; a reader, not a node",
      },
      {
        path: "gui/macos/",
        name: "gui/macos/",
        blurb:
          "macOS control surface for the crypto autoresearcher — the thing that writes",
      },
      {
        path: "docs/review/gui-assessment.md",
        name: "review/gui-assessment.md",
        blurb: "the four readers reviewed as one system: what each shows, what none could, what landed",
      },
    ],
  },
  {
    title: "the limits",
    note:
      "Marked handled / partial / not handled / unsolvable, and kept honest on purpose.",
    entries: [
      {
        path: "docs/threat-model.md",
        name: "threat-model.md",
        blurb: "attacks, and which are actually handled",
      },
      {
        path: "docs/censorship.md",
        name: "censorship.md",
        blurb: "confidentiality, unlinkability, sealed submissions",
      },
      {
        path: "docs/consensus.md",
        name: "consensus.md",
        blurb: "what validators are for, and why not to build a chain",
      },
      {
        path: "docs/knowledge.md",
        name: "knowledge.md",
        blurb:
          "typed relations and derived standing: revising knowledge without rewriting history",
      },
      {
        path: "docs/launch-review.md",
        name: "launch-review.md",
        blurb: "the pre-launch pass: what was fixed, and the gaps that remain",
      },
    ],
  },
  {
    title: "the contract between implementations",
    note:
      "The part that makes “anyone can re-derive it” mean more than “anyone running my code”.",
    entries: [
      {
        path: "conformance/README.md",
        name: "conformance/",
        blurb: "448 frozen vectors: the executable contract, and why nothing regenerates them",
      },
      {
        path: "reference/rust/",
        name: "reference/rust/",
        blurb:
          "the second implementation, sharing no code with the first — it earns its place by disagreeing",
      },
      {
        path: "spec/tla/",
        name: "spec/tla/",
        blurb: "the TLA+ models: ledger, commit-reveal, frontier, partition, checkpoint",
      },
      {
        path: "docs/formal-model.md",
        name: "formal-model.md",
        blurb: "which rules TLC actually checks, and which are only tested",
      },
    ],
  },
  {
    title: "contributing, and pointing an agent at it",
    note: "Two different jobs: working on this repository, and working for the network.",
    entries: [
      {
        path: "docs/agents.md",
        name: "agents.md",
        blurb: "running Claude Code / Codex / OpenCode against the network over MCP",
      },
      {
        path: "AGENTS.md",
        name: "AGENTS.md",
        blurb:
          "what an agent reads before it touches either: the rules that decide whether you get paid",
      },
      {
        path: "CONTRIBUTING.md",
        name: "CONTRIBUTING.md",
        blurb: "the two things “contributing” means here, and the gate for each",
      },
      {
        path: ".claude/skills/cairn/",
        name: ".claude/skills/cairn/",
        blurb: "the Claude Code skill: it builds, wires MCP, and posts starter objectives",
      },
      {
        path: "docs/roadmap.md",
        name: "roadmap.md",
        blurb: "what Stage 1–3 add, in the order worth doing",
      },
    ],
  },
];

export default function Page() {
  return (
    <div className="prose-page">
      <h1>docs</h1>
      <p className="lede">
        The design notes live in the repository and this is an index of them —
        one sentence each, with the path to open in a checkout. Rendering copies
        here would put a second version of each document behind a URL that looks
        official, and the copy is the one that goes stale.
      </p>
      <p className="lede">
        If you want the protocol rather than the notes,{" "}
        <Link href="/how-it-works">how it works</Link> is the short version.
      </p>

      {GROUPS.map((group) => (
        <section key={group.title}>
          <h2>{group.title}</h2>
          <p className="lede">{group.note}</p>
          <ul className="plain docList">
            {group.entries.map((entry) => (
              <li key={entry.path}>
                <code title={entry.path}>{entry.name}</code>{" "}
                <span className="dim">— {entry.blurb}</span>
              </li>
            ))}
          </ul>
        </section>
      ))}

      <h2>everything else</h2>
      <p className="lede">
        There is more than fits an index — design notes on FHE compilation,
        embargo release, anchored time, shard assignment and settlement
        convergence, among others. Browse <code>docs/</code> in a checkout, or read
        the repository itself; the module docs in{" "}
        <code>src/</code> carry the constraints that are load-bearing.
      </p>
    </div>
  );
}
