"use client";

import Link from "next/link";
import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { type Objective, loadObjective, progress, short, units } from "@/lib/site";
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

  useEffect(() => {
    if (!id) {
      setState("missing");
      return;
    }
    void loadObjective(id).then((r) => {
      setObjective(r.objective);
      setLive(r.live);
      setOrigin(r.origin);
      setState(r.objective ? "ready" : "missing");
    });
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

  return (
    <>
      <PageHeader
        crumb={{ href: "/objectives", label: "Objectives" }}
        title={objective.goal || short(objective.id)}
        meta={
          <>
            <StatusPill settled={objective.settled} />
            <Badge tone="info">{objective.verifier_kind}</Badge>
            <span>
              funded by <span className="mono text-ink">{objective.funder}</span>
            </span>
          </>
        }
      />

      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Bounty" value={units(ratchet?.reward ?? objective.reward)} tone="violet" />
        {ratchet && frontier ? (
          <Stat
            label="Best score"
            value={String(frontier.score)}
            from={`${ratchet.direction} from ${ratchet.baseline} toward ${ratchet.target}`}
            tone="accent"
          />
        ) : (
          <Stat
            label="Status"
            value={objective.settled ? "Settled" : "Open"}
            from={objective.settled ? "nothing left to win" : "first accepted claim wins"}
            tone={objective.settled ? "neutral" : "accent"}
          />
        )}
        <Stat label="Paid out" value={units(paid)} tone="info" />
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
              in a footer — the same rule `/objectives` follows over HTTP. */}
          <Box
            title="Statement"
            aside={
              <span className="text-[11px] font-normal text-warn">
                written by the funder, not checked
              </span>
            }
          >
            <p className="text-[14px] leading-relaxed text-ink">{objective.statement}</p>
          </Box>

          <Box
            title={objective.piecework ? "Search" : objective.settled ? "Result" : "Frontier"}
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
                  <dd className="mono text-[15px] font-semibold text-accent">{frontier.score}</dd>
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
                 one settlement. Before this branch the page said "settled" in
                 the tag line and "No claim yet" here, about the same objective. */
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
                 settlement: it pays per novel unit until the pool is dry. The
                 standing here is the node's; who did the work, how fast, and
                 how far along the search is are on the task page. */
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
                  <dd className="mono font-semibold text-accent">
                    {units(objective.piecework.paid_total)}
                  </dd>
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
                <Link
                  href={`/task?id=${encodeURIComponent(objective.id)}`}
                  className="text-[12.5px] text-accent hover:underline"
                >
                  Who is working it, how fast, and how far along →
                </Link>
              </div>
            ) : (
              <p className="text-[13px] text-ink-2">
                No claim yet. The first accepted claim takes{" "}
                {ratchet ? "the first slice of the pool" : "the bounty"}.
              </p>
            )}
          </Box>

          {/* Only while there is something to win. A settled certificate used
              to keep a full-width "Work on this" section, two config files
              and three commands deep, for a prize that was already paid. */}
          {!objective.settled && <WorkOnThis id={objective.id} mustCite={frontier?.must_cite} />}
        </div>

        <aside className="flex min-w-0 flex-col gap-4">
          <Box title="Details">
            <dl className="kv">
              <dt>objective</dt>
              <dd>
                <Hash value={objective.id} chars={10} />
              </dd>
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

/** A verifier field, if it is a string. The record's shape is the funder's. */
function text(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined;
}

/**
 * How to submit, as two tabs rather than two side-by-side cards of prose.
 *
 * The terminal comes first: it is the one that needs nothing configured.
 */
function WorkOnThis({ id, mustCite }: { id: string; mustCite: string | undefined }) {
  const [tab, setTab] = useState<"cli" | "mcp">("cli");
  const cli = cliCalls(id, mustCite);
  const calls = mcpCalls(id, mustCite);

  return (
    <Box
      title="Submit a claim"
      aside={
        <span className="hidden text-[11px] font-normal text-ink-3 sm:inline">
          score locally first; it is free and it is the same checker
        </span>
      }
      flush
    >
      <div className="tabs" role="tablist">
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
        {tab === "cli" ? (
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
              <span className="mono">docs/agents.md</span>{" "}
              has the other clients&rsquo; spellings.
            </p>
            <CodeBlock value={MCP_STANZA} />
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
