"use client";

import Link from "next/link";
import { useCallback, useMemo, useState } from "react";
import { type Chain, epochScales, fetchChain, firstBrokenLink, totalClaims } from "@/lib/chain";
import { type CheckpointResponse, coversHead, readCheckpoint } from "@/lib/checkpoint";
import {
  type KnowledgeIndex,
  type KnowledgeRow,
  type Policy,
  caveats,
  fetchKnowledge,
  verification,
} from "@/lib/knowledge";
import { ago } from "@/lib/events";
import { loadObjectives } from "@/lib/site";
import { objectiveTitle } from "@/lib/title";
import { shortActor } from "@/components/events";
import { useEvery, useNode } from "@/components/hooks";
import {
  Badge,
  Box,
  CopyButton,
  Disclosure,
  EmptyState,
  Hash,
  LiveStamp,
  Note,
  PageHeader,
  Skeleton,
  Stat,
} from "@/components/ui";

const SUBTITLE =
  "How well verified each result on this node is, and the chain that commits to them: two nodes that settled the same results share a head, and where they differ is where they forked.";

/** Links drawn before "show all": the recent past is what a fork is found in. */
const RECENT_LINKS = 12;

/**
 * Knowledge: every result, how well verified it is, and the chain.
 *
 * The chain page used to be the whole of this -- links, a head, a
 * checkpoint -- which answers "is my copy the same as yours" and not the
 * question a person reading results has: *how sure is anyone of this one?*
 * The node has computed that all along (`GET /knowledge`, `src/knowledge.rs`)
 * and no page read it. Now each result shows four kinds of evidence as a
 * ladder (`lib/knowledge.ts`) beside the node's confidence under a policy the
 * reader picks, and the chain sits underneath as the commitment to all of it.
 *
 * Nothing here pays anyone. Settlement reads verdicts and citations; standing
 * and confidence are a view, and two readers with different policies get
 * different numbers from the same log on purpose.
 */
export default function Page() {
  const base = useNode();
  const [policy, setPolicy] = useState<Policy>("default");
  const [knowledge, setKnowledge] = useState<KnowledgeIndex | null>(null);
  const [knowledgeMissing, setKnowledgeMissing] = useState(false);
  const [chain, setChain] = useState<Chain | null>(null);
  const [checkpoint, setCheckpoint] = useState<CheckpointResponse | null>(null);
  const [titles, setTitles] = useState<Map<string, string>>(new Map());
  const [error, setError] = useState<string | null>(null);
  const [readAt, setReadAt] = useState<Date | null>(null);

  const load = useCallback(async () => {
    if (base === null) return;
    // Each part fails on its own: a node older than /knowledge still has a
    // chain, and a checkpoint in the wrong shape is no reason to hide either.
    const [nextKnowledge, nextChain, answer, feed] = await Promise.all([
      fetchKnowledge(base, policy).catch((cause: unknown) => {
        setError(cause instanceof Error ? cause.message : String(cause));
        return undefined;
      }),
      fetchChain(base).catch((cause: unknown) => {
        setError(cause instanceof Error ? cause.message : String(cause));
        return null;
      }),
      readCheckpoint(base),
      loadObjectives(base).catch(() => null),
    ]);
    if (nextKnowledge === null) setKnowledgeMissing(true);
    else if (nextKnowledge) setKnowledge(nextKnowledge);
    if (nextChain) setChain(nextChain);
    setCheckpoint(answer.kind === "signed" ? answer.value : null);
    if (feed?.live) setTitles(new Map(feed.objectives.map((o) => [o.id, objectiveTitle(o)] as const)));
    if (nextKnowledge !== undefined && nextChain) setError(null);
    setReadAt(new Date());
  }, [base, policy]);

  useEvery(load, 30, base !== null);

  const counts = knowledge?.by_standing ?? {};
  const verified = (counts.accepted ?? 0) + (counts.corroborated ?? 0);
  const challenged =
    (counts.contested ?? 0) + (counts.superseded ?? 0) + (counts.withdrawn ?? 0) + (counts.refuted ?? 0);
  const now = readAt?.getTime() ?? Date.now();

  return (
    <>
      <PageHeader
        title="Knowledge"
        subtitle={SUBTITLE}
        actions={
          <>
            <div className="segmented" role="group" aria-label="Confidence policy">
              <button
                type="button"
                aria-pressed={policy === "default"}
                onClick={() => setPolicy("default")}
                title="Acceptance by the pinned checker counts for most of it"
              >
                Standard
              </button>
              <button
                type="button"
                aria-pressed={policy === "demanding"}
                onClick={() => setPolicy("demanding")}
                title="Wants independent replication before belief; one refutation is close to fatal"
              >
                Demanding
              </button>
            </div>
            <LiveStamp at={readAt} error={knowledge || chain ? error : null} />
          </>
        }
      />

      {error && !knowledge && !chain && (
        <div className="mb-4">
          <Note title="Could not read this node" tone="bad">
            {error}
          </Note>
        </div>
      )}

      {/* -- results --------------------------------------------------------- */}
      {knowledge && (
        <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
          <Stat label="Results" value={String(knowledge.total)} from="claims in this log" />
          <Stat label="Verified" value={String(verified)} from="accepted by their checker" tone="accent" />
          <Stat label="Replicated" value={String(counts.corroborated ?? 0)} from="reproduced independently" tone="accent" />
          <Stat
            label="Challenged"
            value={String(challenged)}
            from="disputed, replaced or withdrawn"
            tone={challenged > 0 ? "warn" : "neutral"}
          />
        </div>
      )}

      <Ladder />

      {knowledgeMissing ? (
        <div className="mt-4">
          <EmptyState title="This node is older than the knowledge report">
            A node built with <span className="mono">GET /knowledge</span> shows how well verified each result is.
            The chain below is still this node&rsquo;s.
          </EmptyState>
        </div>
      ) : knowledge === null ? (
        <Skeleton className="mt-4 h-48 w-full" />
      ) : knowledge.claims.length === 0 ? (
        <div className="mt-4">
          <EmptyState title="No result yet">
            A result appears here once someone reveals an answer to a challenge and its checker has spoken.
          </EmptyState>
        </div>
      ) : (
        <Box
          className="mt-4"
          flush
          title={
            <>
              Results, newest first{" "}
              <span className="mono ml-1 font-normal text-ink-3">
                {knowledge.shown < knowledge.total ? `${knowledge.shown} of ${knowledge.total}` : knowledge.total}
              </span>
            </>
          }
          aside={
            <span className="text-[11px] font-normal text-ink-3">
              confidence under the {knowledge.policy.name === "default" ? "standard" : knowledge.policy.name} policy
            </span>
          }
        >
          <ul className="divide-edge-y">
            {knowledge.claims.map((row) => (
              <ResultRow key={row.claim_id} row={row} title={titles.get(row.objective_id)} now={now} />
            ))}
          </ul>
        </Box>
      )}

      {/* -- the chain ------------------------------------------------------- */}
      <h2 className="mt-8 mb-3 text-[13px] font-semibold tracking-[0.06em] text-ink-2 uppercase">The chain</h2>
      {chain ? <ChainSection chain={chain} checkpoint={checkpoint} /> : <Skeleton className="h-32 w-full" />}
    </>
  );
}

/** The four kinds of evidence, once, so every row's dots mean something. */
function Ladder() {
  const steps = [
    ["Checked", "The challenge's pinned checker accepted it. Nothing below counts without this."],
    ["Re-checkable here", "This node holds the checker's code, so anyone with the log can run the check again."],
    ["Backed by a bond", "A validator re-ran the check and staked money on the verdict, and nobody has shown them wrong."],
    ["Replicated", "An independent party reproduced the result in an answer its checker accepted."],
  ] as const;
  return (
    <section className="card card-pad">
      <div className="mb-3 flex flex-wrap items-baseline gap-2">
        <h2 className="text-[13.5px] font-semibold text-ink">How verified is a result?</h2>
        <span className="text-[12px] text-ink-3">Four kinds of evidence, each one a fact the log or this node can show.</span>
      </div>
      <ol className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {steps.map(([title, text], n) => (
          <li key={title} className="flex gap-2.5">
            <span className="mono flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-accent-soft text-[11px] text-accent">
              {n + 1}
            </span>
            <div>
              <div className="text-[12.5px] font-medium text-ink">{title}</div>
              <div className="text-[12px] leading-snug text-ink-3">{text}</div>
            </div>
          </li>
        ))}
      </ol>
      <p className="mt-3 text-[11.5px] text-ink-3">
        Confidence is this node&rsquo;s weighting of that evidence, under the policy you pick above — a reader&rsquo;s
        choice, not the network&rsquo;s. It never moves money: payment follows the checker&rsquo;s verdict alone.
      </p>
    </section>
  );
}

function ResultRow({ row, title, now }: { row: KnowledgeRow; title: string | undefined; now: number }) {
  const [open, setOpen] = useState(false);
  const v = useMemo(() => verification(row), [row]);
  const against = caveats(row);
  return (
    <li className="contain-rows">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        className="flex w-full cursor-pointer items-center gap-3 px-4 py-2.5 text-left transition-colors hover:bg-surface-2"
      >
        <span className="flex shrink-0 gap-1" aria-label={`${v.level} of 4 kinds of evidence`} title={`${v.level} of 4`}>
          {v.checks.map((check) => (
            <span
              key={check.key}
              className={`h-2 w-2 rounded-full ${check.done ? "bg-accent" : "border border-edge-strong"}`}
            />
          ))}
        </span>
        <span className="min-w-0 flex-1">
          <span className="line-clamp-1 text-[13px] text-ink">{title ?? row.objective_id.slice(7, 19)}</span>
          <span className="text-[11.5px] text-ink-3">
            by <span className="mono">{shortActor(row.submitter)}</span> · {ago(row.created_at, now)}
            {against.length > 0 && <span className="text-warn"> · {against[0]}</span>}
          </span>
        </span>
        <Badge tone={v.tone}>{v.label}</Badge>
        <span className="hidden w-28 shrink-0 sm:block" title={`${row.confidence_per_mille / 10}% under this policy`}>
          <span className="flex items-center gap-2">
            <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-surface-3">
              <span
                className={`block h-full rounded-full ${v.tone === "bad" ? "bg-bad" : v.tone === "warn" ? "bg-warn" : "bg-accent"}`}
                style={{ width: `${v.percent}%` }}
              />
            </span>
            <span className="mono w-8 text-right text-[11.5px] text-ink-2">{v.percent}%</span>
          </span>
        </span>
      </button>
      {open && (
        <div className="border-t border-edge bg-surface-2 px-4 py-3 pl-12">
          <ul className="flex flex-col gap-1.5">
            {v.checks.map((check) => (
              <li key={check.key} className="flex gap-2 text-[12.5px]">
                <span className={check.done ? "text-accent" : "text-ink-3"} aria-hidden>
                  {check.done ? "✓" : "○"}
                </span>
                <span className={check.done ? "text-ink" : "text-ink-2"}>
                  <b className="font-medium">{check.label}.</b> {check.why}
                </span>
              </li>
            ))}
          </ul>
          {against.length > 0 && (
            <p className="mt-2 text-[12.5px] text-warn">Against it: {against.join("; ")}.</p>
          )}
          <div className="mt-3 flex flex-wrap items-center gap-3 text-[12px]">
            <Hash value={row.claim_id} label="result" chars={10} />
            <Link href={`/challenge?id=${encodeURIComponent(row.objective_id)}`} className="text-accent hover:underline">
              Open the challenge →
            </Link>
          </div>
        </div>
      )}
    </li>
  );
}

function ChainSection({ chain, checkpoint }: { chain: Chain; checkpoint: CheckpointResponse | null }) {
  const broken = firstBrokenLink(chain.chain);
  const scales = epochScales(chain.chain);
  const covers = checkpoint ? coversHead(checkpoint.checkpoint, chain.height) : null;
  const newest = [...chain.chain].reverse();
  return (
    <div className="flex flex-col gap-4">
      {/* The one claim this page makes on its own behalf: the node says "here
          is a chain", and rendering it unchecked would be taking it on faith. */}
      {broken !== null && (
        <Note title="This is not a chain" tone="bad">
          The link for epoch {broken} does not name the link before it. The node served something inconsistent — do
          not compare this head against anything.
        </Note>
      )}
      {scales.length > 1 && (
        <Note title="Settled under more than one epoch length" tone="bad">
          Its epoch numbers span {scales.length} orders of magnitude, which happens when{" "}
          <code className="mono">CAIRN_EPOCH_SECONDS</code> changed between batches. That value decides which epoch a
          record falls in, and so which reveals were legal: a log holding both was settled under two rules.
        </Note>
      )}

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_22rem]">
        <Box
          title="Head"
          aside={<span className="text-[11px] font-normal text-ink-3">a peer with a different one has forked from you</span>}
        >
          <div className="flex items-start gap-1">
            <code className="mono text-[12.5px] text-accent">{chain.head || "— no epoch has settled yet"}</code>
            {chain.head && <CopyButton value={chain.head} />}
          </div>
          <dl className="kv mt-3">
            <dt>links</dt>
            <dd className="mono">{chain.links}, one per settled epoch</dd>
            <dt>results settled</dt>
            <dd className="mono">{totalClaims(chain.chain)}</dd>
            <dt>log entries</dt>
            <dd className="mono">{chain.height}</dd>
          </dl>
        </Box>
        <Box title="Signed checkpoint">
          {checkpoint ? (
            <dl className="kv">
              <dt>covers</dt>
              <dd className="mono text-[12px]">
                {checkpoint.checkpoint.height} of {chain.height} entries
                <div className={`text-[11.5px] ${covers === "ahead" ? "text-bad" : "text-ink-3"}`}>
                  {covers === "at"
                    ? "every entry"
                    : covers === "behind"
                      ? "behind the log, normal after appends"
                      : "ahead of this log: not this log"}
                </div>
              </dd>
              <dt>merkle root</dt>
              <dd>
                <Hash value={checkpoint.checkpoint.root} chars={8} />
              </dd>
              <dt>signed by</dt>
              <dd>
                <Hash value={checkpoint.public_key} chars={8} />
              </dd>
            </dl>
          ) : (
            <p className="text-[12.5px] text-ink-3">Nobody has signed a checkpoint of this log.</p>
          )}
          <p className="mt-3 text-[11.5px] leading-relaxed text-ink-3">
            Shown, not verified here: <code className="mono">cairn verify --from</code> checks the signature, and{" "}
            <code className="mono">cairn audit</code> re-derives the whole chain.
          </p>
        </Box>
      </div>

      {chain.chain.length > 0 && (
        <Disclosure summary={`Links, newest first (${chain.chain.length})`}>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[34rem] border-collapse text-left text-[12.5px]">
              <thead>
                <tr className="border-b border-edge text-[11px] text-ink-3">
                  <th className="py-2 pr-3 font-medium">Epoch</th>
                  <th className="px-3 py-2 font-medium">Link</th>
                  <th className="px-3 py-2 font-medium">Previous</th>
                  <th className="py-2 pl-3 font-medium">Results settled</th>
                </tr>
              </thead>
              <tbody className="divide-edge-y">
                {newest.slice(0, RECENT_LINKS).map((link) => (
                  <tr key={link.epoch} className="align-top">
                    <td className="mono py-2 pr-3 font-semibold text-ink">{link.epoch}</td>
                    <td className="px-3 py-2">
                      <Hash value={link.link} chars={8} />
                    </td>
                    <td className="px-3 py-2">
                      {link.prev === "" ? <span className="pill pill-open">first</span> : <Hash value={link.prev} chars={8} />}
                    </td>
                    <td className="mono py-2 pl-3 text-ink-2">{link.claims.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {newest.length > RECENT_LINKS && (
              <p className="mt-2 text-[11.5px] text-ink-3">
                and {newest.length - RECENT_LINKS} older; <span className="mono">GET /chain</span> has every link.
              </p>
            )}
          </div>
        </Disclosure>
      )}
    </div>
  );
}
