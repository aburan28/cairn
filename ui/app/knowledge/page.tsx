"use client";

import Link from "next/link";
import { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  type KnowledgeClaim,
  type KnowledgeIndex,
  confidencePercent,
  evidenceLine,
  fetchKnowledgeClaim,
  fetchKnowledgeIndex,
  standingHelp,
  standingTone,
} from "@/lib/knowledge";
import { NODE_URL } from "@/lib/site";
import { resolveNode } from "@/lib/site";
import {
  Badge,
  Box,
  CopyButton,
  EmptyState,
  Hash,
  NodeSource,
  Note,
  PageHeader,
  Progress,
  SectionHeading,
  Skeleton,
} from "@/components/ui";

/**
 * How believed each settled claim is, as this node derives it from the log.
 *
 * The chain page shows *that* claims settled; this one shows what happened
 * to them since: the verifier's verdict, what later verified claims said
 * about them, and a confidence number under the policy named at the top.
 * `?id=` is one claim with its relations and its bonded attestations;
 * without it, the table of every claim, newest first.
 *
 * Standing moves no money and settles nothing. A contested claim is the log
 * working, not the log failing.
 */
export default function Page() {
  return (
    <Suspense
      fallback={
        <div className="flex flex-col gap-3">
          <PageHeader
            title="Knowledge"
            subtitle="How believed each settled claim is: the verifier's verdict, what later verified claims said, and a confidence number under your policy."
          />
          <Skeleton className="h-4 w-full max-w-lg" />
          <Skeleton className="h-20 w-full" />
        </div>
      }
    >
      <Knowledge />
    </Suspense>
  );
}

function Knowledge() {
  const params = useSearchParams();
  const id = params.get("id") ?? "";
  return id ? <Claim id={id} /> : <Index />;
}

function Index() {
  const [base, setBase] = useState(NODE_URL);
  const [policy, setPolicy] = useState<"default" | "demanding">("default");
  const [data, setData] = useState<KnowledgeIndex | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [standing, setStanding] = useState<string | null>(null);

  const load = useCallback(
    async (url: string, name: "default" | "demanding") => {
      setLoading(true);
      setError(null);
      try {
        setData(await fetchKnowledgeIndex(url, name));
      } catch (cause) {
        setData(null);
        setError(cause instanceof Error ? cause.message : String(cause));
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  useEffect(() => {
    void resolveNode().then((url) => {
      setBase(url || window.location.origin);
      void load(url, policy);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load]);
  useEffect(() => {
    if (base !== NODE_URL || data) void load(base === window.location.origin ? "" : base, policy);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [policy]);

  const picker = (
    <>
      <label className="flex items-center gap-1.5 text-[12px] text-ink-3">
        Policy
        <select
          className="field py-1.5"
          value={policy}
          onChange={(event) => setPolicy(event.target.value as "default" | "demanding")}
          title="The reader's weighting: demanding wants replication before belief"
        >
          <option value="default">default</option>
          <option value="demanding">demanding</option>
        </select>
      </label>
      <NodeSource
        value={base}
        onChange={setBase}
        onRead={() => void load(base === window.location.origin ? "" : base, policy)}
        loading={loading}
      />
    </>
  );

  const rows = useMemo(() => {
    if (!data) return [];
    return standing ? data.claims.filter((row) => row.standing === standing) : data.claims;
  }, [data, standing]);

  if (error && !data) {
    return (
      <>
        <PageHeader title="Knowledge" actions={picker} />
        <Note title="Could not read this node" tone="bad">
          {error}
        </Note>
      </>
    );
  }

  if (!data) {
    return (
      <div className="flex flex-col gap-3">
        <PageHeader
          title="Knowledge"
          subtitle="How believed each settled claim is: the verifier's verdict, what later verified claims said, and a confidence number under your policy."
          actions={picker}
        />
        <div className="mt-3 grid grid-cols-2 gap-3 md:grid-cols-4">
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
        </div>
      </div>
    );
  }

  return (
    <>
      <PageHeader
        title="Knowledge"
        subtitle="How believed each settled claim is: the verifier's verdict, what later verified claims said, and a confidence number under your policy. Standing moves no money."
        meta={
          <>
            <Badge tone="accent">{data.total} claims</Badge>
            <Badge tone="neutral" title="The policy this page's numbers were computed under">
              policy: {data.policy.name}
            </Badge>
          </>
        }
        actions={picker}
      />

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <button
          type="button"
          className={`btn btn-sm ${standing === null ? "btn-primary" : ""}`}
          onClick={() => setStanding(null)}
        >
          all <span className="mono">{data.total}</span>
        </button>
        {Object.entries(data.by_standing)
          .sort(([, a], [, b]) => b - a)
          .map(([name, count]) => (
            <button
              type="button"
              key={name}
              className={`btn btn-sm ${standing === name ? "btn-primary" : ""}`}
              onClick={() => setStanding(standing === name ? null : name)}
              title={standingHelp(name)}
            >
              {name} <span className="mono">{count}</span>
            </button>
          ))}
      </div>

      {rows.length === 0 ? (
        <EmptyState title={standing ? `No ${standing} claim here` : "No claim in this log yet"}>
          {standing
            ? "Nothing derived to this standing under the chosen policy."
            : "Standing appears once a claim is verified."}
        </EmptyState>
      ) : (
        <div className="box mb-5 overflow-x-auto">
          <table className="w-full min-w-[52rem] border-collapse text-left text-[12.5px]">
            <thead>
              <tr className="border-b border-edge text-[11px] text-ink-3">
                <th className="px-4 py-2 font-medium">Claim</th>
                <th className="px-3 py-2 font-medium">Standing</th>
                <th className="px-3 py-2 font-medium">Confidence</th>
                <th className="px-3 py-2 font-medium">Evidence</th>
                <th className="px-3 py-2 font-medium">By</th>
                <th className="px-4 py-2 font-medium">On</th>
              </tr>
            </thead>
            <tbody className="divide-edge-y">
              {rows.map((row) => (
                <tr key={row.claim_id} className="align-top hover:bg-surface-2">
                  <td className="px-4 py-2.5">
                    <Hash
                      value={row.claim_id}
                      href={`/knowledge?id=${encodeURIComponent(row.claim_id)}`}
                      chars={8}
                    />
                  </td>
                  <td className="px-3 py-2.5">
                    <Badge tone={standingTone(row.standing)} title={standingHelp(row.standing)}>
                      {row.standing}
                    </Badge>
                    {row.reproducible === "not-here" && (
                      <div className="mt-1 text-[11px] text-warn" title="The pinned verifier code is missing from this node's store">
                        not re-derivable here
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-2.5">
                    <div className="flex min-w-28 items-center gap-2">
                      <div className="min-w-20 flex-1">
                        <Progress value={row.confidence_per_mille / 1000} />
                      </div>
                      <span className="mono text-[12px] text-ink-2">
                        {confidencePercent(row.confidence_per_mille)}%
                      </span>
                    </div>
                  </td>
                  <td className="px-3 py-2.5 text-[12px] text-ink-2">{evidenceLine(row)}</td>
                  <td className="mono px-3 py-2.5 text-[12px] text-ink-2">{row.submitter}</td>
                  <td className="px-4 py-2.5">
                    <Link
                      href={`/challenge?id=${encodeURIComponent(row.objective_id)}`}
                      className="text-accent hover:underline"
                      title={row.objective_id}
                    >
                      challenge →
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {data.total > data.shown && (
        <p className="mb-4 text-[12px] text-ink-3">
          Showing {data.shown} of {data.total}; the newest first.
        </p>
      )}
      <p className="text-[12px] text-ink-3">{data.note}</p>
    </>
  );
}

function Claim({ id }: { id: string }) {
  const [base, setBase] = useState(NODE_URL);
  const [policy, setPolicy] = useState<"default" | "demanding">("default");
  const [claim, setClaim] = useState<KnowledgeClaim | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(
    async (url: string, name: "default" | "demanding") => {
      setLoading(true);
      setError(null);
      try {
        setClaim(await fetchKnowledgeClaim(id, url, name));
      } catch (cause) {
        setClaim(null);
        setError(cause instanceof Error ? cause.message : String(cause));
      } finally {
        setLoading(false);
      }
    },
    [id],
  );

  useEffect(() => {
    void resolveNode().then((url) => {
      setBase(url || window.location.origin);
      void load(url, policy);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load]);

  const picker = (
    <>
      <label className="flex items-center gap-1.5 text-[12px] text-ink-3">
        Policy
        <select
          className="field py-1.5"
          value={policy}
          onChange={(event) => {
            const next = event.target.value as "default" | "demanding";
            setPolicy(next);
            void load(base === window.location.origin ? "" : base, next);
          }}
        >
          <option value="default">default</option>
          <option value="demanding">demanding</option>
        </select>
      </label>
      <NodeSource
        value={base}
        onChange={setBase}
        onRead={() => void load(base === window.location.origin ? "" : base, policy)}
        loading={loading}
      />
    </>
  );

  if (error && !claim) {
    return (
      <>
        <PageHeader crumb={{ href: "/knowledge", label: "Knowledge" }} title="No such claim" actions={picker} />
        <Note title="Could not read this claim" tone="bad">
          {error}
        </Note>
      </>
    );
  }

  if (!claim) {
    return (
      <div className="flex flex-col gap-3">
        <Skeleton className="h-7 w-56" />
        <Skeleton className="h-4 w-full max-w-lg" />
        <Skeleton className="h-20 w-full" />
      </div>
    );
  }

  const state = claim.state;
  return (
    <>
      <PageHeader
        crumb={{ href: "/knowledge", label: "Knowledge" }}
        title="One claim, and what became of it"
        meta={
          <>
            <Badge tone={standingTone(state.standing)} title={standingHelp(state.standing)}>
              {state.standing}
            </Badge>
            <span className="mono text-[12px] text-ink-2">
              {confidencePercent(state.confidence_per_mille)}% under {claim.policy.name}
            </span>
            <Hash value={claim.claim_id} chars={8} />
          </>
        }
        actions={picker}
      />

      <div className="mb-5 grid gap-4 lg:grid-cols-[minmax(0,1fr)_22rem]">
        <Box title="Standing">
          <div className="mb-2 max-w-64">
            <Progress value={state.confidence_per_mille / 1000} label="confidence" />
          </div>
          <dl className="kv mt-3">
            <dt>verdict</dt>
            <dd className="mono">{state.verdict ?? "none recorded"}</dd>
            <dt>re-derivable</dt>
            <dd className="mono">{state.reproducible}</dd>
            <dt>corroborations</dt>
            <dd className="mono">{state.corroborations} independent parties</dd>
            <dt>refutations</dt>
            <dd className="mono">{state.refutations}</dd>
            <dt>disputes</dt>
            <dd className="mono">{state.disputes}</dd>
            {state.superseded_by.length > 0 && (
              <>
                <dt>superseded by</dt>
                <dd>
                  <ul className="flex flex-col gap-0.5">
                    {state.superseded_by.map((other) => (
                      <li key={other}>
                        <Hash value={other} href={`/knowledge?id=${encodeURIComponent(other)}`} chars={8} />
                      </li>
                    ))}
                  </ul>
                </dd>
              </>
            )}
            {state.retracted_by && (
              <>
                <dt>retracted by</dt>
                <dd>
                  <Hash
                    value={state.retracted_by}
                    href={`/knowledge?id=${encodeURIComponent(state.retracted_by)}`}
                    chars={8}
                  />
                </dd>
              </>
            )}
          </dl>
          <p className="hint mt-3">
            {standingHelp(state.standing)}. Counts are independent parties after collapsing
            correlated sources — one party under ten names corroborates once.
          </p>
        </Box>

        <div className="flex min-w-0 flex-col gap-4">
          <Box title="Claim">
            <dl className="kv">
              <dt>submitter</dt>
              <dd className="mono">{claim.submitter}</dd>
              <dt>objective</dt>
              <dd>
                <Link
                  href={`/challenge?id=${encodeURIComponent(claim.objective_id)}`}
                  className="text-accent hover:underline"
                >
                  challenge →
                </Link>
              </dd>
              <dt>claim</dt>
              <dd>
                <div className="flex items-start gap-1">
                  <code className="mono text-[11.5px] [overflow-wrap:anywhere]">{claim.claim_id}</code>
                  <CopyButton value={claim.claim_id} />
                </div>
              </dd>
            </dl>
          </Box>

          <Box
            title={
              <>
                Bonded attestations{" "}
                <span className="mono ml-1 font-normal text-ink-3">
                  {claim.attestations.accept + claim.attestations.reject}
                </span>
              </>
            }
          >
            {claim.attestations.accept + claim.attestations.reject === 0 ? (
              <p className="text-[12.5px] text-ink-3">
                Nobody has stood behind this verdict under bond.
              </p>
            ) : (
              <>
                <p className="text-[12.5px] text-ink-2">
                  {claim.attestations.accept} accept · {claim.attestations.reject} reject
                  {claim.attestations.slashed > 0 && (
                    <span className="text-bad"> · {claim.attestations.slashed} slashed</span>
                  )}{" "}
                  · {claim.attestations.bond_each.toLocaleString("en-US")} bonded each.
                </p>
                <ul className="mt-2 flex flex-col gap-1.5">
                  {claim.attestations.attestations.map((row) => (
                    <li key={row.attestation_id} className="text-[12px] text-ink-2">
                      <span className="mono">{row.attestor}</span> said {row.status}
                      {row.slashed && <span className="text-bad">, slashed</span>}
                    </li>
                  ))}
                </ul>
              </>
            )}
            <p className="hint mt-2">
              Beside the standing, never inside it: a bonded opinion is neither a verdict
              nor a relation.
            </p>
          </Box>
        </div>
      </div>

      <SectionHeading count={state.assertions.length}>What was said about it</SectionHeading>
      {state.assertions.length === 0 ? (
        <EmptyState title="Nothing has been said about this claim">
          Relations from later verified claims — replicates, refutes, supersedes — appear here.
        </EmptyState>
      ) : (
        <div className="box mb-5 overflow-x-auto">
          <table className="w-full min-w-[40rem] border-collapse text-left text-[12.5px]">
            <thead>
              <tr className="border-b border-edge text-[11px] text-ink-3">
                <th className="px-4 py-2 font-medium">By</th>
                <th className="px-3 py-2 font-medium">Relation</th>
                <th className="px-3 py-2 font-medium">Heard</th>
                <th className="px-4 py-2 font-medium">Voice</th>
              </tr>
            </thead>
            <tbody className="divide-edge-y">
              {state.assertions.map((row) => (
                <tr key={`${row.by}/${row.relation}`} className="hover:bg-surface-2">
                  <td className="px-4 py-2.5">
                    <Hash value={row.by} href={`/knowledge?id=${encodeURIComponent(row.by)}`} chars={8} />
                  </td>
                  <td className="mono px-3 py-2.5 text-ink">{row.relation}</td>
                  <td className="px-3 py-2.5">
                    <Badge tone={row.grounded ? "accent" : "neutral"}>
                      {row.grounded ? "counts" : "not heard"}
                    </Badge>
                  </td>
                  <td className="mono px-4 py-2.5 text-[12px] text-ink-3">
                    {row.grounded ? `class ${row.class}` : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="text-[12px] text-ink-3">{claim.note}</p>
    </>
  );
}
