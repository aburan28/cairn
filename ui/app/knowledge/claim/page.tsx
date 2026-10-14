"use client";

import Link from "next/link";
import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { useNode } from "@/components/hooks";
import { Badge, Box, CopyButton, EmptyState, Hash, Note, PageHeader, Skeleton } from "@/components/ui";
import { fetchKnowledgeClaim, type KnowledgeClaim, type Policy } from "@/lib/knowledge";

/** A static route with a query id, so it can be embedded in the node's exported UI. */
export default function Page() {
  return (
    <Suspense fallback={<Skeleton className="h-32" />}>
      <ClaimView />
    </Suspense>
  );
}

function ClaimView() {
  const id = useSearchParams().get("id") ?? "";
  const base = useNode();
  const [policy, setPolicy] = useState<Policy>("default");
  const [claim, setClaim] = useState<KnowledgeClaim | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (base === null || !id) return;
    let current = true;
    setClaim(null);
    setError(null);
    void fetchKnowledgeClaim(base, id, policy)
      .then((answer) => { if (current) setClaim(answer); })
      .catch((cause: unknown) => {
        if (current) setError(cause instanceof Error ? cause.message : String(cause));
      });
    return () => { current = false; };
  }, [base, id, policy]);

  const actions = (
    <div className="segmented" role="group" aria-label="Confidence policy">
      <button type="button" aria-pressed={policy === "default"} onClick={() => setPolicy("default")}>Standard</button>
      <button type="button" aria-pressed={policy === "demanding"} onClick={() => setPolicy("demanding")}>Demanding</button>
    </div>
  );

  if (!id) {
    return <EmptyState title="Choose a result">Open a result from the <Link href="/knowledge" className="text-accent">Knowledge page</Link>.</EmptyState>;
  }

  return (
    <>
      <PageHeader
        crumb={{ href: "/knowledge", label: "Knowledge" }}
        title="Result evidence"
        subtitle="The verdict, later verified claims about it, and checks backed by a bond."
        actions={actions}
      />
      {error && <Note title="Could not read this result" tone="bad">{error}</Note>}
      {!claim && !error && <Skeleton className="h-48" />}
      {claim && <Evidence claim={claim} />}
    </>
  );
}

function Evidence({ claim }: { claim: KnowledgeClaim }) {
  const state = claim.state;
  const tone = state.standing === "accepted" || state.standing === "corroborated"
    ? "accent" : state.standing === "refuted" || state.standing === "withdrawn" ? "bad" : "warn";
  const confidence = Math.max(0, Math.min(100, Math.floor(state.confidence_per_mille / 10)));
  return (
    <>
      <div className="mb-4 flex flex-wrap items-center gap-3 text-[13px]">
        <Badge tone={tone}>{state.standing}</Badge>
        <span>{confidence}% confidence under the {claim.policy.name} policy</span>
        <Hash value={claim.claim_id} chars={10} />
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Box title="Standing from the log">
          <dl className="kv">
            <dt>pinned checker</dt><dd>{state.verdict ?? "no verdict"}</dd>
            <dt>re-derivable here</dt><dd>{state.reproducible}</dd>
            <dt>independent corroborations</dt><dd>{state.corroborations}</dd>
            <dt>refutations</dt><dd>{state.refutations}</dd>
            <dt>disputes</dt><dd>{state.disputes}</dd>
            {state.retracted_by && <><dt>retracted by</dt><dd><ResultLink id={state.retracted_by} /></dd></>}
            {state.superseded_by.length > 0 && <><dt>superseded by</dt><dd>{state.superseded_by.map((id) => <ResultLink key={id} id={id} />)}</dd></>}
          </dl>
          <p className="hint mt-3">Standing and confidence are this node&rsquo;s derivation from the log. Neither changes settlement.</p>
        </Box>
        <Box title="Claim and bonded checks">
          <dl className="kv">
            <dt>submitter</dt><dd className="mono break-all">{claim.submitter}</dd>
            <dt>objective</dt><dd><Link href={`/challenge?id=${encodeURIComponent(claim.objective_id)}`} className="text-accent">Open challenge →</Link></dd>
            <dt>claim id</dt><dd className="flex items-start gap-1"><code className="mono break-all text-[11px]">{claim.claim_id}</code><CopyButton value={claim.claim_id} /></dd>
          </dl>
          <p className="mt-4 text-[13px] text-ink-2">
            {claim.attestations.accept} accept · {claim.attestations.reject} reject · {claim.attestations.slashed} slashed
          </p>
          {claim.attestations.attestations.length > 0 ? (
            <ul className="mt-2 flex flex-col gap-1.5">
              {claim.attestations.attestations.map((row) => (
                <li key={row.attestation_id} className="text-[12px] text-ink-2">
                  <span className="mono break-all">{row.attestor}</span> said {row.status}{row.slashed && <span className="text-bad">, slashed</span>}
                </li>
              ))}
            </ul>
          ) : <p className="hint mt-2">Nobody has stood behind this verdict under bond.</p>}
          <p className="hint mt-3">Bonded opinions are shown beside standing; they do not replace the pinned checker&rsquo;s verdict.</p>
        </Box>
      </div>
      <Box title={`What later claims said (${state.assertions.length})`}>
        {state.assertions.length === 0 ? (
          <p className="text-[13px] text-ink-3">No verified relation has been asserted about this result.</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {state.assertions.map((row) => (
              <li key={`${row.by}/${row.relation}`} className="flex flex-wrap items-center gap-2 text-[12px]">
                <ResultLink id={row.by} />
                <span>{row.relation}</span>
                <Badge tone={row.grounded ? "accent" : "neutral"}>{row.grounded ? `counts · class ${row.class}` : "not grounded"}</Badge>
              </li>
            ))}
          </ul>
        )}
      </Box>
      <p className="mt-3 text-[12px] text-ink-3">{claim.note}</p>
    </>
  );
}

function ResultLink({ id }: { id: string }) {
  return <Hash value={id} href={`/knowledge/claim?id=${encodeURIComponent(id)}`} chars={8} />;
}
