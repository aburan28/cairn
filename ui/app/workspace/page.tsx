"use client";

import Link from "next/link";
import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { useNodeRead } from "@/components/hooks";
import { Badge, Card, CopyButton, Hash, LiveStamp, Note, PageHeader, Sheet } from "@/components/ui";
import { fetchWorkspace, fetchWorkspaces, replayCommand, type Run, type Workspace } from "@/lib/workspace";

export default function Page() { return <Suspense><Selected /></Suspense>; }
function Selected() {
  const params = useSearchParams();
  const id = params.get("space");
  return id ? <Detail key={id} id={id} /> : <Listing objective={params.get("objective")} />;
}

function Listing({ objective }: { objective: string | null }) {
  const { value, error, readAt, refresh, loading } = useNodeRead(fetchWorkspaces);
  const rows = value?.workspaces.filter((workspace) => !objective || workspace.objective_id === objective) ?? [];
  return <>
    <PageHeader title="Workspaces" subtitle="Contributors, experiments and the inputs each run used." actions={<button className="btn btn-sm" onClick={() => void refresh()} disabled={loading}>Refresh</button>} />
    <LiveStamp at={readAt} error={error} />
    {error && <Note tone="warn">{error}</Note>}
    {value && rows.length === 0 && <Note title="No published workspace">{objective ? "No published lab is linked to this challenge. " : ""}{value.note} Recipes and input bytes become public when a lab is shared.</Note>}
    {!!value?.unavailable && <Note tone="warn">{value.unavailable} configured workspace(s) could not be read. Refresh after the operator restores them.</Note>}
    <div className="mt-4 grid gap-3 md:grid-cols-2">{rows.map((workspace) => <Card key={workspace.space} className="card-pad min-w-0">
      <Link className="text-accent" href={`/workspace?space=${workspace.space}`}>{workspace.name}</Link>
      <p className="hint">{workspace.ops} operations · {workspace.runs} runs · {workspace.conflicts} conflicts</p>
      <Hash value={workspace.space} />
    </Card>)}</div>
    {objective && <Link className="btn btn-sm mt-4" href="/workspace">All workspaces</Link>}
  </>;
}

function Detail({ id }: { id: string }) {
  const { base, value, error, readAt, refresh, loading } = useNodeRead((base) => fetchWorkspace(base, id), { key: id });
  return <>
    <PageHeader title={value?.summary.name ?? "Workspace"} crumb={{ href: "/workspace", label: "Workspaces" }} subtitle="Causal history and reproducible input snapshots." actions={<button className="btn btn-sm" disabled={loading} onClick={() => void refresh()}>Refresh</button>} />
    <LiveStamp at={readAt} error={error} />
    {error && <Note tone="warn">{error}{value && " Showing the last successful read."}</Note>}
    {!value && !error && <p className="hint">Reading workspace…</p>}
    {value && <WorkspaceView workspace={value} base={base ?? ""} />}
  </>;
}

function WorkspaceView({ workspace, base }: { workspace: Workspace; base: string }) {
  const [action, setAction] = useState<{ run: Run; mode: "exact" | "reapply" | "promote" } | null>(null);
  const objective = workspace.summary.objective_id;
  return <>
    <Note>{workspace.note}</Note>
    <div className="my-4 flex flex-wrap items-center gap-2">
      <Badge tone="accent">{workspace.summary.ops} operations</Badge><Badge tone={workspace.conflicts.length ? "warn" : "accent"}>{workspace.conflicts.length} conflicts</Badge>
      {objective && <Link href={`/challenge?id=${objective}`} className="btn btn-sm">Challenge and frontier</Link>}
      {workspace.frontier && <span className="text-[12px]">Settled frontier: <Hash value={workspace.frontier.claim_id} /> · score {workspace.frontier.score}</span>}
    </div>
    <section className="mb-5">
      <h2 className="mb-2 font-semibold">Unresolved choices</h2>
      {!workspace.conflicts.length && <p className="hint">No conflicting registers in this read.</p>}
      {workspace.conflicts.map((conflict) => <Card className="card-pad mb-2 min-w-0" key={`${conflict.kind}:${conflict.path}`}>
        <h3 className="mono break-all text-[13px]">{conflict.path} <Badge tone="warn">{conflict.kind}</Badge></h3>
        <ul className="mt-2 space-y-2">{conflict.values.map((value) => <li key={value.version} className="text-[12px]">
          <Hash value={value.author} /> · <span className="mono break-all">{value.version}</span>
          <pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-all">{value.value === null ? "deleted" : JSON.stringify(value.value)}{value.exec === undefined ? "" : value.exec ? " · executable" : " · data file"}</pre>
        </li>)}</ul>
      </Card>)}
      {!!workspace.conflicts.length && <p className="hint">Resolve all versions you have read with <code>cairn lab resolve</code>. Runs refuse conflicting inputs; unrelated conflicts can remain open.</p>}
    </section>
    <section className="mb-5">
      <h2 className="mb-2 font-semibold">Candidate runs</h2>
      {!workspace.runs.length && <p className="hint">Run an experiment with <code>cairn lab exec</code> or the lab MCP tool to publish its receipt and outputs together.</p>}
      {workspace.runs.map((run) => <Card className="card-pad mb-3 min-w-0" key={run.id}>
        <div className="flex flex-wrap items-center gap-2 text-[12px]"><Hash value={run.id} /><span>by</span><Hash value={run.author} /><time>{run.time}</time><Badge tone={run.receipt.error ? "warn" : run.receipt.exit_status === 0 ? "accent" : "warn"}>{run.receipt.error ? "runtime unavailable" : `exit ${run.receipt.exit_status ?? "unknown"}`}</Badge></div>
        {run.receipt.lineage && <p className="hint">{run.receipt.lineage.mode} of <Hash value={run.receipt.lineage.of} /></p>}
        {run.receipt.lineage?.baseline && <p className="hint">Declared research baseline <Hash value={run.receipt.lineage.baseline} />. This reference grants no citation authority.</p>}
        {run.receipt.replay_comparison && <p className="hint">Replay output bytes {run.receipt.replay_comparison.outputs_identical ? "match the original" : "differ from the original"}. This comparison is not a verifier verdict.</p>}
        <pre className="my-2 whitespace-pre-wrap break-all text-[12px]">{JSON.stringify(run.receipt.argv ?? [])}</pre>
        <details className="text-[12px]"><summary className="cursor-pointer">Pinned inputs and receipt</summary>
          <p className="hint">Environment <Hash value={run.receipt.env?.tree ?? "not recorded"} />. Input heads are the observed snapshot, distinct from operations received while the run finished.</p>
          <ul>{run.receipt.input_heads?.map((head) => <li key={head}><Hash value={head} /></li>)}</ul>
          {run.receipt.mounts?.filter((mount) => mount.kind !== "output").map((mount, i) => <div key={i} className="mt-2">
            <h4 className="mono break-all">{mount.prefix || mount.kind} → {mount.target}</h4>
            {mount.snapshot?.map((file) => <p className="mono break-all" key={file.path}>{file.path} · {file.exec ? "executable" : "data"} · {file.blob ?? "directory"} · {file.versions.join(", ")}</p>)}
          </div>)}
          <pre className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-all">{JSON.stringify(run.receipt, null, 2)}</pre>
        </details>
        <div className="mt-3 flex flex-wrap gap-2">
          <button className="btn btn-sm" disabled={run.receipt.replay_version !== 1 || run.receipt.mounts?.some((mount) => mount.kind === "host" && !mount.snapshot)} onClick={() => setAction({ run, mode: "exact" })}>Replay recorded inputs</button>
          <button className="btn btn-sm" disabled={run.receipt.replay_version !== 1 || run.receipt.mounts?.some((mount) => mount.kind === "host" && !mount.snapshot)} onClick={() => setAction({ run, mode: "reapply" })}>Run on current workspace</button>
          {!!run.candidates.length && objective && <button className="btn btn-sm" onClick={() => setAction({ run, mode: "promote" })}>Prepare promotion</button>}
        </div>
        {run.receipt.replay_version !== 1 && <p className="hint">This older receipt has no replayable input manifest.</p>}
        {run.receipt.mounts?.some((mount) => mount.kind === "host" && !mount.snapshot) && <p className="hint">A host input was kept private. Its bytes were not shared, so this run cannot be replayed from the lab. Explicitly snapshot host inputs when publishing a replayable experiment.</p>}
        {run.candidates.map((candidate) => <div key={candidate.path} className="mt-3 text-[12px]">
          <a className="text-accent underline" href={`${base}/workspace/${workspace.summary.space}/blob/${candidate.blob}`} download="artifact.json">Download artifact.json</a> · <Hash value={candidate.artifact_hash} />
          {!candidate.claims.length && <p className="hint">No matching claim in this node’s log. A successful experiment is not a verified result.</p>}
          {candidate.claims.map((claim) => <p key={claim.claim_id}><Hash value={claim.claim_id} /> · {claim.frontier ? "settled frontier" : claim.settled ? "settled" : claim.accepted ? "accepted · awaiting settlement" : "admitted claim · inspect its verdict"}</p>)}
        </div>)}
      </Card>)}
      {workspace.runs_truncated && <p className="hint">Showing the latest 100 runs. Use <code>cairn lab runs</code> on a replica for older history.</p>}
    </section>
    <section>
      <h2 className="mb-2 font-semibold">Contributor history</h2>
      <p className="hint">Lamport order respects causal parents. Adjacent concurrent operations are display order, not scientific approval or payment priority.</p>
      <div className="overflow-x-auto"><table className="w-full text-left text-[12px]"><thead><tr><th>Order</th><th>Contributor / operation</th><th>Causal parents</th></tr></thead><tbody>{workspace.operations.map((op) => <tr key={op.id} className="border-t border-edge align-top">
        <td className="py-2 pr-3">{op.lamport}<br />{op.kind}</td><td className="min-w-40 py-2 pr-3"><Hash value={op.author} /><br /><Hash value={op.id} /><br /><time>{op.time}</time></td>
        <td className="py-2">{op.deps.length ? op.deps.map((dep) => <div key={dep}><Hash value={dep} /></div>) : "genesis"}</td>
      </tr>)}</tbody></table></div>
      {workspace.operations_truncated && <p className="hint">Showing the latest 200 operations. Full signed history remains in the lab; sync a replica to verify it independently.</p>}
    </section>
    {action && <Sheet title={action.mode === "promote" ? "Prepare a verified promotion" : action.mode === "exact" ? "Replay recorded inputs" : "Run on current workspace"} onClose={() => setAction(null)}>
      {action.mode === "promote" ? <>
        <p>Download this run’s artifact.json. Ask your connected Cairn agent to score it with the challenge’s pinned verifier. Inspect the current frontier, then commit and reveal the claim through the normal submission tools.</p>
        <p className="hint">A frontier advance may require an explicit integration recipe. Lab ancestry grants no citation or payment authority. An unavailable verifier teaches nothing about the artifact.</p>
        <pre className="my-3 whitespace-pre-wrap break-all text-[12px]">{`Objective: ${objective}\nRun: ${action.run.id}\nArtifact: ${action.run.candidates[0]?.artifact_hash}\nUse score_candidate first. Read frontier_status for current citation capabilities. If accepted, submit_claim commits, then reveals in a later epoch. Keep this run as lineage; do not treat lab parents as payment citations.`}</pre>
        <CopyButton value={`Score artifact.json for objective ${objective} with score_candidate, inspect frontier_status, and use the normal commit/reveal workflow if it passes. Preserve lab run ${action.run.id} as research lineage. Lab parents are not citation authority.`} />
        <Link className="btn btn-sm ml-2" href={`/challenge?id=${objective}`}>Open challenge</Link>
      </> : <>
        <p>{action.mode === "exact" ? "Use the recorded input blobs, environment and recipe. The workspace’s current files are ignored. Network-dependent runs cannot be replayed exactly." : "Run the old recipe against today’s unambiguous lab files. Host input snapshots stay pinned. Integrate any intended algorithm change before running; this does not merge source code."}</p>
        <p className="hint">Run on your local lab replica with your own signing identity. A public reader cannot execute commands or sign for an operator. Check the plan first by adding <code>--check</code>. Both actions publish a new receipt with lineage; runtime limits and isolation remain visible in it.</p>
        <pre className="my-3 whitespace-pre-wrap break-all text-[12px]">{replayCommand(action.run.id, action.mode === "reapply", workspace.frontier?.claim_id)}</pre>
        <CopyButton value={replayCommand(action.run.id, action.mode === "reapply", workspace.frontier?.claim_id)} />
        {action.mode === "reapply" && workspace.frontier && <p className="hint">The baseline flag records the frontier this node currently reports. Integrate that baseline into your lab inputs before running; the flag neither fetches nor merges code.</p>}
        <p className="hint">Use <code>--lab DIR</code> before <code>replay</code> if your replica is not .cairn-lab. Replaying inputs does not promise identical output from a nondeterministic or unconfined program.</p>
      </>}
    </Sheet>}
  </>;
}
