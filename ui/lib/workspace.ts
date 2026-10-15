/** The node supplies identities and ledger outcomes; the reader derives neither. */
export type WorkspaceSummary = { space: string; name: string; ops: number; conflicts: number; runs: number; objective_id: string | null };
export type PinnedFile = { path: string; blob: string | null; size: number; exec: boolean; versions: string[] };
export type Run = {
  id: string; author: string; time: string;
  receipt: {
    replay_version?: number; input_heads?: string[]; argv?: string[]; cwd?: string;
    env?: { name: string; tree: string; manifest?: string };
    mounts?: { kind: string; prefix?: string; target: string; single?: boolean; snapshot?: PinnedFile[] }[];
    lineage?: { of: string; mode: string; baseline?: string };
    replay_comparison?: { outputs_identical: boolean; stdout_identical: boolean; stderr_identical: boolean; changed_paths: string[] };
    error?: string | null; exit_status?: number | null;
    [key: string]: unknown;
  };
  outputs: { path: string; blob: string | null; size: number }[];
  candidates: { path: string; blob: string; artifact_hash: string; claims: { claim_id: string; accepted: boolean; settled: boolean; frontier: boolean }[] }[];
};
export type Workspace = {
  summary: WorkspaceSummary; heads: string[];
  conflicts: { kind: string; path: string; values: { author: string; version: string; value: unknown; exec?: boolean }[] }[];
  runs: Run[]; runs_truncated: boolean;
  operations: { id: string; author: string; lamport: number; kind: string; time: string; deps: string[] }[];
  operations_truncated: boolean; frontier: { claim_id: string; score: number } | null; note: string;
};
export async function fetchWorkspaces(base: string): Promise<{ workspaces: WorkspaceSummary[]; note: string; unavailable: number }> {
  const response = await fetch(`${base}/workspaces`, { cache: "no-store" });
  if (!response.ok) throw new Error(response.status === 404 ? "This node predates shared workspaces. Update the node to publish a lab." : `Could not read workspaces (${response.status}).`);
  const body = await response.json();
  if (!Array.isArray(body.workspaces) || typeof body.note !== "string") throw new Error("The node returned an unreadable workspace list.");
  return body;
}
export async function fetchWorkspace(base: string, id: string): Promise<Workspace> {
  if (!/^sha256:[0-9a-f]{64}$/.test(id)) throw new Error("Invalid workspace id.");
  const response = await fetch(`${base}/workspace/${id}`, { cache: "no-store" });
  if (!response.ok) throw new Error(`This workspace is not published or could not be read (${response.status}).`);
  const body = await response.json();
  if (body?.summary?.space !== id || !Array.isArray(body.runs) || !Array.isArray(body.operations) || !Array.isArray(body.conflicts)) throw new Error("The node returned an unreadable workspace.");
  return body;
}

/** Fixed ids only; user-authored names never become executable shell text. */
export function replayCommand(run: string, reapply = false, baseline?: string): string {
  if (!/^sha256:[0-9a-f]{64}$/.test(run)) throw new Error("Invalid run id.");
  if (baseline && !/^sha256:[0-9a-f]{64}$/.test(baseline)) throw new Error("Invalid baseline id.");
  return `cairn lab replay ${run}${reapply ? ` --reapply${baseline ? ` --baseline ${baseline}` : ""}` : ""} --identity "$CAIRN_LAB_IDENTITY"`;
}
