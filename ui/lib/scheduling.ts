import { expectFields } from "./shape";

export type ResourceOffer = {
  cpus: number | null;
  memory_mb: number | null;
  gpus: number | null;
  storage_mb: number | null;
  concurrency: number | null;
};

export type WorkerRequirement = {
  mode: "built_in" | "external" | string;
  id?: string;
};

export type ResourceRequirements = ResourceOffer;

export type ObjectiveCapabilities = {
  worker: WorkerRequirement;
  assignment: "partitioned" | "queued" | string;
  resources: ResourceRequirements;
};

export type ChallengeAssignment = {
  objective_id: string;
  goal: string;
  statement: string;
  reward: number;
  eligible: boolean;
  reason: string;
  capabilities: ObjectiveCapabilities;
};

export type CapabilityEdge = {
  host: string;
  objective_id: string;
  assignment: "partitioned" | "queued" | string;
  worker: WorkerRequirement;
};

export type AssignmentsResponse = {
  host: string;
  resources: ResourceOffer;
  assignments: ChallengeAssignment[];
  note: string;
};

/** Read-only challenge matching for a host's current resource offer. */
export async function fetchAssignments(
  base: string,
  host?: string,
): Promise<AssignmentsResponse> {
  const query = host ? `?host=${encodeURIComponent(host)}` : "";
  const response = await fetch(`${base}/assignments${query}`, { cache: "no-store" });
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as { error?: string } | null;
    throw new Error(body?.error ?? `${base || "this node"}/assignments answered ${response.status}.`);
  }
  return expectFields<AssignmentsResponse>(
    await response.json(),
    ["host", "resources", "assignments"],
    `${base || "this node"}/assignments`,
  );
}

export function resourceSummary(resources: ResourceOffer): string {
  const parts = [
    resources.cpus == null ? null : `${resources.cpus} CPU${resources.cpus === 1 ? "" : "s"}`,
    resources.memory_mb == null ? null : `${Math.round(resources.memory_mb / 1024)} GB memory`,
    resources.gpus == null ? null : `${resources.gpus} GPU${resources.gpus === 1 ? "" : "s"}`,
    resources.concurrency == null ? null : `${resources.concurrency} slot${resources.concurrency === 1 ? "" : "s"}`,
  ].filter((part): part is string => part !== null);
  return parts.length ? parts.join(" · ") : "capacity not reported";
}

export function workerModeLabel(worker: WorkerRequirement): string {
  if (worker.mode === "built_in") {
    return worker.id ? `Cairn worker: ${worker.id}` : "Cairn worker";
  }
  return "External worker";
}
