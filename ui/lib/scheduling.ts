import { expectFields } from "./shape";

export type CpuRequirements = {
  arch?: string | null;
  vendor?: string | null;
  model?: string | null;
  features?: string[];
  min_base_khz?: number | null;
};

export type CpuProfile = {
  arch: string;
  vendor: string | null;
  model: string | null;
  features: string[];
  reported_features: string[];
  base_khz: number | null;
  max_khz: number | null;
  observed_min_khz: number | null;
  observed_max_khz: number | null;
  source: string;
  observed_at: string;
};

export type RateCard = {
  unit: string;
  rates: {
    id: string;
    workload: string;
    cpu: CpuRequirements;
    cpu_second_microunits: number;
    memory_gib_second_microunits: number;
  }[];
};

export type ResourceOffer = {
  cpus: number | null;
  memory_mb: number | null;
  gpus: number | null;
  storage_mb: number | null;
  concurrency: number | null;
  cpu_millis?: number | null;
  cpu?: CpuProfile | null;
  pricing?: RateCard | null;
};

export type WorkerRequirement = {
  mode: "built_in" | "package" | "external" | string;
  id?: string;
  /** For `package`: the solver package the objective pins (docs/solvers.md). */
  package?: string;
};

export type ResourceRequirements = Omit<ResourceOffer, "cpu" | "pricing" | "cpu_millis"> & {
  cpu?: CpuRequirements;
  invalid?: boolean;
};

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

export function resourceSummary(resources: ResourceOffer | ResourceRequirements): string {
  if ("invalid" in resources && resources.invalid) return "Invalid resource requirements";
  const cpuMillis = "cpu_millis" in resources ? resources.cpu_millis : null;
  const parts = [
    cpuMillis != null
      ? `${cpuMillis / 1000} CPU${cpuMillis === 1000 ? "" : "s"}`
      : resources.cpus == null ? null : `${resources.cpus} CPU${resources.cpus === 1 ? "" : "s"}`,
    resources.memory_mb == null ? null : `${Math.round(resources.memory_mb / 1024)} GB memory`,
    resources.gpus == null ? null : `${resources.gpus} GPU${resources.gpus === 1 ? "" : "s"}`,
    resources.concurrency == null ? null : `${resources.concurrency} slot${resources.concurrency === 1 ? "" : "s"}`,
    resources.cpu?.arch ?? null,
    resources.cpu?.features?.length ? resources.cpu.features.join(", ") : null,
  ].filter((part): part is string => part !== null);
  return parts.length ? parts.join(" · ") : "capacity not reported";
}

export function cpuSummary(cpu: CpuProfile | null | undefined): string | null {
  if (!cpu) return null;
  const parts = [cpu.model ?? cpu.arch];
  if (cpu.base_khz != null) parts.push(`${(cpu.base_khz / 1_000_000).toFixed(2)} GHz base`);
  if (cpu.max_khz != null) parts.push(`${(cpu.max_khz / 1_000_000).toFixed(2)} GHz boost ceiling`);
  const features = cpu.features.filter((name) => name.startsWith("avx") || ["sve", "sve2", "neon"].includes(name));
  if (features.length) parts.push(features.join(", "));
  return parts.join(" · ");
}

export function workerModeLabel(worker: WorkerRequirement): string {
  if (worker.mode === "built_in") {
    return worker.id ? `Cairn worker: ${worker.id}` : "Cairn worker";
  }
  if (worker.mode === "package") return "Published solver";
  return "External worker";
}
