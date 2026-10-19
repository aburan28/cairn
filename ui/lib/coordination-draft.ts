import { type Bridge, briefProblem } from "./draft";

export type CoordinationPhase = "idle" | "drafting" | "checking" | "ready" | "launching" | "posted" | "error";
export type CoordinationStatus = {
  phase: CoordinationPhase;
  brief: string;
  budget: string;
  message: string;
  provider: string;
  draftId?: string;
  objectiveId?: string;
  spec?: string;
  statement?: string;
  unit?: string;
  units?: string;
  unitPrice?: string;
  reward?: string;
  notes?: string;
};
const phases = new Set<CoordinationPhase>(["idle", "drafting", "checking", "ready", "launching", "posted", "error"]);

/** Keep amounts as decimal strings all the way to Swift's UInt64. */
export function coordinationBudget(text: string): string {
  const clean = text.trim().replace(/[,_]/g, "");
  if (!clean) {
    if (!text.trim()) return "";
    throw new Error("Budget must be a positive whole number of units.");
  }
  if (!/^\d+$/.test(clean) || BigInt(clean) === 0n || BigInt(clean) > 18446744073709551615n) {
    throw new Error("Budget must be a positive whole number no greater than 18446744073709551615.");
  }
  return BigInt(clean).toString();
}

export function coordinationBusy(phase: CoordinationPhase | undefined): boolean {
  return phase === "drafting" || phase === "checking" || phase === "launching";
}

function status(value: unknown): CoordinationStatus {
  const row = value as Partial<CoordinationStatus> | null;
  if (!row || !phases.has(row.phase as CoordinationPhase)
      || [row.brief, row.budget, row.message, row.provider].some((field) => typeof field !== "string")) {
    throw new Error("This version of Cairn cannot generate coordinated challenges. Update Cairn and try again.");
  }
  if (["ready", "launching", "posted"].includes(row.phase!)) {
    if ([row.draftId, row.spec, row.statement, row.unit, row.units, row.unitPrice, row.reward, row.notes]
        .some((field) => typeof field !== "string") || !/^sha256:[0-9a-f]{64}$/.test(row.objectiveId ?? "")) {
      throw new Error("Cairn returned an incomplete challenge spec. Generate it again before launching.");
    }
  }
  return row as CoordinationStatus;
}

async function request(bridge: Bridge, message: unknown): Promise<CoordinationStatus> {
  try { return status(await bridge.postMessage(message)); }
  catch (cause) { throw new Error(cause instanceof Error ? cause.message : String(cause)); }
}

export function coordinationStatus(bridge: Bridge): Promise<CoordinationStatus> {
  return request(bridge, { kind: "coordination-status" });
}

export function generateCoordination(bridge: Bridge, brief: string, budget: string): Promise<CoordinationStatus> {
  const problem = briefProblem(brief);
  if (problem) return Promise.reject(new Error(problem));
  let amount: string;
  try { amount = coordinationBudget(budget); }
  catch (cause) { return Promise.reject(cause); }
  return request(bridge, { kind: "draft-coordination", brief: brief.trim(), budget: amount });
}

export function cancelCoordination(bridge: Bridge): Promise<CoordinationStatus> {
  return request(bridge, { kind: "cancel-coordination" });
}

export function launchCoordination(bridge: Bridge, draftId: string): Promise<CoordinationStatus> {
  return request(bridge, { kind: "launch-coordination", draftId });
}
