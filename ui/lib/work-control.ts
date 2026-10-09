import { appBridge, type Bridge } from "./draft";

export type WorkStatus = {
  state: "idle" | "running" | "stopping" | "exited";
  objective?: string;
  worker?: string;
  started_at?: string;
  cpu_percent?: number | null;
  exit_code?: number;
  activity?: string;
};

/** Only Cairn.app owns the worker process. A node HTTP route cannot start it. */
export async function readWorkStatus(bridge: Bridge): Promise<WorkStatus> {
  const value = await bridge.postMessage({ kind: "work-status" });
  if (!value || typeof value !== "object") throw new Error("Cairn.app did not return work status.");
  const status = value as WorkStatus;
  if (!["idle", "running", "stopping", "exited"].includes(status.state)) throw new Error("Cairn.app returned an unknown work state.");
  return status;
}

export async function startWork(bridge: Bridge, objective: string): Promise<void> {
  await bridge.postMessage({ kind: "start-work", objective });
}

export async function stopWork(bridge: Bridge): Promise<void> {
  await bridge.postMessage({ kind: "stop-work" });
}

export { appBridge };
