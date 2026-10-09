import { appBridge, type Bridge } from "./draft";

export type WorkStatus = {
  state: "idle" | "running" | "pausing" | "paused" | "stopping" | "exited";
  objective?: string;
  worker?: string;
  started_at?: string;
  cpu_percent?: number | null;
  rounds_completed?: number;
  rounds_per_minute?: number | null;
  exit_code?: number;
  activity?: string;
  leaving?: boolean;
  threads?: number | null;
  gpus?: string | null;
  hours_per_day?: number | null;
};

/** Only Cairn.app owns the worker process. A node HTTP route cannot start it. */
export async function readWorkStatus(bridge: Bridge): Promise<WorkStatus> {
  const value = await bridge.postMessage({ kind: "work-status" });
  if (!value || typeof value !== "object") throw new Error("Cairn.app did not return work status.");
  const status = value as WorkStatus;
  if (!["idle", "running", "pausing", "paused", "stopping", "exited"].includes(status.state)) throw new Error("Cairn.app returned an unknown work state.");
  return status;
}

export async function startWork(bridge: Bridge, objective: string): Promise<void> {
  await bridge.postMessage({ kind: "start-work", objective });
}

export async function stopWork(bridge: Bridge): Promise<void> {
  await bridge.postMessage({ kind: "stop-work" });
}

export async function pauseWork(bridge: Bridge): Promise<void> {
  await bridge.postMessage({ kind: "pause-work" });
}

export async function resumeWork(bridge: Bridge): Promise<void> {
  await bridge.postMessage({ kind: "resume-work" });
}

export async function exitWork(bridge: Bridge): Promise<void> {
  await bridge.postMessage({ kind: "exit-work" });
}

export { appBridge };
