"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { type Bridge } from "@/lib/draft";
import { fetchProgress, formatAge, formatRate, workerRate, type ReportedWorker } from "@/lib/progress";
import { appBridge, exitWork, pauseWork, readWorkStatus, resumeWork, startWork, stopWork, type WorkStatus } from "@/lib/work-control";
import { Badge } from "@/components/ui";

/** Process control is local to Cairn.app. The node supplies the worker's
 * reported search rate; the app supplies measured CPU for its process tree. */
export function WorkPanel({ objective, base }: { objective: string; base: string }) {
  const [bridge, setBridge] = useState<Bridge | null>(null);
  const [status, setStatus] = useState<WorkStatus | null>(null);
  const [worker, setWorker] = useState<ReportedWorker | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [supported, setSupported] = useState(true);
  const [setupOpen, setSetupOpen] = useState(false);

  useEffect(() => setBridge(appBridge()), []);

  const refresh = useCallback(async () => {
    if (!bridge) return;
    try {
      const next = await readWorkStatus(bridge);
      setSupported(true);
      setStatus(next);
      if (next.state === "running" || next.state === "pausing" || next.state === "paused" || next.state === "stopping") setSetupOpen(false);
      if ((next.state === "running" || next.state === "pausing" || next.state === "paused" || next.state === "stopping") && next.objective && next.worker) {
        const progress = await fetchProgress(next.objective, base);
        setWorker(progress.reported.workers.find((row) => row.worker === next.worker) ?? null);
      } else {
        setWorker(null);
      }
      setError(null);
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : String(cause);
      if (message.includes("work-status") || message.includes("work state")) setSupported(false);
      setError(message);
    }
  }, [bridge, base]);

  useEffect(() => {
    if (!bridge) return;
    void refresh();
    const timer = setInterval(() => {
      if (document.visibilityState === "visible") void refresh();
    }, 5000);
    return () => clearInterval(timer);
  }, [bridge, refresh]);

  const act = async (action: "start" | "pause" | "resume" | "stop" | "exit") => {
    if (!bridge) return;
    setBusy(true);
    setError(null);
    try {
      if (action === "start") { await startWork(bridge, objective); setSetupOpen(true); }
      else if (action === "pause") await pauseWork(bridge);
      else if (action === "resume") await resumeWork(bridge);
      else if (action === "exit") await exitWork(bridge);
      else await stopWork(bridge);
      await refresh();
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : String(cause);
      if (message !== "Cancelled.") setError(message);
    } finally {
      setBusy(false);
    }
  };

  const draining = status?.state === "stopping";
  const paused = status?.state === "paused";
  const pausing = status?.state === "pausing";
  const running = status?.state === "running" || pausing || paused || draining;
  const onThisGoal = running && status.objective === objective;
  const rate = !paused && worker?.status === "live" ? workerRate(worker) : null;
  const roundRate = paused ? null : status?.rounds_per_minute;

  return (
    <section className="box mb-5 p-4" aria-label="My work on this Mac">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-[15px] font-semibold text-ink">My work on this Mac</h2>
            {running && <Badge tone={draining || paused || pausing ? "neutral" : "accent"}>{draining ? "Finishing" : pausing ? "Pausing" : paused ? "Paused" : "Working"}</Badge>}
          </div>
          <p className="mt-1 text-[12.5px] text-ink-2">
            {!bridge
              ? "Open this goal in Cairn.app to control a worker and see this Mac’s CPU use."
              : draining
                ? `Finishing this round and revealing pending answers before ${status?.leaving ? "exiting this task" : "stopping"}.`
                : pausing
                  ? "Finishing the current round before pausing. Pending answers will still be revealed."
                : paused
                  ? "Paused after this round. Pending answers are still revealed; Resume continues the same task."
                : running
                  ? onThisGoal ? `Working as ${status.worker}.` : `This Mac is working on another goal as ${status.worker}.`
                : setupOpen ? "Finish resource setup in the Cairn.app window, then press Start there." : status?.state === "exited" ? "Stopped. Start again with your saved settings, or exit this task." : "Choose resources and start this goal on this Mac."}
          </p>
        </div>
        {bridge && (
          <div className="flex flex-wrap gap-2">
            {running ? (
              <>
                <button className="btn btn-sm" type="button" disabled={busy || draining} onClick={() => void act(paused || pausing ? "resume" : "pause")}>{paused || pausing ? "Resume" : "Pause"}</button>
                <button className="btn btn-sm" type="button" disabled={busy || draining} onClick={() => void act("stop")}>{draining ? "Finishing safely…" : "Stop"}</button>
                <button className="btn btn-sm" type="button" disabled={busy || status?.leaving} onClick={() => void act("exit")}>Exit task</button>
              </>
            ) : (
              <>
                <button className="btn btn-primary btn-sm" type="button" disabled={busy || !objective || !supported} onClick={() => void act("start")}>Set up &amp; start</button>
                {status?.state === "exited" && <button className="btn btn-sm" type="button" disabled={busy} onClick={() => void act("exit")}>Exit task</button>}
              </>
            )}
          </div>
        )}
      </div>
      {running && (
        <div className="mt-4 grid grid-cols-2 gap-3 border-t border-edge pt-4 sm:grid-cols-4">
          <Metric label="CPU used now" value={status.cpu_percent == null ? "Reading…" : `${Math.round(status.cpu_percent)}%`} help="100% is one busy CPU core; includes the solver." />
          <Metric
            label={rate && rate > 0 ? "Search rate" : "Round rate"}
            value={paused ? "Paused" : rate && rate > 0 ? formatRate(rate) : roundRate == null ? "Measuring…" : `${roundRate.toFixed(1)} rounds/min`}
            help={paused ? "No new search round starts while paused; pending answers are still revealed."
              : rate && rate > 0
              ? "From this worker's recent node report, when its solver measures steps."
              : `${status.rounds_completed ?? 0} solver rounds complete. Each round can take a different amount of work.`}
          />
          <Metric label="Last report" value={worker ? formatAge(worker.age_seconds) : "Waiting…"} help="Workers report to the node while a solver runs." />
          <Metric label="Work started" value={status.started_at ? new Date(status.started_at).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }) : "—"} help="Local process start time." />
        </div>
      )}
      {running && (
        <div className="mt-4 rounded-lg border border-edge bg-surface-2 px-3 py-2 text-[12px] text-ink-2">
          <span className="font-medium text-ink">{paused || pausing ? "Last assigned task" : "Current task"}</span>
          <span className="ml-2">
            {worker?.units ? `Units ${worker.units.first}–${worker.units.end - 1}`
              : worker?.unit != null ? `Unit ${worker.unit}` : "Waiting for the first assigned slice"}
            {worker?.epoch != null ? ` · epoch ${worker.epoch}` : ""}
          </span>
          {worker && <span className="ml-2">· {worker.units_submitted} submitted · {worker.units_pending} pending (worker report)</span>}
        </div>
      )}
      {running && status.activity && <p className="mt-3 text-[12px] text-ink-2" aria-live="polite">Latest activity: {status.activity}</p>}
      {running && <p className="mt-2 text-[11.5px] text-ink-3">Offered resources: {status.threads ?? "default"} CPU threads · {status.gpus ? `GPU ${status.gpus}` : "CPU only"} · {status.hours_per_day && status.hours_per_day < 24 ? `${status.hours_per_day} h/day` : "no daily limit"}. The solver must honor the CPU and GPU offer. Stop and Exit finish pending reveals.</p>}
      {status?.state === "exited" && status.activity && <p className="mt-3 text-[12px] text-ink-2">Last activity: {status.activity}</p>}
      {error && <p className="mt-3 text-[12px] text-warn" role="alert">{error}</p>}
      {!bridge && <Link href="/contribute#compute" className="mt-3 inline-block text-[12.5px] text-accent hover:underline">See ways to contribute →</Link>}
      {running && !paused && !rate && <p className="mt-2 text-[11.5px] text-ink-3">Round rate counts completed solver runs. Search steps appear when the solver measures them.</p>}
    </section>
  );
}

function Metric({ label, value, help }: { label: string; value: string; help: string }) {
  return <div title={help}><div className="text-[11px] text-ink-3">{label}</div><div className="mt-1 text-[16px] font-semibold text-ink">{value}</div></div>;
}
