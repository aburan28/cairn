"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { fetchSubmission, type Queued, type SubmissionStatus } from "@/lib/submit";
import { useEvery } from "./hooks";
import { Badge, Card, Hash, Note, SectionHeading } from "./ui";

export function SubmissionTracker({ receipt, base }: { receipt: Queued; base: string }) {
  const [result, setResult] = useState<SubmissionStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reading, setReading] = useState(false);
  const [readAt, setReadAt] = useState<string | null>(null);
  const generation = useRef(0);
  const pending = useRef(false);
  useEffect(() => () => { generation.current += 1; }, []);
  const read = useCallback(async () => {
    if (pending.current) return;
    const version = generation.current;
    pending.current = true;
    setReading(true);
    try {
      const next = await fetchSubmission(receipt.queued, base);
      if (version !== generation.current) return;
      setResult(next);
      setError(null);
      setReadAt(new Date().toLocaleTimeString());
    } catch (cause) {
      if (version === generation.current) setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      pending.current = false;
      if (version === generation.current) setReading(false);
    }
  }, [receipt.queued, base]);
  useEvery(read, 5, !result || result.status === "queued");
  const status = result?.status ?? "queued";
  const record = result?.record_id || receipt.record_id;
  return (
    <div aria-live="polite"><Card className="card-pad">
      <SectionHeading>Submission tracking</SectionHeading>
      <Badge tone={status === "admitted" ? "accent" : status === "refused" ? "bad" : "warn"}>
        {result ? status : "queued · awaiting status"}
      </Badge>
      <p className="hint">{result?.note ?? receipt.note}</p>
      <div className="mt-3 flex flex-wrap items-center gap-2 text-[12.5px]">
        <span>Receipt</span><Hash value={receipt.queued} chars={10} />
        {record && <><span>Record</span><Hash value={record} chars={10} /></>}
      </div>
      {error && <Note tone="warn">Could not confirm the latest outcome. {error}</Note>}
      <p className="hint">Admission means the record entered this node’s log. Verification and settlement are separate steps.</p>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <button className="btn btn-sm" disabled={reading} onClick={() => void read()}>{reading ? "Reading…" : "Refresh status"}</button>
        <Link className="btn btn-sm" href={`/submission?id=${receipt.queued}`}>Open tracking page</Link>
        {status === "admitted" && receipt.kind === "objective" && record &&
          <Link className="btn btn-sm" href={`/challenge?id=${record}`}>Open challenge</Link>}
        <Link className="btn btn-sm" href="/log">Inspect log</Link>
      </div>
      {readAt && <p className="hint">Last read {readAt} from {base || "this node"}.</p>}
    </Card></div>
  );
}
