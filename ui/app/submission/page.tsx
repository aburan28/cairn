"use client";

import { Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { useNode } from "@/components/hooks";
import { SubmissionTracker } from "@/components/SubmissionTracker";
import { Note, PageHeader } from "@/components/ui";

function Tracking() {
  const base = useNode();
  const id = useSearchParams().get("id") ?? "";
  return <>
    <PageHeader title="Submission" subtitle="The admission outcome reported by this node." />
    {!/^sha256:[a-f0-9]{64}$/.test(id) ? <Note tone="warn">Open the tracking link returned when you submitted a challenge.</Note>
      : base === null ? <p>Finding a node…</p>
      : <SubmissionTracker key={`${base}:${id}`} base={base} receipt={{ queued: id, kind: "objective", note: "Reading this receipt from the node." }} />}
  </>;
}

export default function Page() { return <Suspense><Tracking /></Suspense>; }
