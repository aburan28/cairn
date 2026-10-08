"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { PageHeader } from "@/components/ui";

/**
 * The chain is now part of Knowledge, beside how well verified each result in
 * it is. This path stays so a bookmark or an old link still lands there --
 * replaced in history, so Back does not bounce through it.
 */
export default function Page() {
  const router = useRouter();
  useEffect(() => router.replace("/knowledge"), [router]);
  return (
    <PageHeader
      title="Knowledge"
      subtitle="The chain is on the Knowledge page now, beside how well verified each result is — two nodes that settled the same results share a head, and where they differ is where they forked."
    />
  );
}
