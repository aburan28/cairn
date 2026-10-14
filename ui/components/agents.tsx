"use client";

/**
 * Agents on this node: who is attached over MCP, and how to attach one.
 *
 * Shared by the Network page (the status), the Coordination page (where a
 * coordinated task is launched through an agent) and Contribute (solving
 * challenges with one), so the three cannot describe the connection three
 * ways.
 */

import Link from "next/link";
import { useState } from "react";
import {
  type McpPresence,
  describePresence,
  slashCommand,
} from "@/lib/agents";
import { type Bridge } from "@/lib/draft";
import { openSheet } from "@/lib/contribute";
import { type NodeEvent } from "@/lib/journal";
import { ago } from "@/lib/events";
import { Badge, Hash } from "@/components/ui";

/** Connect through the app, which knows the local node and key paths. */
export function AgentConnect({ bridge }: { bridge: Bridge | null }) {
  const [error, setError] = useState<string | null>(null);
  return (
    <div className="flex flex-col gap-3">
      {bridge ? (
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            className="btn btn-primary btn-sm"
            onClick={() =>
              openSheet(bridge, "agents").catch((cause: unknown) =>
                setError(cause instanceof Error ? cause.message : String(cause)),
              )
            }
          >
            Connect an agent…
          </button>
          <span className="text-[12px] text-ink-3">
            Cairn.app writes the configuration with this Mac&rsquo;s paths.
          </span>
          {error && <span className="text-[12px] text-bad">{error}</span>}
        </div>
      ) : <p className="text-[12.5px] text-ink-2">Open this node in Cairn.app to connect an agent. The app sets up the connection for this computer.</p>}
      <p className="hint">The challenge&rsquo;s checker decides what is accepted and paid.</p>
    </div>
  );
}

/** Who is attached, what it has done, and the prompts it can be given. */
export function AgentStatus({
  mcp,
  events,
  now,
}: {
  mcp: McpPresence | undefined;
  events: NodeEvent[];
  now: number;
}) {
  const recent = events.filter((e) => e.kind === "agent").slice(-5).reverse();
  const attached = mcp?.serving && mcp.client;
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2 text-[13px]">
        <span
          className={`h-2 w-2 rounded-full ${attached ? "bg-accent" : mcp?.serving ? "bg-warn" : "bg-ink-3"}`}
          aria-hidden
        />
        <span className="text-ink">{describePresence(mcp)}</span>
      </div>
      {mcp?.serving && (
        <dl className="kv">
          {mcp.connected_at && (
            <>
              <dt>since</dt>
              <dd className="mono text-[12px]">{ago(mcp.connected_at, now)}</dd>
            </>
          )}
          <dt>activity</dt>
          <dd className="mono text-[12px]">
            {mcp.calls.toLocaleString("en-US")} call{mcp.calls === 1 ? "" : "s"}
            {mcp.writes > 0 && <span className="text-ink-3"> · {mcp.writes} recorded something</span>}
            {mcp.last_tool && <span className="text-ink-3"> · last {mcp.last_tool}</span>}
          </dd>
          <dt>signs as</dt>
          <dd>
            {mcp.signs_as ? (
              <Hash value={mcp.signs_as} chars={10} />
            ) : (
              <span className="text-[12px] text-ink-3">
                no key: submissions carry whatever name the agent sends
              </span>
            )}
          </dd>
          <dt>may fund</dt>
          <dd className="text-[12px] text-ink-2">
            {mcp.spend_limit > 0
              ? `up to ${mcp.spend_limit.toLocaleString("en-US")} units of challenges in total`
              : "unfunded challenges only (no spending ceiling set)"}
          </dd>
          {mcp.prompts.length > 0 && (
            <>
              <dt>prompts</dt>
              <dd className="flex flex-wrap gap-1.5">
                {mcp.prompts.map((prompt) => (
                  <Badge key={prompt} tone="accent" title="An MCP prompt: type it in Claude Code">
                    {slashCommand(prompt)}
                  </Badge>
                ))}
              </dd>
            </>
          )}
        </dl>
      )}
      {recent.length > 0 && (
        <ul className="flex flex-col gap-1 text-[12.5px]">
          {recent.map((event) => (
            <li key={event.seq} className="flex items-baseline gap-2">
              <span className="text-ink-2">{event.text}</span>
              <span className="ml-auto shrink-0 text-[11.5px] text-ink-3">{ago(event.at, now)}</span>
            </li>
          ))}
        </ul>
      )}
      {mcp?.serving && mcp.prompts.includes("coordinate_task") && (
        <p className="text-[12.5px] text-ink-2">
          Ask it to split a big search across your machines:{" "}
          <Link href="/coordination" className="text-accent hover:underline">
            launch a coordinated task →
          </Link>
        </p>
      )}
    </div>
  );
}
