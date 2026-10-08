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
  AGENT_CLIENTS,
  type AgentClient,
  type McpPresence,
  agentStanza,
  claudeAdd,
  describePresence,
  slashCommand,
} from "@/lib/agents";
import { type Bridge } from "@/lib/draft";
import { openSheet } from "@/lib/contribute";
import { type NodeEvent } from "@/lib/journal";
import { ago } from "@/lib/events";
import { Badge, Command, Hash } from "@/components/ui";

/** How to attach an agent: Cairn.app's sheet when there is one, else the stanza. */
export function AgentConnect({ bridge }: { bridge: Bridge | null }) {
  const [client, setClient] = useState<AgentClient>("claude-code");
  const [error, setError] = useState<string | null>(null);
  const info = AGENT_CLIENTS.find((c) => c.id === client) ?? AGENT_CLIENTS[0];
  return (
    <div className="flex flex-col gap-3">
      {bridge && (
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
      )}
      <div>
        <div className="segmented mb-2" role="group" aria-label="Agent">
          {AGENT_CLIENTS.map((c) => (
            <button key={c.id} type="button" aria-pressed={c.id === client} onClick={() => setClient(c.id)}>
              {c.title}
            </button>
          ))}
        </div>
        {client === "claude-code" && <Command text={claudeAdd()} className="mb-2" />}
        <Command text={agentStanza(client)} />
        <p className="hint">
          In {info.file}. The agent then starts this node itself and talks to it over MCP, and this
          page keeps working at the same address. Every tool an agent has is listed by the agent
          once it connects; what pays is decided by each challenge&rsquo;s checker, never the agent.
        </p>
      </div>
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
