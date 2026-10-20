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
  conductorSetup,
  describePresence,
  slashCommand,
} from "@/lib/agents";
import { type AppSheet } from "@/lib/contribute";
import { type Bridge } from "@/lib/draft";
import { openSheet } from "@/lib/contribute";
import { type NodeEvent } from "@/lib/journal";
import { ago } from "@/lib/events";
import { Badge, Command, Disclosure, Hash } from "@/components/ui";

/** Connect through the app, which knows the local node and key paths. */
export function AgentConnect({ bridge }: { bridge: Bridge | null }) {
  const [error, setError] = useState<string | null>(null);
  const open = (sheet: AppSheet) => () => {
    if (!bridge) return;
    setError(null);
    openSheet(bridge, sheet).catch((cause: unknown) =>
      setError(cause instanceof Error ? cause.message : String(cause)),
    );
  };
  return (
    <div className="flex flex-col gap-3">
      {bridge ? (
        <div className="flex flex-wrap items-center gap-2">
          <button type="button" className="btn btn-primary btn-sm" onClick={open("agents")}>
            Connect an agent…
          </button>
          <button type="button" className="btn btn-sm" onClick={open("conductor")}>
            Connect Conductor…
          </button>
          <span className="text-[12px] text-ink-3">
            Cairn.app writes the configuration with this Mac&rsquo;s paths.
          </span>
          {error && <span className="text-[12px] text-bad">{error}</span>}
        </div>
      ) : (
        <>
          <p className="text-[12.5px] text-ink-2">Connect an agent using the setup below, or use the desktop app to configure it for this computer.</p>
          <ConductorSetup />
        </>
      )}
      <p className="hint">The challenge&rsquo;s checker decides what is accepted and paid.</p>
    </div>
  );
}

/**
 * Conductor by hand, for a browser tab with no app to write the configs:
 * every workspace's agent shares this node over HTTP. In Cairn.app the
 * Connect Conductor… button does the same and restarts the node itself.
 *
 * Closed until asked for: the same three commands sit on the Network,
 * challenge and Contribute pages, and open they outweighed everything else
 * on all three.
 */
function ConductorSetup() {
  const setup = conductorSetup();
  return (
    <Disclosure summary="Manual agent setup"><div className="flex flex-col gap-2">
      <p className="text-[12.5px] text-ink-2">
        <span className="text-ink">Conductor</span> runs Claude Code and Codex side by side, one
        workspace each. Start this node with the agents&rsquo; port, then point both at it once:
      </p>
      <Command text={setup.serve} />
      <Command text={setup.claude} />
      <Command text={setup.codex} />
      <p className="hint">
        Each session gets its own connection to this one node, so workspaces can work at once
        &mdash; a node of their own each would be refused the log&rsquo;s lock. The port is
        loopback only, and any program on this computer can act as this node through it. Have
        each workspace pass its own <span className="mono">node_id</span> to{" "}
        <span className="mono">work_assignment</span> (<span className="mono">$CONDUCTOR_WORKSPACE_NAME</span>),
        or two of them search the same slice.
      </p>
    </div></Disclosure>
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
      <div className="flex items-start gap-2 text-[13px]">
        <span
          className={`mt-[0.45em] h-2 w-2 shrink-0 rounded-full ${attached ? "bg-accent" : mcp?.serving ? "bg-warn" : "bg-ink-3"}`}
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
