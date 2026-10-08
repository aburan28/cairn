/**
 * Agents: the MCP side of a node, for the Network and Coordination pages.
 *
 * Three things a person running a node asks and the reader used to answer
 * none of: is an agent attached here, how do I attach one, and what can I ask
 * it to do. The first is `node.mcp` on `GET /network` (`src/mcp.rs`,
 * `Presence`); the second is the client stanza `docs/agents.md` documents and
 * Cairn.app's Connect an Agent… sheet writes with real paths; the third is the
 * node's MCP prompts, `GET /prompts`, rendered by `POST /prompts/{name}`.
 */

import { expectFields } from "./shape";

/** `node.mcp`. Absent on a node older than the field. */
export type McpPresence =
  | { serving: false }
  | {
      serving: true;
      transport: string;
      /** The client's own name for itself, from `initialize`. Unchecked. */
      client: { name: string; version: string } | null;
      connected_at: string | null;
      last_call_at: string | null;
      calls: number;
      /** Calls that appended something and were admitted. */
      writes: number;
      last_tool: string | null;
      /** The key submissions are signed with, when there is one. */
      signs_as: string | null;
      /** What `post_objective` may fund in total; 0 is unfunded posts only. */
      spend_limit: number;
      prompts: string[];
    };

export type AgentClient = "claude-code" | "codex" | "opencode";

export const AGENT_CLIENTS: { id: AgentClient; title: string; file: string }[] = [
  { id: "claude-code", title: "Claude Code", file: ".mcp.json in the project, or `claude mcp add`" },
  { id: "codex", title: "Codex", file: "~/.codex/config.toml" },
  { id: "opencode", title: "OpenCode", file: "opencode.json" },
];

/**
 * The client stanza that makes an agent launch this node as its MCP server --
 * `docs/agents.md`'s one-process arrangement, where the agent's client is the
 * node's supervisor and the reader keeps working at the same address.
 *
 * A browser cannot know this machine's paths, so `binary` defaults to the
 * `cairn` on `PATH`; Cairn.app's sheet writes the same shape with absolute
 * ones (`AgentStanza.swift`), and inside the app the page opens that instead.
 */
export function agentStanza(client: AgentClient, binary = "cairn"): string {
  const args = ["run"];
  switch (client) {
    case "claude-code":
      return JSON.stringify({ mcpServers: { cairn: { command: binary, args } } }, null, 2);
    case "opencode":
      return JSON.stringify(
        { mcp: { cairn: { type: "local", command: [binary, ...args], enabled: true } } },
        null,
        2,
      );
    case "codex":
      return `[mcp_servers.cairn]\ncommand = ${JSON.stringify(binary)}\nargs = ${JSON.stringify(args)}\n`;
  }
}

/** The one-liner for Claude Code, which writes the stanza itself. */
export function claudeAdd(binary = "cairn"): string {
  return `claude mcp add cairn --scope user -- ${binary} run`;
}

/** The slash command a prompt is in Claude Code. */
export function slashCommand(prompt: string): string {
  return `/mcp__cairn__${prompt}`;
}

/** One line about who is attached, for a status row. */
export function describePresence(mcp: McpPresence | undefined): string {
  if (!mcp) return "This node is older than the MCP status report.";
  if (!mcp.serving) {
    return "Not serving MCP: this node was started without it, so agents attach by launching a node of their own on the same data.";
  }
  if (!mcp.client) return "Serving MCP on stdio; no agent has said hello yet.";
  const version = mcp.client.version ? ` ${mcp.client.version}` : "";
  return `${mcp.client.name}${version} is attached over MCP`;
}

export type PromptDefinition = {
  name: string;
  title: string;
  description: string;
  slash_command: string;
  arguments: { name: string; description: string; required: boolean }[];
};

/** `GET /prompts`, or `null` from a node older than the route. */
export async function fetchPrompts(base: string): Promise<PromptDefinition[] | null> {
  const response = await fetch(`${base}/prompts`, { cache: "no-store" });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error(`${base || "this node"}/prompts answered ${response.status}`);
  const body = expectFields<{ prompts: PromptDefinition[] }>(
    await response.json(),
    ["prompts"],
    `${base || "this node"}/prompts`,
  );
  return body.prompts;
}

export class PromptRefused extends Error {}

/**
 * One prompt, rendered by the node exactly as MCP `prompts/get` renders it.
 * A POST, because a description can be longer than a request line may be;
 * nothing is written. Throws `PromptRefused` with the node's own words when
 * an argument is wrong, and a plain error when no node answered.
 */
export async function renderPrompt(
  base: string,
  name: string,
  args: Record<string, string>,
): Promise<string> {
  const response = await fetch(`${base}/prompts/${encodeURIComponent(name)}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ arguments: args }),
    cache: "no-store",
  });
  const body = (await response.json().catch(() => null)) as { text?: unknown; error?: unknown } | null;
  if (!response.ok) {
    const why = typeof body?.error === "string" ? body.error : `answered ${response.status}`;
    if (response.status === 400) throw new PromptRefused(why);
    if (response.status === 404) {
      throw new Error("This node is older than coordinated-task prompts; update it to use this.");
    }
    throw new Error(why);
  }
  if (typeof body?.text !== "string") throw new Error("The node answered without a prompt.");
  return body.text;
}
