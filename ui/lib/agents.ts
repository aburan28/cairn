/**
 * How agents reach a node: the stanzas and commands behind `/agents`.
 *
 * Two arrangements, as `docs/agents.md` describes them: the agent runs the
 * node itself over stdio MCP (`cairn run` as the MCP server, one process
 * owning the log), or it works a remote node as a labourer (`cairn work`
 * over HTTP). The stanzas here are the same shapes
 * `gui/macos-app/.../AgentStanza.swift` renders with real paths — this page
 * cannot know the reader's paths, so it shows placeholders and says so.
 */

export type AgentClient = "claude" | "codex" | "opencode";

export const CLIENTS: Array<{ id: AgentClient; label: string; file: string }> = [
  { id: "claude", label: "Claude Code", file: ".mcp.json, or `claude mcp add`" },
  { id: "codex", label: "Codex", file: "~/.codex/config.toml" },
  { id: "opencode", label: "OpenCode", file: "opencode.json" },
];

/** The stdio stanza that makes the agent run this node's log. Placeholders, honestly labelled. */
export function mcpStanza(client: AgentClient): string {
  const binary = "/abs/path/to/cairn";
  const log = "/abs/path/to/cairn.jsonl";
  const root = "/abs/path/to/repo";
  switch (client) {
    case "claude":
      return JSON.stringify(
        { mcpServers: { cairn: { command: binary, args: ["--log", log, "--root", root, "mcp"] } } },
        null,
        2,
      );
    case "opencode":
      return JSON.stringify(
        {
          mcp: {
            cairn: {
              type: "local",
              command: [binary, "--log", log, "--root", root, "mcp"],
              enabled: true,
            },
          },
        },
        null,
        2,
      );
    case "codex":
      return (
        `[mcp_servers.cairn]\ncommand = "${binary}"\n` +
        `args = ["--log", "${log}", "--root", "${root}", "mcp"]\n`
      );
  }
}

/** The one line that writes the Claude stanza without hand-editing JSON. */
export function claudeAdd(): string {
  return "claude mcp add cairn --scope user -- /abs/path/to/cairn --log /abs/path/to/cairn.jsonl --root /abs/path/to/repo mcp";
}

/** Enrol a machine with this leader, from the leader's shell and the machine's. */
export function fleetInvite(): string {
  return "cairn fleet invite --member garage-gpu > invite.json";
}

export function fleetJoin(node: string): string {
  return `cairn fleet join --node ${node || "<node-url>"} --invite invite.json --name garage-gpu`;
}

/** Lead a fleet: sign every enrolled member's submissions under one id. */
export function fleetLead(): string {
  return "CAIRN_FLEET=enrolled cairn run --mcp-identity leader.identity.json";
}
