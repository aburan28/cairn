import { describe, expect, it } from "vitest";
import { agentStanza, claudeAdd, describePresence, slashCommand } from "./agents";

describe("agent stanzas", () => {
  it("launch the node itself, so the agent and this reader share one process", () => {
    const claude = JSON.parse(agentStanza("claude-code"));
    expect(claude.mcpServers.cairn).toEqual({ command: "cairn", args: ["run"] });
    const opencode = JSON.parse(agentStanza("opencode", "/opt/cairn"));
    expect(opencode.mcp.cairn.command).toEqual(["/opt/cairn", "run"]);
    expect(agentStanza("codex")).toBe('[mcp_servers.cairn]\ncommand = "cairn"\nargs = ["run"]\n');
    expect(claudeAdd()).toBe("claude mcp add cairn --scope user -- cairn run");
  });

  it("name a prompt as Claude Code's slash command", () => {
    expect(slashCommand("coordinate_task")).toBe("/mcp__cairn__coordinate_task");
  });
});

describe("describePresence", () => {
  it("says who is attached, and why nobody can be", () => {
    expect(describePresence(undefined)).toMatch(/older/);
    expect(describePresence({ serving: false })).toMatch(/^Not serving MCP/);
    const base = {
      serving: true as const,
      transport: "stdio",
      connected_at: null,
      last_call_at: null,
      calls: 0,
      writes: 0,
      last_tool: null,
      signs_as: null,
      spend_limit: 0,
      prompts: [],
    };
    expect(describePresence({ ...base, client: null })).toMatch(/no agent has said hello/);
    expect(describePresence({ ...base, client: { name: "claude-code", version: "2.1" } })).toBe(
      "claude-code 2.1 is attached over MCP",
    );
  });
});
