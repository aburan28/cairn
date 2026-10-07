import { describe, expect, it } from "vitest";
import { claudeAdd, fleetInvite, fleetJoin, fleetLead, mcpStanza } from "./agents";

describe("agent stanzas", () => {
  it("names the same three arguments in every client's shape", () => {
    for (const client of ["claude", "codex", "opencode"] as const) {
      const text = mcpStanza(client);
      expect(text).toContain("--log");
      expect(text).toContain("--root");
      expect(text).toContain("mcp");
    }
  });

  it("parses as JSON where the client reads JSON", () => {
    expect(() => JSON.parse(mcpStanza("claude"))).not.toThrow();
    expect(() => JSON.parse(mcpStanza("opencode"))).not.toThrow();
    expect(JSON.parse(mcpStanza("claude")).mcpServers.cairn.command).toContain("cairn");
  });

  it("keeps the fleet commands pointed at the node's own CLI", () => {
    expect(claudeAdd()).toContain("claude mcp add cairn");
    expect(fleetInvite()).toContain("cairn fleet invite");
    expect(fleetJoin("http://10.0.0.2:8080")).toContain("--node http://10.0.0.2:8080");
    expect(fleetJoin("")).toContain("<node-url>");
    expect(fleetLead()).toContain("CAIRN_FLEET=enrolled");
  });
});
