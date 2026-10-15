import { afterEach, expect, it, vi } from "vitest";
import { fetchWorkspace, fetchWorkspaces, replayCommand } from "./workspace";

afterEach(() => vi.unstubAllGlobals());
const id = `sha256:${"a".repeat(64)}`;
it("keeps exact-input replay distinct from a new run on current files", () => {
  expect(replayCommand(id)).not.toContain("--reapply");
  expect(replayCommand(id, true)).toContain("--reapply");
  expect(replayCommand(id, true, id)).toContain(`--baseline ${id}`);
  expect(() => replayCommand(id, true, "injected baseline")).toThrow("Invalid baseline");
  expect(() => replayCommand('$(touch /tmp/x)')).toThrow("Invalid");
});
it("a successful empty workspace list remains empty", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(Response.json({ workspaces: [], unavailable: 0, note: "Nothing published." })));
  expect((await fetchWorkspaces("")).workspaces).toEqual([]);
});
it("does not present a different or missing workspace under the requested id", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(Response.json({ summary: { space: "different" }, runs: [], conflicts: [], operations: [] })));
  await expect(fetchWorkspace("", id)).rejects.toThrow("unreadable");
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("", { status: 404 })));
  await expect(fetchWorkspace("", id)).rejects.toThrow("not published");
});
