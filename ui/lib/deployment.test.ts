import { describe, expect, it } from "vitest";
import { networkSetup } from "./deployment";

describe("network setup guidance", () => {
  it("keeps private recovery inside the configured network", () => {
    const guide = networkSetup("private");
    const text = JSON.stringify(guide);
    expect(text).toContain("WireGuard");
    expect(text).toContain("CAIRN_NETWORK=private");
    expect(text).toContain("already exist on its interface");
    expect(text).toContain("private keys on their owning machines");
    expect(text).not.toMatch(/tailscale|funnel|https:\/\/|install\.sh/i);
    expect(guide.commands.every(({ text }) => !text.includes("0.0.0.0"))).toBe(true);
  });

  it("preserves public setup unless the serving node supplied the private marker", () => {
    const publicGuide = networkSetup("public");
    expect(publicGuide.commands.map(({ text }) => text)).toEqual([
      "cairn run --listen 0.0.0.0:9000 --serve 127.0.0.1:8080",
      "tailscale up",
      "tailscale serve --bg --https=8443 http://127.0.0.1:8080",
      "tailscale funnel --https=8443 --bg http://127.0.0.1:8080",
    ]);
    for (const marker of [null, undefined, "", "false", "PRIVATE", "unrecognized"]) {
      expect(networkSetup(marker)).toBe(publicGuide);
    }
  });
});
