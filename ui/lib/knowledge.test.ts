import { describe, expect, it } from "vitest";
import { confidencePercent, evidenceLine, standingHelp, standingTone } from "./knowledge";

describe("standing display", () => {
  it("colours acceptance green, dispute amber, and rejection red", () => {
    expect(standingTone("accepted")).toBe("accent");
    expect(standingTone("corroborated")).toBe("accent");
    expect(standingTone("contested")).toBe("warn");
    expect(standingTone("superseded")).toBe("warn");
    expect(standingTone("refuted")).toBe("bad");
    expect(standingTone("withdrawn")).toBe("bad");
    expect(standingTone("unverified")).toBe("neutral");
    expect(standingTone("something-new")).toBe("neutral");
  });

  it("explains every standing in one line", () => {
    for (const standing of [
      "refuted",
      "unverified",
      "withdrawn",
      "superseded",
      "contested",
      "corroborated",
      "accepted",
    ]) {
      expect(standingHelp(standing).length).toBeGreaterThan(10);
    }
    expect(standingHelp("refuted")).toContain("rejected");
  });
});

describe("confidence", () => {
  it("renders per-mille as a floored percent and clamps nonsense", () => {
    expect(confidencePercent(600)).toBe(60);
    expect(confidencePercent(965)).toBe(96);
    expect(confidencePercent(0)).toBe(0);
    expect(confidencePercent(1000)).toBe(100);
    expect(confidencePercent(Number.NaN)).toBe(0);
    expect(confidencePercent(5000)).toBe(100);
  });

  it("summarises corroboration in one line, or says nothing was said", () => {
    expect(evidenceLine({ corroborations: 0, refutations: 0, disputes: 0 })).toBe("nothing said yet");
    expect(evidenceLine({ corroborations: 2, refutations: 1, disputes: 0 })).toBe(
      "2 corroborations · 1 refutation",
    );
    expect(evidenceLine({ corroborations: 1, refutations: 0, disputes: 1 })).toBe(
      "1 corroboration · 1 dispute",
    );
  });
});
