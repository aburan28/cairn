import { describe, expect, it } from "vitest";
import { SNAPSHOT, progress, provenance, short, units } from "./site";

describe("progress (site.ts copy, as a percentage)", () => {
  const maximize = { baseline: 9, target: 20, direction: "maximize" };
  const minimize = { baseline: 100, target: 40, direction: "minimize" };

  it("counts up for maximize", () => {
    expect(progress(9, maximize)).toBe(0);
    expect(progress(20, maximize)).toBe(100);
    expect(progress(12, maximize)).toBe(27);
  });

  it("counts down for minimize, consulting the direction explicitly", () => {
    expect(progress(100, minimize)).toBe(0);
    expect(progress(40, minimize)).toBe(100);
    expect(progress(70, minimize)).toBe(50);
  });

  it("clamps to [0, 100]", () => {
    expect(progress(25, maximize)).toBe(100);
    expect(progress(2, maximize)).toBe(0);
    expect(progress(10, minimize)).toBe(100);
    expect(progress(150, minimize)).toBe(0);
  });

  it("is 0 for a degenerate or inverted span rather than dividing by it", () => {
    expect(progress(9, { ...maximize, target: 9 })).toBe(0);
    // A "maximize" ratchet whose target is below its baseline has a negative
    // span. The other two copies count that as a minimize; this one shows no
    // progress. Pinned so the difference is known rather than discovered.
    expect(progress(5, { baseline: 9, target: 3, direction: "maximize" })).toBe(0);
  });
});

describe("provenance", () => {
  it("names the node for a live value and the snapshot otherwise", () => {
    expect(provenance({ live: true, origin: "http://127.0.0.1:8080" })).toBe(
      "live from http://127.0.0.1:8080",
    );
    expect(provenance({ live: false, origin: "launch/cairn.jsonl" })).toBe(
      "from launch/cairn.jsonl snapshot",
    );
  });
});

describe("the bundled snapshot", () => {
  // The fallback is a committed file produced by a script, and the pages read
  // fields from it by name. This is the shape check the fetchers make at
  // runtime, made once at test time for the file that never goes over HTTP.
  it("carries the chain and checkpoint facts the landing page reads", () => {
    expect(SNAPSHOT.chain).toMatchObject({
      head: expect.any(String),
      links: expect.any(Number),
      height: expect.any(Number),
      ledger_head: expect.any(String),
    });
    expect(SNAPSHOT.checkpoint).toMatchObject({
      head: expect.any(String),
      height: expect.any(Number),
      root: expect.any(String),
      issued_at: expect.any(String),
      public_key: expect.any(String),
    });
  });

  it("was signed over the log the node served -- same height, same ledger head", () => {
    expect(SNAPSHOT.checkpoint.height).toBe(SNAPSHOT.chain.height);
    expect(SNAPSHOT.checkpoint.head).toBe(SNAPSHOT.chain.ledger_head);
  });

  it("counts entries, not links, as its height", () => {
    // 4 links and 25 entries for the launch log. If these were ever equal the
    // unit confusion this change fixed would be invisible to the tests.
    expect(SNAPSHOT.chain.height).toBeGreaterThan(SNAPSHOT.chain.links);
  });
});

describe("formatting", () => {
  it("shortens a sha256 id to something comparable by eye", () => {
    expect(short("sha256:7cb2c935c6d1b1f458b024e302a953ba856ed7a5d053830fab53f0287ca8d4e5")).toBe(
      "7cb2c935…d4e5",
    );
    expect(short("carol")).toBe("carol");
  });

  it("renders a missing amount as a dash rather than throwing", () => {
    expect(units(1_100_000)).toBe("1,100,000");
    expect(units(undefined)).toBe("—");
    expect(units(null)).toBe("—");
  });
});
