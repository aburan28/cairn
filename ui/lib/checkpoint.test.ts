import { describe, expect, it } from "vitest";
import { type Checkpoint, coversHead } from "./checkpoint";

const signed: Checkpoint = {
  head: "sha256:entry-25",
  height: 25,
  root: "sha256:root",
  issued_at: "2026-08-08T03:30:02+00:00",
};

describe("coversHead", () => {
  // The argument is the ledger's entry count. The launch log has 25 entries
  // and 4 epoch links; passing the link count, which this page did, made
  // every checkpoint look like it covered the head.
  it("is at the head when the checkpoint signed every entry the node serves", () => {
    expect(coversHead(signed, 25)).toBe("at");
  });

  it("is behind when the node appended after signing", () => {
    expect(coversHead(signed, 30)).toBe("behind");
  });

  it("is ahead when the checkpoint claims more entries than the node has", () => {
    expect(coversHead(signed, 20)).toBe("ahead");
  });

  it("does not read a link count as a height", () => {
    // Pinned so nobody reintroduces the comparison. The old two-way answer
    // turned 25 signed entries against 4 links into "at", for a log the
    // operator had kept appending to. With the units named, the same mistake
    // is an impossible height and the page turns red.
    const links = 4;
    expect(coversHead(signed, links)).not.toBe("at");
  });
});
