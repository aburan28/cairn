import { describe, expect, it } from "vitest";
import { type Checkpoint, classifyCheckpoint, coversHead } from "./checkpoint";

const signed: Checkpoint = {
  head: "sha256:entry-25",
  height: 25,
  root: "sha256:root",
  issued_at: "2026-08-08T03:30:02+00:00",
};

describe("classifyCheckpoint", () => {
  const what = "this node/checkpoint";

  // Byte for byte what `cairn-serve` answers at /checkpoint for a log it was
  // given no --checkpoint for (`checkpoint` in src/serve.rs, via `json_error`),
  // captured from a running node rather than typed from memory.
  const nodeNoCheckpoint =
    '{"error":"this node publishes no checkpoint; verify the log\'s chain directly"}';
  // The other 404 the same function writes, when the file it was pointed at
  // cannot be read.
  const nodeUnreadableFile =
    '{"error":"no checkpoint available: No such file or directory (os error 2)"}';
  // What Python's http.server answers for a path it has no file for -- the
  // same kind of body GitHub Pages and the Next dev server send, which is
  // what /checkpoint reaches when the site is built with no node URL.
  const staticHost404 =
    '<!DOCTYPE HTML>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n' +
    "<title>Error response</title>\n</head>\n<body>\n<h1>Error response</h1>\n" +
    "<p>Error code: 404</p>\n<p>Message: File not found.</p>\n" +
    "<p>Error code explanation: 404 - Nothing matches the given URI.</p>\n" +
    "</body>\n</html>\n";
  const good = JSON.stringify({ checkpoint: signed, public_key: "c9af03a0" });

  it("reads the node's own 404 as a node with no checkpoint", () => {
    expect(classifyCheckpoint(404, nodeNoCheckpoint, what)).toEqual({
      kind: "unsigned",
      reason: "this node publishes no checkpoint; verify the log's chain directly",
    });
    expect(classifyCheckpoint(404, nodeUnreadableFile, what).kind).toBe("unsigned");
  });

  it("says nothing about a node for a static host's 404", () => {
    // The finding this pins: the public site is built with no node URL, so
    // this fetch reaches GitHub Pages, and the page rendered "this node
    // publishes no checkpoint" where there was no node at all.
    expect(classifyCheckpoint(404, staticHost404, what)).toEqual({ kind: "no-node" });
    expect(classifyCheckpoint(404, "", what)).toEqual({ kind: "no-node" });
    expect(classifyCheckpoint(404, "Not Found", what)).toEqual({ kind: "no-node" });
  });

  it("does not take any JSON `error` at a 404 for the node's", () => {
    // A JSON API that happens to sit at this origin says {"error": "not
    // found"} for a route it lacks. The word is the difference: both of the
    // node's messages name a checkpoint, and an HTML page containing the word
    // is not `{"error": …}`.
    expect(classifyCheckpoint(404, '{"error":"not found"}', what)).toEqual({ kind: "no-node" });
    expect(classifyCheckpoint(404, '{"error":42}', what)).toEqual({ kind: "no-node" });
    expect(classifyCheckpoint(404, '["checkpoint"]', what)).toEqual({ kind: "no-node" });
    expect(
      classifyCheckpoint(404, "<html><body>no checkpoint here</body></html>", what),
    ).toEqual({ kind: "no-node" });
  });

  it("reports a node that is reachable and answers wrongly", () => {
    // Consistent with the 200-in-the-wrong-shape rule: something answered,
    // and it was not a checkpoint. Silence would give it what an unsigned
    // node gets, and the two are not the same fact.
    expect(classifyCheckpoint(500, '{"error":"cannot read the log"}', what)).toEqual({
      kind: "unreadable",
      message: "this node/checkpoint answered 500.",
    });
    expect(classifyCheckpoint(503, staticHost404, what).kind).toBe("unreadable");
    expect(classifyCheckpoint(200, staticHost404, what)).toEqual({
      kind: "unreadable",
      message: "this node/checkpoint answered 200 with a body that is not JSON.",
    });
    const wrongShape = classifyCheckpoint(200, '{"checkpoint":{"height":25}}', what);
    expect(wrongShape.kind).toBe("unreadable");
    expect(wrongShape).toMatchObject({ message: expect.stringContaining("`public_key`") });
    const wrongInner = classifyCheckpoint(
      200,
      '{"checkpoint":{"height":25},"public_key":"c9af"}',
      what,
    );
    expect(wrongInner).toMatchObject({
      kind: "unreadable",
      message: expect.stringContaining("`head`"),
    });
  });

  it("returns the checkpoint and its key for a well-formed 200", () => {
    expect(classifyCheckpoint(200, good, what)).toEqual({
      kind: "signed",
      value: { checkpoint: signed, public_key: "c9af03a0" },
    });
  });
});

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
