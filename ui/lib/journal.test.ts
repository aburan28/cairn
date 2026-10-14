import { describe, expect, it } from "vitest";
import { type EventsPage, type NodeEvent, absorb, timeline } from "./journal";
import type { LogRecord } from "./log";

const record = (seq: number, ts: string): LogRecord => ({
  seq,
  kind: "claim",
  hash: `sha256:${seq}`,
  prev: null,
  ts,
  payload: {},
});

const event = (seq: number, at: string, text = "e"): NodeEvent => ({
  seq,
  at,
  kind: "peer",
  tone: "good",
  text,
  subject: null,
});

const page = (events: NodeEvent[], started_at = "2026-10-07T10:00:00+00:00"): EventsPage => ({
  events,
  last: events.length ? events[events.length - 1].seq : 0,
  dropped: 0,
  capacity: 500,
  started_at,
  note: "",
});

describe("timeline", () => {
  it("interleaves records and node events newest first", () => {
    const items = timeline(
      [record(1, "2026-10-07T10:00:00+00:00"), record(2, "2026-10-07T10:05:00+00:00")],
      [event(1, "2026-10-07T10:02:00+00:00"), event(2, "2026-10-07T10:07:00+00:00")],
    );
    expect(items.map((i) => (i.type === "record" ? `r${i.record.seq}` : `e${i.event.seq}`))).toEqual([
      "e2",
      "r2",
      "e1",
      "r1",
    ]);
  });

  it("puts a record above an event from the same second, and keeps seq order within a kind", () => {
    const at = "2026-10-07T10:00:00+00:00";
    const items = timeline([record(4, at), record(5, at)], [event(9, at)]);
    expect(items.map((i) => i.type)).toEqual(["record", "record", "event"]);
    expect(items[0].type === "record" && items[0].record.seq).toBe(5);
  });
});

describe("absorb", () => {
  it("adds new events once and keeps the newest within the cap", () => {
    let held = absorb({ events: [], started_at: null }, page([event(1, "a"), event(2, "b")]));
    held = absorb(held, page([event(2, "b"), event(3, "c")]));
    expect(held.events.map((e) => e.seq)).toEqual([1, 2, 3]);
    const capped = absorb(held, page([event(4, "d")]), 2);
    expect(capped.events.map((e) => e.seq)).toEqual([3, 4]);
  });

  it("drops what a restarted node's previous process said, since its seqs start again", () => {
    const before = absorb({ events: [], started_at: null }, page([event(1, "a", "old"), event(2, "b", "old")]));
    const after = absorb(before, page([event(1, "c", "new")], "2026-10-07T11:00:00+00:00"));
    expect(after.events.map((e) => e.text)).toEqual(["new"]);
  });
});
