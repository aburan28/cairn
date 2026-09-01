import { describe, expect, it } from "vitest";
import { ShapeMismatch, expectFields } from "./shape";

describe("expectFields", () => {
  it("returns the object when every field is present", () => {
    const body = { head: "", links: 0, chain: [] };
    expect(expectFields(body, ["head", "links", "chain"], "/chain")).toBe(body);
  });

  it("names the endpoint and every missing field", () => {
    // The incident this exists for: the node renamed `remaining` to
    // `pool_remaining` and the page rendered a dash. The message has to say
    // which request and which field, or it is an error nobody can act on.
    const attempt = () => expectFields({ head: "" }, ["head", "links", "chain"], "http://n/chain");
    expect(attempt).toThrow(ShapeMismatch);
    expect(attempt).toThrow(/http:\/\/n\/chain/);
    expect(attempt).toThrow(/`links`, `chain`/);
  });

  it("treats null as present and undefined as missing", () => {
    // A genesis record's `prev` is null. Null is an answer; undefined is the
    // absence of one, and only the second means the shapes disagree.
    expect(() => expectFields({ prev: null }, ["prev"], "line 1")).not.toThrow();
    expect(() => expectFields({ prev: undefined }, ["prev"], "line 1")).toThrow(ShapeMismatch);
  });

  it("refuses a non-object, saying what it got", () => {
    expect(() => expectFields(null, ["a"], "/x")).toThrow(/answered null/);
    expect(() => expectFields([1], ["a"], "/x")).toThrow(/answered an array/);
    expect(() => expectFields("text", ["a"], "/x")).toThrow(/answered a string/);
  });
});
