import { describe, expect, it } from "vitest";
import { BRIEF_MAX, type Bridge, appBridge, briefProblem, handOff } from "./draft";

function recorder(reply: () => Promise<unknown> = async () => true) {
  const sent: unknown[] = [];
  const bridge: Bridge = {
    postMessage(message) {
      sent.push(message);
      return reply();
    },
  };
  return { bridge, sent };
}

describe("appBridge", () => {
  it("finds the handler Cairn.app registers", () => {
    const { bridge } = recorder();
    expect(appBridge({ webkit: { messageHandlers: { cairn: bridge } } })).toBe(bridge);
  });

  it("is null in a browser, and in an app build that registered no handler", () => {
    expect(appBridge({})).toBeNull();
    expect(appBridge(null)).toBeNull();
    expect(appBridge({ webkit: { messageHandlers: {} } })).toBeNull();
    expect(appBridge({ webkit: { messageHandlers: { cairn: {} } } })).toBeNull();
  });
});

describe("briefProblem", () => {
  it("wants enough to draft from, counted without the whitespace", () => {
    expect(briefProblem("")).not.toBeNull();
    expect(briefProblem("   short   ")).not.toBeNull();
    expect(briefProblem("find a 16-input sorting network")).toBeNull();
  });

  it("refuses a document", () => {
    expect(briefProblem("x".repeat(BRIEF_MAX))).toBeNull();
    expect(briefProblem("x".repeat(BRIEF_MAX + 1))).not.toBeNull();
  });
});

describe("handOff", () => {
  it("sends the trimmed description in the shape WebView.swift parses", async () => {
    const { bridge, sent } = recorder();
    await handOff("  find a 16-input sorting network  \n", bridge);
    expect(sent).toEqual([{ kind: "draft-challenge", brief: "find a 16-input sorting network" }]);
  });

  it("sends nothing the app's Draft button would refuse", async () => {
    const { bridge, sent } = recorder();
    await expect(handOff("hi", bridge)).rejects.toThrow(/what you want solved/);
    expect(sent).toEqual([]);
  });

  it("surfaces the app's reason when the sheet did not open", async () => {
    const { bridge } = recorder(() => Promise.reject(new Error("Close the open sheet first.")));
    await expect(handOff("find a 16-input sorting network", bridge)).rejects.toThrow(
      "Close the open sheet first.",
    );
  });
});
