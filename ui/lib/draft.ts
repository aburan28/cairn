/**
 * Posting a challenge from a plain description, by handing it to Cairn.app.
 *
 * # Why the page does not draft it itself
 *
 * Drafting asks a hosted model, over TLS, with the funder's API key, then
 * writes the theorem it gets back under the node's root, compiles it with the
 * Lean on that Mac and runs a hole through the node's own verifier before
 * anything is posted. The node can do none of that for a page. It has no TLS
 * by design (`tests/cipher_policy.rs`). It serves plain HTTP, so a key typed
 * into a page it serves crosses the wire in the clear. And a route that took
 * Lean source from a page would let anyone who can reach the node's port
 * publish theorems under its funder's name.
 *
 * Cairn.app can do all of it, because it is the process that runs the node and
 * holds the key — and it already does, behind New Challenge…. So in the app's
 * window this page is a text box in front of that sheet, and anywhere else it
 * is the form.
 *
 * # The bridge
 *
 * `window.webkit.messageHandlers.cairn`, which Cairn.app registers on its one
 * web view (`gui/macos-app/Sources/Cairn/WebView.swift`). `postMessage`
 * returns a promise: it resolves once the sheet is open, and rejects with the
 * app's own reason when it is not — the window is attached to a node the app
 * does not run, or another sheet is up. The app answers only the main frame
 * of the node it is showing, so nothing a page embeds can open the sheet.
 *
 * Detected by the handler, not by the user agent: an older Cairn.app sets the
 * same `CairnApp/` marker and has no handler, and a page that trusted the
 * marker would post into nothing.
 */

/** The one method this page calls on the app's handler. */
export type Bridge = { postMessage(message: unknown): Promise<unknown> };

/** Below this the app's own Draft button stays disabled, so the page agrees. */
export const BRIEF_MIN = 10;
/** A description, not a document. Bounds what a page can put in a request. */
export const BRIEF_MAX = 20_000;

/** The message the app reads. `WebView.swift` parses exactly this. */
export type DraftRequest = { kind: "draft-challenge"; brief: string };
export type DictationRequest = { kind: "start-dictation" } | { kind: "stop-dictation" };

/** Cairn.app's handler, when this page is in a window that has one. */
export function appBridge(scope: unknown = globalThis): Bridge | null {
  const handler = (scope as { webkit?: { messageHandlers?: { cairn?: unknown } } } | null)
    ?.webkit?.messageHandlers?.cairn;
  if (typeof handler !== "object" || handler === null) return null;
  return typeof (handler as Bridge).postMessage === "function" ? (handler as Bridge) : null;
}

/** Why this description cannot be handed over yet, or null when it can. */
export function briefProblem(text: string): string | null {
  const length = text.trim().length;
  if (length < BRIEF_MIN) {
    return "Say what you want solved, and what counts as a right answer.";
  }
  if (length > BRIEF_MAX) {
    return "That is longer than a description needs to be: keep it under 20,000 characters.";
  }
  return null;
}

/**
 * Open New Challenge… with this description, which starts drafting at once
 * when a model key is saved. Resolves when the sheet is up; throws the app's
 * reason when it is not.
 */
export async function handOff(brief: string, bridge: Bridge): Promise<void> {
  const problem = briefProblem(brief);
  if (problem) throw new Error(problem);
  const request: DraftRequest = { kind: "draft-challenge", brief: brief.trim() };
  try {
    await bridge.postMessage(request);
  } catch (cause) {
    // WebKit rejects with an Error carrying the app's message verbatim.
    throw new Error(cause instanceof Error ? cause.message : String(cause));
  }
}

/** Cairn.app transcribes on device and returns editable text only when stopped. */
export async function startDictation(bridge: Bridge): Promise<void> {
  await bridge.postMessage({ kind: "start-dictation" } satisfies DictationRequest);
}

export async function stopDictation(bridge: Bridge): Promise<string> {
  const answer = await bridge.postMessage({ kind: "stop-dictation" } satisfies DictationRequest);
  const text = (answer as { text?: unknown } | null)?.text;
  if (typeof text !== "string" || !text.trim()) {
    throw new Error("Cairn did not hear a description. Try again or type it.");
  }
  return text.trim();
}
