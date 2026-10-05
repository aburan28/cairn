"use client";

import { useEffect, useRef, useState } from "react";
import { type Bridge, startDictation, stopDictation } from "@/lib/draft";

type BrowserSpeechResult = { isFinal: boolean; [index: number]: { transcript: string } };
type BrowserSpeech = {
  continuous: boolean;
  interimResults: boolean;
  lang: string;
  onresult: ((event: { results: ArrayLike<BrowserSpeechResult> }) => void) | null;
  onerror: ((event: { error: string }) => void) | null;
  onend: (() => void) | null;
  start(): void;
  stop(): void;
  abort(): void;
};
type BrowserSpeechConstructor = new () => BrowserSpeech;

function browserSpeech(): BrowserSpeechConstructor | null {
  const scope = window as Window & {
    SpeechRecognition?: BrowserSpeechConstructor;
    webkitSpeechRecognition?: BrowserSpeechConstructor;
  };
  return scope.SpeechRecognition ?? scope.webkitSpeechRecognition ?? null;
}

/** Dictation never posts. The caller receives editable text, then the normal
 * challenge review and submission flow decides what to do with it. */
export function VoiceInput({
  bridge,
  onText,
}: {
  bridge: Bridge | null | undefined;
  onText: (text: string) => void;
}) {
  const [status, setStatus] = useState<"idle" | "starting" | "listening" | "stopping">("idle");
  const [supported, setSupported] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const speech = useRef<BrowserSpeech | null>(null);

  useEffect(() => setSupported(browserSpeech() !== null), []);
  useEffect(() => () => {
    if (speech.current) {
      speech.current.onend = null;
      speech.current.abort();
    }
    if (bridge) void bridge.postMessage({ kind: "stop-dictation" }).catch(() => {});
  }, [bridge]);

  async function start() {
    setError(null);
    setStatus("starting");
    if (bridge) {
      try {
        await startDictation(bridge);
        setStatus("listening");
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : String(cause));
        setStatus("idle");
      }
      return;
    }
    const Constructor = browserSpeech();
    if (!Constructor) {
      setError("Speech recognition is unavailable in this browser. You can use your device's dictation keyboard.");
      setStatus("idle");
      return;
    }
    const recognizer = new Constructor();
    speech.current = recognizer;
    recognizer.continuous = true;
    recognizer.interimResults = false;
    recognizer.lang = navigator.language;
    let text = "";
    recognizer.onresult = (event) => {
      text = Array.from(event.results)
        .filter((result) => result.isFinal)
        .map((result) => result[0]?.transcript ?? "")
        .join(" ")
        .trim();
    };
    recognizer.onerror = (event) => {
      setError(event.error === "not-allowed" ? "Allow microphone access to dictate a challenge." : `Speech recognition stopped: ${event.error}.`);
      setStatus("idle");
    };
    recognizer.onend = () => {
      speech.current = null;
      if (text) onText(text);
      setStatus("idle");
    };
    try {
      recognizer.start();
      setStatus("listening");
    } catch (cause) {
      speech.current = null;
      setError(cause instanceof Error ? cause.message : String(cause));
      setStatus("idle");
    }
  }

  async function stop() {
    setStatus("stopping");
    if (bridge) {
      try {
        onText(await stopDictation(bridge));
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : String(cause));
      } finally {
        setStatus("idle");
      }
    } else {
      speech.current?.stop();
    }
  }

  const active = status !== "idle";
  return (
    <div className="mt-2">
      <button
        type="button"
        className={`btn btn-sm ${active ? "btn-primary" : ""}`}
        disabled={bridge === undefined || (!bridge && !supported) || status === "starting" || status === "stopping"}
        aria-pressed={active}
        onClick={() => void (status === "listening" ? stop() : start())}
      >
        <span aria-hidden="true">{active ? "●" : "◉"}</span>
        {status === "listening" ? "Stop listening" : status === "starting" ? "Starting microphone…" : status === "stopping" ? "Transcribing…" : "Speak description"}
      </button>
      <span className="ml-2 text-[12px] text-ink-3">
        {active ? "Listening. Your words will appear here for review." : bridge ? "Transcribed on this Mac; review before posting." : "Your browser may process speech online; review before posting."}
      </span>
      {!bridge && bridge !== undefined && !supported && (
        <p className="hint">Voice entry is unavailable in this browser. Use your device's dictation keyboard.</p>
      )}
      {error && <p role="alert" className="mt-1 text-[12px] text-bad">{error}</p>}
    </div>
  );
}
