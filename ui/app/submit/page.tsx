"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  type Draft,
  type Prepared,
  type Queued,
  EMPTY_DRAFT,
  VERIFIER_KINDS,
  fromRecord,
  isScored,
  kindInfo,
  prepare,
  problems,
  reachableForWrites,
  sha256Hex,
  submit,
  toRecord,
} from "@/lib/submit";
import {
  type Wallet,
  available,
  connect,
  hasEvmOnly,
  isKeyShaped,
  isMobileBrowser,
  signPayload,
} from "@/lib/wallet";
import { NODE_URL } from "@/lib/objectives";
import { repoLink } from "@/lib/site";
import { Badge, Card, CopyButton, Hash, Note, SectionHeading } from "@/components/ui";

/**
 * Post a challenge, funded by a key a wallet holds.
 *
 * # Why a browser wallet is the right key here
 *
 * A cairn `funder` is not an account. It *is* an Ed25519 public key in hex, and
 * `funding_signature` is that key's signature over the objective's canonical
 * funding payload. Solana wallets sign Ed25519 over arbitrary bytes, so a
 * Phantom or Solflare key already *is* a cairn identity — and the signature it
 * returns is checked by the same `verify_funding_signature` that checks one
 * from `cairn identity`. Nothing is adapted or stubbed.
 *
 * # The one thing this page refuses to do
 *
 * It does not build the bytes the wallet signs. The node does, at
 * `POST /objective/prepare`, and this page relays them unread. Canonical
 * encoding decides a record's identity and lives in two implementations that
 * must agree; a third here would be a consensus rule in a browser, versioned by
 * nothing and unable to run the conformance vectors. See `lib/submit.ts`.
 *
 * # And the thing it will not claim
 *
 * A 202 is a queue receipt. The operator's `cairn drain` re-decides every rule
 * against the whole log, and can refuse. The success panel says so in those
 * words, because a green tick that means "probably" is worse than no tick.
 *
 * # Where the checker hash comes from
 *
 * It is the pin, and it is the one field a person retypes wrong. So the form
 * offers two honest sources before a text box: load the `objective.json` that
 * `cairn scaffold` wrote, which already carries it, or pick the checker file
 * itself and let WebCrypto hash it — the same `shasum -a 256` a funder would
 * run, and not a consensus rule, since the node checks the pinned file against
 * the declared hash on its own before trusting either.
 */
export default function Page() {
  const [draft, setDraft] = useState<Draft>(EMPTY_DRAFT);
  // Which fields the funder has actually touched. A form that greets you with
  // six red lines has told you nothing you did not know — you have just
  // arrived — and it trains people to read red as decoration. Every problem is
  // still computed on every keystroke; this only decides when to *show* one.
  const [touched, setTouched] = useState<Partial<Record<keyof Draft, true>>>({});
  const [wallet, setWallet] = useState<Wallet | null>(null);
  const [wallets, setWallets] = useState<{ kind: string; label: string }[]>([]);
  const [evmOnly, setEvmOnly] = useState(false);
  const [onPhone, setOnPhone] = useState(false);
  const [walletError, setWalletError] = useState<string | null>(null);

  const [loadNote, setLoadNote] = useState<{ tone: "accent" | "warn" | "bad"; text: string } | null>(
    null,
  );
  const [hashNote, setHashNote] = useState<string | null>(null);
  const objectiveFile = useRef<HTMLInputElement>(null);
  const checkerFile = useRef<HTMLInputElement>(null);

  const [prepared, setPrepared] = useState<Prepared | null>(null);
  const [signature, setSignature] = useState<string | null>(null);
  const [receipt, setReceipt] = useState<Queued | null>(null);
  const [busy, setBusy] = useState<null | "preparing" | "signing" | "submitting">(null);
  const [error, setError] = useState<string | null>(null);

  // `created_at` is fixed when the page loads rather than at submit time. It is
  // inside the objective's id, so a value that moved between "prepare" and
  // "submit" would produce a signature over one record and a submission of a
  // different one — which fails verification for a reason no message explains.
  const [createdAt] = useState(() => new Date().toISOString().replace(/\.\d+Z$/, "+00:00"));

  const canWrite = reachableForWrites();

  useEffect(() => {
    setWallets(available());
    setEvmOnly(hasEvmOnly());
    // After mount: a UA read during prerender would disagree with the phone
    // that hydrates, and the extra sentence would be a hydration warning.
    setOnPhone(isMobileBrowser());
    // Reconnect silently if this origin is already trusted, so a returning
    // funder is not made to approve the same page again.
    void (async () => {
      for (const candidate of available()) {
        try {
          const restored = await connect(candidate.kind, true);
          setWallet(restored);
          setDraft((d) => ({ ...d, funder: restored.funder }));
          return;
        } catch {
          // Not previously trusted. Normal, and not worth reporting.
        }
      }
    })();
  }, []);

  const found = useMemo(() => problems(draft), [draft]);
  const complete = Object.keys(found).length === 0;
  const record = useMemo(
    () => (complete ? toRecord(draft, createdAt) : null),
    [complete, draft, createdAt],
  );

  // Any edit invalidates a signature made over the previous draft. Silently
  // keeping it would submit a record whose authorization covers something else.
  const invalidate = useCallback(() => {
    setPrepared(null);
    setSignature(null);
    setReceipt(null);
    setError(null);
  }, []);

  const set = useCallback(
    <K extends keyof Draft>(key: K, value: Draft[K]) => {
      setDraft((d) => ({ ...d, [key]: value }));
      setTouched((t) => ({ ...t, [key]: true }));
      invalidate();
    },
    [invalidate],
  );

  async function onConnect(kind: string) {
    setWalletError(null);
    try {
      const connected = await connect(kind);
      setWallet(connected);
      set("funder", connected.funder);
    } catch (cause) {
      setWalletError(cause instanceof Error ? cause.message : String(cause));
    }
  }

  async function onLoadObjective(file: File | undefined) {
    if (!file) return;
    try {
      const { draft: loaded, dropped } = fromRecord(JSON.parse(await file.text()));
      // A connected wallet stays the funder: the file's funder is whoever
      // scaffolded it, and the person at this page is the one about to sign.
      setDraft(wallet ? { ...loaded, funder: wallet.funder } : loaded);
      setTouched({});
      invalidate();
      setLoadNote(
        dropped.length > 0
          ? {
              tone: "warn",
              text:
                `Loaded ${file.name}. Not carried: ${dropped.join(", ")} — the form has ` +
                "no control for them, so the posted objective will differ from the file there.",
            }
          : { tone: "accent", text: `Loaded ${file.name}. Every field of it is in the form.` },
      );
    } catch (cause) {
      setLoadNote({
        tone: "bad",
        text: `${file.name} is not an objective: ${cause instanceof Error ? cause.message : String(cause)}`,
      });
    }
  }

  async function onHashChecker(file: File | undefined) {
    if (!file) return;
    setHashNote(null);
    try {
      const digest = await sha256Hex(await file.arrayBuffer());
      set("programSha256", digest);
      if (!draft.program.trim()) set("program", file.name);
      setHashNote(`sha256 of ${file.name} (${file.size.toLocaleString()} bytes), hashed here.`);
    } catch (cause) {
      setHashNote(cause instanceof Error ? cause.message : String(cause));
    }
  }

  async function onPrepare() {
    if (!record) return;
    setBusy("preparing");
    setError(null);
    try {
      setPrepared(await prepare(record));
      setSignature(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(null);
    }
  }

  async function onSign() {
    if (!prepared || !wallet) return;
    setBusy("signing");
    setError(null);
    try {
      setSignature(await signPayload(wallet.kind, prepared.payload_hex));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(null);
    }
  }

  async function onSubmit() {
    if (!record) return;
    setBusy("submitting");
    setError(null);
    try {
      const signed = signature ? { ...record, funding_signature: signature } : record;
      setReceipt(await submit(signed));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(null);
    }
  }

  const needsSignature = isKeyShaped(draft.funder.trim());
  const readyToSubmit = complete && (!needsSignature || Boolean(signature));
  const kind = kindInfo(draft.verifierKind);
  const scored = isScored(draft.verifierKind);

  const objectiveJson = record ? JSON.stringify(record, null, 2) : "";
  const signedJson = record
    ? JSON.stringify(signature ? { ...record, funding_signature: signature } : record, null, 2)
    : "";

  return (
    <>
      <header className="mb-8 max-w-[62rem]">
        <h1 className="text-[26px] font-semibold">Post a challenge</h1>
        <p className="prose-block mt-2">
          A challenge is a question with a <b>pinned checker</b> and a bounty. The
          checker decides what passes — not the prose, and not you, once it is
          posted. Editing it later posts a <i>different</i> objective, and claims
          against the original stop resolving.
        </p>
      </header>

      {!canWrite && (
        <div className="mb-6">
          <Note title="this page cannot submit from here" tone="warn">
            You are reading this from{" "}
            <span className="mono">{NODE_URL || "another origin"}</span>, and a node
            accepts submissions same-origin only — a JSON <span className="mono">POST</span>{" "}
            is preflighted, and <span className="mono">OPTIONS</span> is deliberately
            unrouted so no page can make its visitors fill a stranger&rsquo;s queue.
            Open this page from the node itself (<span className="mono">cairn run --serve
            0.0.0.0:8080</span>, then <span className="mono">/ui/submit</span>), or use
            the <span className="mono">cairn post</span> command in the panel on the
            right. Everything else on this page still works.
          </Note>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_26rem]">
        {/* -- the form ---------------------------------------------------- */}
        <div className="flex flex-col gap-6">
          <Card className="card-pad">
            <SectionHeading
              aside={
                <>
                  <input
                    ref={objectiveFile}
                    type="file"
                    accept=".json,application/json"
                    className="hidden"
                    onChange={(event) => void onLoadObjective(event.target.files?.[0])}
                  />
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => objectiveFile.current?.click()}
                  >
                    Load objective.json
                  </button>
                </>
              }
            >
              Start from a scaffold
            </SectionHeading>
            <p className="text-[12.5px] leading-relaxed text-ink-2">
              <span className="mono">cairn scaffold my-challenge --kind {draft.verifierKind}</span>{" "}
              writes an <span className="mono">objective.json</span> with the checker
              already hashed. Load it here and only the bounty and the funder are left
              to decide. Nothing leaves this page: the file is read in the browser.
            </p>
            {loadNote && (
              <div className="mt-3">
                <Note tone={loadNote.tone}>{loadNote.text}</Note>
              </div>
            )}
          </Card>

          <Card className="card-pad">
            <SectionHeading>Who is funding it</SectionHeading>

            {wallet ? (
              <div className="flex flex-wrap items-center gap-3">
                <Badge tone="accent">{wallet.label} connected</Badge>
                <span className="mono truncate text-[12px] text-ink-2" title={wallet.address}>
                  {wallet.address.slice(0, 8)}…{wallet.address.slice(-6)}
                </span>
                <button
                  type="button"
                  className="btn btn-sm btn-ghost ml-auto"
                  onClick={() => {
                    setWallet(null);
                    set("funder", "");
                  }}
                >
                  Disconnect
                </button>
              </div>
            ) : (
              <div className="flex flex-wrap gap-2">
                {wallets.map((candidate) => (
                  <button
                    key={candidate.kind}
                    type="button"
                    className="btn"
                    onClick={() => void onConnect(candidate.kind)}
                  >
                    Connect {candidate.label}
                  </button>
                ))}
                {wallets.length === 0 && (
                  <p className="text-[13px] text-ink-2">
                    No Ed25519 wallet found in this browser.
                    {evmOnly && (
                      <>
                        {" "}
                        An Ethereum wallet is present, and cannot be used:{" "}
                        <b>EVM wallets sign secp256k1</b>, and a cairn funder is an
                        Ed25519 key. There is no conversion between the two, so
                        connecting one could only look like it worked.
                      </>
                    )}
                    {onPhone && !evmOnly && (
                      <>
                        {" "}
                        Safari (and Chrome) on a phone do not inject wallets.
                        Open this page in <b>Phantom&rsquo;s in-app browser</b>{" "}
                        — Browse, then this URL — which is the one place on iOS
                        that `signMessage` exists. The native reader in{" "}
                        <a
                          className="text-accent hover:underline"
                          href={repoLink("gui/ios/")}
                        >
                          gui/ios
                        </a>{" "}
                        reads a node; it does not sign.{" "}
                      </>
                    )}{" "}
                    Phantom, Solflare and Backpack all work on a desktop. Or fund
                    under a plain name below.
                  </p>
                )}
              </div>
            )}

            {walletError && (
              <div className="mt-3">
                <Note title="the wallet refused" tone="bad">
                  {walletError}
                </Note>
              </div>
            )}

            <div className="mt-4">
              <label className="label" htmlFor="funder">
                Funder
              </label>
              <input
                id="funder"
                className="field field-mono"
                value={draft.funder}
                onChange={(event) => set("funder", event.target.value)}
                placeholder="a 64-character public key, or a name like alice"
              />
              <p className="hint">
                {needsSignature ? (
                  <>
                    This is a <b>signed identity</b>: 64 hex characters is a public
                    key, so the record must carry that key&rsquo;s signature. Nobody
                    can post under it without the key — which is what makes citation
                    flow pay the right person.
                  </>
                ) : draft.funder.trim() ? (
                  <>
                    This is an <b>unauthenticated nickname</b>. Anyone can use it, and
                    nothing is checked. Fine for a demo log; on a log that declares a
                    supply, a nickname funder is refused outright.
                  </>
                ) : (
                  <>
                    Connect a wallet to fund as its key, or type a name to fund
                    unauthenticated.
                  </>
                )}
              </p>
              <Problem of="funder" found={found} touched={touched} />
            </div>
          </Card>

          <Card className="card-pad">
            <SectionHeading>The question</SectionHeading>
            <div className="flex flex-col gap-4">
              <div>
                <label className="label" htmlFor="goal">
                  Goal
                </label>
                <input
                  id="goal"
                  className="field"
                  value={draft.goal}
                  onChange={(event) => set("goal", event.target.value)}
                  placeholder="GOAL-collatz-extremes"
                />
                <p className="hint">A short handle. It is what every list shows.</p>
                <Problem of="goal" found={found} touched={touched} />
              </div>

              <div>
                <label className="label" htmlFor="statement">
                  Statement
                </label>
                <textarea
                  id="statement"
                  className="field min-h-28 resize-y"
                  value={draft.statement}
                  onChange={(event) => set("statement", event.target.value)}
                  placeholder="What must a solver produce, and what counts as better?"
                />
                <p className="hint">
                  Prose, and <b>the network treats it as untrusted</b> — every page
                  here labels it so, because an agent reading a statement is reading
                  something a stranger wrote. It documents the bounty; the checker
                  decides it.
                </p>
                <Problem of="statement" found={found} touched={touched} />
              </div>

              <div>
                <label className="label" htmlFor="schema">
                  Artifact shape <span className="text-ink-3">(optional, JSON)</span>
                </label>
                <textarea
                  id="schema"
                  className="field field-mono min-h-20 resize-y"
                  value={draft.artifactSchema}
                  onChange={(event) => set("artifactSchema", event.target.value)}
                  placeholder='{"type":"object","required":["n"],"properties":{"n":{"type":"integer"}}}'
                  spellCheck={false}
                />
                <p className="hint">
                  What the checker expects, for a solver who has only the record.
                  Documentation, not a rule — nothing validates against it, and nothing
                  may: the pinned verifier is the only thing that decides what passes.
                </p>
                <Problem of="artifactSchema" found={found} touched={touched} />
              </div>
            </div>
          </Card>

          <Card className="card-pad">
            <SectionHeading>The checker</SectionHeading>
            <p className="mb-4 text-[13px] leading-relaxed text-ink-2">
              The verifier is what actually decides payment. The published schema
              requires only its <span className="mono">kind</span>; the fields each
              kind needs are checked by the verifier itself, when a verdict is first
              wanted — so they are pinned here, before money moves.
            </p>

            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {VERIFIER_KINDS.map((option) => {
                const active = draft.verifierKind === option.kind;
                return (
                  <button
                    key={option.kind}
                    type="button"
                    onClick={() => set("verifierKind", option.kind)}
                    aria-pressed={active}
                    className={`rounded-lg border p-3 text-left transition-all ${
                      active
                        ? "border-accent bg-accent-soft"
                        : "border-edge bg-surface hover:border-edge-strong"
                    }`}
                  >
                    <div className="text-[13px] font-medium">{option.title}</div>
                    <div className="mt-1 text-[12px] leading-snug text-ink-2">
                      {option.blurb}
                    </div>
                  </button>
                );
              })}
            </div>

            <div className="mt-4 flex flex-col gap-4">
              {kind.program && (
                <>
                  <div className="grid gap-4 sm:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
                    <div>
                      <label className="label" htmlFor="program">
                        {kind.program === "statistic" ? "Statistic path" : `${cap(kind.program)} path`}
                      </label>
                      <input
                        id="program"
                        className="field field-mono"
                        value={draft.program}
                        onChange={(event) => set("program", event.target.value)}
                        placeholder={`examples/my-challenge/${kind.program}s/${kind.program}.py`}
                      />
                      <p className="hint">Relative to the objective bundle root.</p>
                      <Problem of="program" found={found} touched={touched} />
                    </div>
                    <div>
                      <label className="label" htmlFor="entrypoint">
                        Entrypoint
                      </label>
                      <input
                        id="entrypoint"
                        className="field field-mono"
                        value={draft.entrypoint}
                        onChange={(event) => set("entrypoint", event.target.value)}
                        placeholder={draft.verifierKind === "evaluator" ? "score" : "check"}
                      />
                      <Problem of="entrypoint" found={found} touched={touched} />
                    </div>
                  </div>

                  <div>
                    <div className="mb-1.5 flex items-center justify-between gap-2">
                      <label className="label mb-0" htmlFor="sha">
                        {cap(kind.program)} sha256
                      </label>
                      <input
                        ref={checkerFile}
                        type="file"
                        className="hidden"
                        onChange={(event) => void onHashChecker(event.target.files?.[0])}
                      />
                      <button
                        type="button"
                        className="btn btn-sm"
                        onClick={() => checkerFile.current?.click()}
                      >
                        Hash a file
                      </button>
                    </div>
                    <input
                      id="sha"
                      className="field field-mono"
                      value={draft.programSha256}
                      onChange={(event) => set("programSha256", event.target.value.trim())}
                      placeholder="64 lowercase hex characters"
                      spellCheck={false}
                    />
                    <p className="hint">
                      {hashNote ?? (
                        <>
                          This is the pin. Without it the objective says &ldquo;run this
                          path&rdquo;, which is a promise about a file anyone can edit after
                          work has started. Pick the file to hash it here, or{" "}
                          <span className="mono">
                            shasum -a 256 {draft.program || `<${kind.program}>`}
                          </span>
                          .
                        </>
                      )}
                    </p>
                    <Problem of="programSha256" found={found} touched={touched} />
                  </div>
                </>
              )}

              {scored && (
                <div className="grid gap-4 sm:grid-cols-2">
                  <div>
                    <label className="label" htmlFor="threshold">
                      Threshold
                    </label>
                    <input
                      id="threshold"
                      className="field field-mono"
                      inputMode="decimal"
                      value={draft.threshold}
                      onChange={(event) => set("threshold", event.target.value)}
                      placeholder="20"
                    />
                    <p className="hint">The score at which a candidate passes at all.</p>
                    <Problem of="threshold" found={found} touched={touched} />
                  </div>
                  <div>
                    <label className="label" htmlFor="direction">
                      Direction
                    </label>
                    <select
                      id="direction"
                      className="field"
                      value={draft.direction}
                      onChange={(event) => set("direction", event.target.value)}
                    >
                      <option value="maximize">maximize — higher is better</option>
                      <option value="minimize">minimize — lower is better</option>
                    </select>
                    <p className="hint">Shared with the ratchet below; they cannot disagree.</p>
                  </div>
                </div>
              )}

              {draft.verifierKind === "lean" && (
                <div className="flex flex-col gap-4">
                  <div>
                    <label className="label" htmlFor="lean-statement">
                      Statement
                    </label>
                    <textarea
                      id="lean-statement"
                      className="field field-mono min-h-24 resize-y"
                      value={draft.leanStatement}
                      onChange={(event) => set("leanStatement", event.target.value)}
                      placeholder="theorem two_plus_two : 2 + 2 = 4"
                      spellCheck={false}
                    />
                    <p className="hint">
                      The theorem, as Lean source. A submitter supplies the proof term;
                      the toolchain is the checker.
                    </p>
                    <Problem of="leanStatement" found={found} touched={touched} />
                  </div>
                  <div className="grid gap-4 sm:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
                    <div>
                      <label className="label" htmlFor="lean-preamble">
                        Preamble <span className="text-ink-3">(optional)</span>
                      </label>
                      <textarea
                        id="lean-preamble"
                        className="field field-mono min-h-16 resize-y"
                        value={draft.leanPreamble}
                        onChange={(event) => set("leanPreamble", event.target.value)}
                        placeholder="import Mathlib"
                        spellCheck={false}
                      />
                    </div>
                    <div>
                      <label className="label" htmlFor="lean-timeout">
                        Timeout, seconds <span className="text-ink-3">(optional)</span>
                      </label>
                      <input
                        id="lean-timeout"
                        className="field field-mono"
                        inputMode="numeric"
                        value={draft.timeoutSeconds}
                        onChange={(event) => set("timeoutSeconds", event.target.value)}
                        placeholder="60"
                      />
                      <Problem of="timeoutSeconds" found={found} touched={touched} />
                    </div>
                  </div>
                </div>
              )}

              {draft.verifierKind === "replay" && (
                <div className="flex flex-col gap-4">
                  <div>
                    <label className="label" htmlFor="replay-command">
                      Command
                    </label>
                    <textarea
                      id="replay-command"
                      className="field field-mono min-h-20 resize-y"
                      value={draft.replayCommand}
                      onChange={(event) => set("replayCommand", event.target.value)}
                      placeholder={"python3\nrun.py\n--seed\n1"}
                      spellCheck={false}
                    />
                    <p className="hint">
                      One argument per line. Runs in a jail with no network, read-only
                      under the objective root.
                    </p>
                    <Problem of="replayCommand" found={found} touched={touched} />
                  </div>
                  <div className="grid gap-4 sm:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
                    <div>
                      <label className="label" htmlFor="replay-fields">
                        Reproducible fields
                      </label>
                      <input
                        id="replay-fields"
                        className="field field-mono"
                        value={draft.replayFields}
                        onChange={(event) => set("replayFields", event.target.value)}
                        placeholder="relations_found, degree"
                      />
                      <p className="hint">
                        Comma-separated. The fields of the result that must match on
                        re-run; machine-dependent ones like timings are refused.
                      </p>
                      <Problem of="replayFields" found={found} touched={touched} />
                    </div>
                    <div>
                      <label className="label" htmlFor="replay-cwd">
                        Working directory <span className="text-ink-3">(optional)</span>
                      </label>
                      <input
                        id="replay-cwd"
                        className="field field-mono"
                        value={draft.replayCwd}
                        onChange={(event) => set("replayCwd", event.target.value)}
                        placeholder="."
                      />
                    </div>
                  </div>
                </div>
              )}

              <div>
                <label className="label" htmlFor="extras">
                  Other verifier fields <span className="text-ink-3">(optional, JSON)</span>
                </label>
                <textarea
                  id="extras"
                  className="field field-mono min-h-16 resize-y"
                  value={draft.verifierExtras}
                  onChange={(event) => set("verifierExtras", event.target.value)}
                  placeholder='{"timeout_seconds": 30}'
                  spellCheck={false}
                />
                <p className="hint">
                  Anything this form has no control for — <span className="mono">stepper</span>,{" "}
                  <span className="mono">seed</span>, a certificate&rsquo;s{" "}
                  <span className="mono">timeout_seconds</span>. Merged into the verifier
                  as written; a loaded file&rsquo;s extra fields land here.
                </p>
                <Problem of="verifierExtras" found={found} touched={touched} />
              </div>
            </div>
          </Card>

          <Card className="card-pad">
            <SectionHeading>The bounty</SectionHeading>
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label className="label" htmlFor="reward">
                  Reward, in units
                </label>
                <input
                  id="reward"
                  className="field field-mono"
                  inputMode="numeric"
                  value={draft.reward}
                  onChange={(event) => set("reward", event.target.value)}
                  placeholder="100000"
                />
                <p className="hint">
                  A whole number. There are no floats anywhere near money here — a
                  rounding difference between two implementations is a disagreement
                  about who was paid.
                </p>
                <Problem of="reward" found={found} touched={touched} />
              </div>
              <div>
                <label className="label" htmlFor="deadline">
                  Deadline <span className="text-ink-3">(optional)</span>
                </label>
                <input
                  id="deadline"
                  className="field field-mono"
                  value={draft.deadline}
                  onChange={(event) => set("deadline", event.target.value)}
                  placeholder="2026-12-31T00:00:00+00:00"
                />
                <p className="hint">RFC 3339. Left blank, the bounty does not expire.</p>
              </div>
            </div>

            <label className="mt-4 flex cursor-pointer items-start gap-2.5">
              <input
                type="checkbox"
                className="mt-0.5 accent-[var(--accent)]"
                checked={draft.requireSignedSubmitter}
                onChange={(event) => set("requireSignedSubmitter", event.target.checked)}
              />
              <span className="text-[13px]">
                <b>Require signed submitters.</b>
                <span className="block text-ink-2">
                  Every claim must come from a key, not a nickname. The cost is real
                  and it is yours: it turns away contributors who have not made an
                  identity.
                </span>
              </span>
            </label>
          </Card>

          <Card className="card-pad">
            <SectionHeading>Progressive payout</SectionHeading>
            <label className="flex cursor-pointer items-start gap-2.5">
              <input
                type="checkbox"
                className="mt-0.5 accent-[var(--accent)]"
                checked={draft.useRatchet}
                onChange={(event) => set("useRatchet", event.target.checked)}
              />
              <span className="text-[13px]">
                <b>Pay along an improvement curve (a ratchet).</b>
                <span className="block text-ink-2">
                  Instead of one payment to one winner, each improvement is paid for
                  how far it moved the frontier. That is what makes publishing
                  immediately the profitable move rather than a gift to your
                  competitors. Requires an <b>evaluator</b>, which produces a score;
                  a certificate has nothing to score.
                </span>
              </span>
            </label>
            <Problem of="useRatchet" found={found} touched={touched} />

            {draft.useRatchet && (
              <div className="mt-4 grid gap-4 sm:grid-cols-3">
                <div>
                  <label className="label" htmlFor="baseline">
                    Baseline
                  </label>
                  <input
                    id="baseline"
                    className="field field-mono"
                    value={draft.baseline}
                    onChange={(event) => set("baseline", event.target.value)}
                    placeholder="9"
                  />
                  <p className="hint">Anything at or below it has moved nothing.</p>
                  <Problem of="baseline" found={found} touched={touched} />
                </div>
                <div>
                  <label className="label" htmlFor="target">
                    Target
                  </label>
                  <input
                    id="target"
                    className="field field-mono"
                    value={draft.target}
                    onChange={(event) => set("target", event.target.value)}
                    placeholder="20"
                  />
                  <p className="hint">Where the pool is exactly exhausted.</p>
                  <Problem of="target" found={found} touched={touched} />
                </div>
                <div>
                  <label className="label" htmlFor="minimprovement">
                    Minimum improvement
                  </label>
                  <input
                    id="minimprovement"
                    className="field field-mono"
                    value={draft.minImprovement}
                    onChange={(event) => set("minImprovement", event.target.value)}
                    placeholder="3"
                  />
                  <p className="hint">
                    The smallest move that pays. Set it deliberately: it is currently
                    the only thing bounding how finely a span can be sliced.{" "}
                    <a
                      className="text-accent hover:underline"
                      href={repoLink("docs/threat-model.md")}
                    >
                      threat-model.md
                    </a>
                  </p>
                  <Problem of="minImprovement" found={found} touched={touched} />
                </div>
              </div>
            )}
          </Card>
        </div>

        {/* -- review and sign --------------------------------------------- */}
        <aside className="lg:sticky lg:top-20 lg:self-start">
          <div className="flex flex-col gap-4">
            <Card className="card-pad">
              <SectionHeading>Review &amp; authorize</SectionHeading>

              <ol className="flex flex-col gap-3">
                <Step
                  n={1}
                  title="Compose"
                  done={complete}
                  detail={
                    complete
                      ? "The draft is complete."
                      : `${Object.keys(found).length} field${
                          Object.keys(found).length === 1 ? "" : "s"
                        } still to fill.`
                  }
                />
                <Step
                  n={2}
                  title="Canonicalize"
                  done={Boolean(prepared)}
                  detail={
                    prepared
                      ? "The node returned the exact bytes to sign."
                      : "The node encodes the record and returns the bytes. This page never computes them."
                  }
                />
                <Step
                  n={3}
                  title={needsSignature ? "Sign with the wallet" : "No signature needed"}
                  done={needsSignature ? Boolean(signature) : true}
                  detail={
                    needsSignature
                      ? signature
                        ? "Signed. The node will verify it against the funder key."
                        : "The wallet signs those bytes and nothing else."
                      : "A nickname funder carries no signature, and none is demanded."
                  }
                />
                <Step
                  n={4}
                  title="Queue it"
                  done={Boolean(receipt)}
                  detail="Queued for the operator to drain. Not admitted until then."
                />
              </ol>

              <div className="mt-4 flex flex-col gap-2">
                <button
                  type="button"
                  className="btn"
                  disabled={!complete || busy !== null || !canWrite}
                  onClick={() => void onPrepare()}
                >
                  {busy === "preparing" ? "Asking the node…" : "Canonicalize"}
                </button>

                {needsSignature && (
                  <button
                    type="button"
                    className="btn"
                    disabled={!prepared || !wallet || busy !== null}
                    onClick={() => void onSign()}
                  >
                    {busy === "signing"
                      ? "Waiting for the wallet…"
                      : signature
                        ? "Sign again"
                        : `Sign with ${wallet?.label ?? "a wallet"}`}
                  </button>
                )}

                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={!readyToSubmit || busy !== null || !canWrite}
                  onClick={() => void onSubmit()}
                >
                  {busy === "submitting" ? "Submitting…" : "Submit to the node"}
                </button>
              </div>

              {error && (
                <div className="mt-4">
                  <Note
                    title={error.includes("same-origin") ? "cannot reach the node" : "refused"}
                    tone="bad"
                  >
                    {error}
                  </Note>
                </div>
              )}
            </Card>

            {prepared && (
              <Card className="card-pad">
                <SectionHeading>What the wallet signs</SectionHeading>
                <p className="mb-2 text-[12.5px] leading-relaxed text-ink-2">
                  These bytes, exactly. The domain tag is what stops a signature made
                  here being replayed as some other kind of authorization.
                </p>
                <pre className="code max-h-52 overflow-auto text-[11.5px]">{prepared.payload}</pre>
                <div className="mt-2 flex items-center gap-2 text-[12px] text-ink-2">
                  <span>digest</span>
                  <Hash value={prepared.digest} chars={10} />
                </div>
                {signature && (
                  <div className="mt-2 flex items-center gap-2 text-[12px] text-ink-2">
                    <span>signature</span>
                    <Hash value={signature} chars={10} />
                  </div>
                )}
              </Card>
            )}

            {receipt && (
              <Card className="card-pad">
                <SectionHeading>Queued</SectionHeading>
                <div className="flex items-center gap-2 text-[12.5px] text-ink-2">
                  <Badge tone="accent">accepted into the queue</Badge>
                </div>
                <div className="mt-2 flex items-center gap-2 text-[12.5px] text-ink-2">
                  <span>spool id</span>
                  <Hash value={receipt.queued} chars={10} />
                </div>
                {/* The node's own words, not a paraphrase. It is the one place
                    that can say what a queue receipt is worth, and softening it
                    here is how a proposal starts reading as a confirmation. */}
                <p className="hint">{receipt.note}</p>
                <div className="mt-3 flex gap-2">
                  <Link href="/objectives" className="btn btn-sm">
                    Watch objectives
                  </Link>
                  <Link href="/log" className="btn btn-sm">
                    Watch the log
                  </Link>
                </div>
              </Card>
            )}

            <Card className="card-pad">
              <SectionHeading>Or post it from a terminal</SectionHeading>
              <p className="mb-2 text-[12.5px] leading-relaxed text-ink-2">
                For a key that lives in a file rather than a wallet, or from a page
                that cannot write to the node. An agent can do the same over MCP with{" "}
                <span className="mono">post_objective</span>.
              </p>
              <div className="relative">
                <pre className="code max-h-64 overflow-auto text-[11.5px]">
                  {objectiveJson || "// fill the form to see the record"}
                </pre>
                {objectiveJson && (
                  <div className="absolute top-2 right-2">
                    <CopyButton value={signedJson} />
                  </div>
                )}
              </div>
              <pre className="code mt-2 text-[11.5px]">
                {`cairn post objective.json${
                  needsSignature ? " --identity ~/.cairn/identity.json" : ""
                }`}
              </pre>
            </Card>
          </div>
        </aside>
      </div>
    </>
  );
}

function cap(word: string): string {
  return word.charAt(0).toUpperCase() + word.slice(1);
}

function Problem({
  of,
  found,
  touched,
}: {
  of: keyof Draft;
  found: Partial<Record<keyof Draft, string>>;
  touched: Partial<Record<keyof Draft, true>>;
}) {
  const message = found[of];
  if (!message || !touched[of]) return null;
  return (
    <p className="mt-1.5 text-[12px] text-bad" role="alert">
      {message}
    </p>
  );
}

function Step({
  n,
  title,
  detail,
  done,
}: {
  n: number;
  title: string;
  detail: string;
  done: boolean;
}) {
  return (
    <li className="flex gap-3">
      <span
        className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full
                    border text-[11px] font-medium ${
                      done ? "border-accent bg-accent text-canvas" : "border-edge text-ink-3"
                    }`}
        aria-hidden
      >
        {done ? "✓" : n}
      </span>
      <span>
        <span className="block text-[13px] font-medium">{title}</span>
        <span className="block text-[12px] leading-snug text-ink-2">{detail}</span>
      </span>
    </li>
  );
}
