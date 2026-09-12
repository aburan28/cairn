/**
 * Browser wallets, as cairn identities.
 *
 * # Why a wallet works here at all
 *
 * A cairn `funder` is not an account in a registry. It *is* an Ed25519 public
 * key in lowercase hex, and `funding_signature` is that key's signature over
 * the objective's canonical funding payload — see `signed_submitter` and
 * `Objective::funding_signing_payload` in the Rust. Nothing else is consulted:
 * there is no lookup, no session, and no server that could vouch for you.
 *
 * Solana wallets sign with Ed25519 and expose `signMessage(bytes)` over
 * arbitrary bytes. So a Phantom, Solflare or Backpack key is *already* a valid
 * cairn identity, and the signature such a wallet returns is the one the node
 * verifies with the same code path that verifies a signature from
 * `cairn identity`. Nothing is adapted, bridged or simulated: the wallet does
 * real cryptographic work and the node checks it.
 *
 * # Why EVM wallets are refused rather than accommodated
 *
 * MetaMask, Rabby and every other Ethereum wallet sign secp256k1. There is no
 * transformation from a secp256k1 signature to an Ed25519 one, and no way for
 * an Ethereum address to *be* a cairn funder id. An integration that connected
 * to them anyway could only be theatre — a "connected" pill over a flow that
 * must fall back to something else to actually sign. So they are detected and
 * explained, which is more useful than being offered and then failing.
 *
 * # What this module deliberately does not do
 *
 * It does not build the bytes to be signed. Canonical encoding is
 * consensus-critical and lives in exactly two implementations that must agree;
 * a third here, in a browser, unversioned and unable to run the conformance
 * vectors, is precisely the drift AGENTS.md forbids. The node's
 * `POST /objective/prepare` returns the bytes and this module relays them to
 * the wallet unread. See `lib/submit.ts`.
 *
 * It also never sees a secret key. `signMessage` happens inside the wallet;
 * what comes back is a signature.
 */

/** A connected wallet, reduced to the two things cairn needs. */
export type Wallet = {
  /** Which injected provider answered: "phantom", "solflare", … */
  readonly kind: string;
  /** Human name for the chrome. */
  readonly label: string;
  /** The account in the wallet's own base58 spelling, for display. */
  readonly address: string;
  /** The same key as a cairn funder id: 64 lowercase hex characters. */
  readonly funder: string;
};

/** An injected provider we can drive. Structural, so no wallet SDK is needed. */
type Provider = {
  connect?: (options?: { onlyIfTrusted?: boolean }) => Promise<{ publicKey?: unknown }>;
  disconnect?: () => Promise<void>;
  signMessage?: (
    message: Uint8Array,
    display?: string,
  ) => Promise<{ signature?: unknown } | Uint8Array>;
  publicKey?: unknown;
  isPhantom?: boolean;
};

type Candidate = { kind: string; label: string; get: () => Provider | undefined };

/**
 * Where each wallet injects itself.
 *
 * Namespaced first (`window.phantom.solana`) because that is what current
 * Phantom recommends, then the legacy global, which Solflare and Backpack
 * still set. Order is preference order: the first that answers is used.
 */
function candidates(): Candidate[] {
  const w = globalThis as unknown as Record<string, any>;
  return [
    { kind: "phantom", label: "Phantom", get: () => w.phantom?.solana },
    { kind: "solflare", label: "Solflare", get: () => w.solflare },
    { kind: "backpack", label: "Backpack", get: () => w.backpack },
    // Last: several wallets set the bare global, so it is the least specific
    // signal about *which* wallet is answering.
    { kind: "injected", label: "Injected wallet", get: () => w.solana },
  ];
}

/**
 * Is this a phone browser that cannot inject an extension?
 *
 * Safari on iPhone does not run wallet extensions. Phantom, Solflare and
 * Backpack inject only inside their own in-app browsers. Distinguishing the
 * two is what lets `/submit` say *why* the list is empty on a phone, rather
 * than "install an extension" to somebody who cannot. Pure over a UA string
 * so the test does not need a `navigator`.
 */
export function isMobileUserAgent(ua: string): boolean {
  return /iPhone|iPad|iPod|Android/i.test(ua);
}

export function isMobileBrowser(): boolean {
  if (typeof navigator === "undefined") return false;
  return isMobileUserAgent(navigator.userAgent);
}

/** Every Ed25519 wallet currently present in this page. */
export function available(): { kind: string; label: string }[] {
  const seen = new Set<Provider>();
  const found: { kind: string; label: string }[] = [];
  for (const candidate of candidates()) {
    const provider = candidate.get();
    // `signMessage` is the capability that matters; a provider without it
    // cannot fund anything and should not be offered.
    if (!provider || typeof provider.signMessage !== "function") continue;
    if (seen.has(provider)) continue;
    seen.add(provider);
    found.push({ kind: candidate.kind, label: candidate.label });
  }
  return found;
}

/**
 * An EVM wallet is present.
 *
 * Reported separately from `available` so the page can say *why* MetaMask is
 * not on the list, rather than showing an empty one to somebody who can see
 * their wallet in the toolbar.
 */
export function hasEvmOnly(): boolean {
  const w = globalThis as unknown as Record<string, any>;
  return Boolean(w.ethereum) && available().length === 0;
}

function providerFor(kind: string): Provider {
  const candidate = candidates().find((c) => c.kind === kind);
  const provider = candidate?.get();
  if (!provider) throw new Error(`no ${kind} wallet is present in this browser`);
  return provider;
}

/**
 * Connect, and report the account as a cairn funder id.
 *
 * `onlyIfTrusted` is the silent path: it resolves for a wallet that has
 * already approved this origin and rejects otherwise, without showing a
 * prompt. That is what lets the page restore a connection on load without
 * every visit popping a wallet dialog at somebody who never asked.
 */
export async function connect(kind: string, silent = false): Promise<Wallet> {
  const provider = providerFor(kind);
  if (typeof provider.connect !== "function") {
    throw new Error("this wallet does not support connecting from a page");
  }
  const result = await provider.connect(silent ? { onlyIfTrusted: true } : undefined);
  const key = result?.publicKey ?? provider.publicKey;
  const address = readAddress(key);
  if (!address) throw new Error("the wallet connected but reported no public key");

  const bytes = base58Decode(address);
  if (!bytes || bytes.length !== 32) {
    throw new Error(
      `the wallet reported a ${bytes ? bytes.length : "?"}-byte key; a cairn ` +
        "funder is a 32-byte Ed25519 public key, so this is not an Ed25519 wallet",
    );
  }
  const label = candidates().find((c) => c.kind === kind)?.label ?? kind;
  return { kind, label, address, funder: toHex(bytes) };
}

export async function disconnect(kind: string): Promise<void> {
  const provider = providerFor(kind);
  if (typeof provider.disconnect === "function") await provider.disconnect();
}

/**
 * Sign exactly these bytes.
 *
 * `payloadHex` comes from the node and is relayed unread: this decodes hex to
 * bytes and hands them over. Nothing here inspects, reformats or re-derives
 * the message, which is the property that makes the signature verifiable —
 * the node recomputes the same payload from the record it is given, so any
 * cleverness applied here could only produce a signature that fails.
 *
 * The returned signature is 64 bytes, hex-encoded, which is the spelling
 * `funding_signature` uses.
 */
export async function signPayload(kind: string, payloadHex: string): Promise<string> {
  const provider = providerFor(kind);
  if (typeof provider.signMessage !== "function") {
    throw new Error("this wallet cannot sign messages");
  }
  const message = fromHex(payloadHex);
  if (!message) throw new Error("the node returned a payload that is not hex");

  // Phantom takes a display hint and returns `{ signature }`; some wallets
  // return the bare bytes. Both shapes are handled because guessing wrong
  // shows up as a signature that verifies nowhere.
  const answer = await provider.signMessage(message, "utf8");
  const raw =
    answer instanceof Uint8Array
      ? answer
      : (answer as { signature?: unknown })?.signature;
  const bytes = asBytes(raw);
  if (!bytes) throw new Error("the wallet returned no signature");
  if (bytes.length !== 64) {
    throw new Error(
      `the wallet returned a ${bytes.length}-byte signature; Ed25519 signatures are 64 bytes`,
    );
  }
  return toHex(bytes);
}

// -- encodings --------------------------------------------------------------
//
// Hand-written because the alternative is a dependency, and this app loads
// nothing it was not served. Both are small, and both are covered by
// `wallet.test.ts` against vectors rather than against themselves.

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Bitcoin-alphabet base58, which is how every Solana wallet spells a key.
 *
 * Returns `null` rather than throwing on a bad character: the input is a
 * string from an extension we do not control, and a caller that has to
 * `try`/`catch` around a decode will eventually forget to.
 */
export function base58Decode(text: string): Uint8Array | null {
  if (text.length === 0) return null;
  const bytes: number[] = [];
  for (const char of text) {
    let carry = B58.indexOf(char);
    if (carry < 0) return null;
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  // Each leading '1' is one leading zero byte, which the arithmetic above
  // cannot represent and would otherwise silently drop — turning a 32-byte key
  // into a 31-byte one for the small fraction of keys that start with zero.
  for (const char of text) {
    if (char !== "1") break;
    bytes.push(0);
  }
  return new Uint8Array(bytes.reverse());
}

export function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";
  const digits: number[] = [];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8;
      digits[i] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = "";
  for (const byte of bytes) {
    if (byte !== 0) break;
    out += "1";
  }
  for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]];
  return out;
}

/** Lowercase hex, which is the only spelling `signed_submitter` accepts. */
export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

export function fromHex(text: string): Uint8Array | null {
  if (text.length % 2 !== 0) return null;
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) return null;
    out[i] = byte;
  }
  return out;
}

/** Is this string a cairn signed identity? Mirrors `records::signed_submitter`. */
export function isKeyShaped(name: string): boolean {
  return /^[0-9a-f]{64}$/.test(name);
}

function readAddress(key: unknown): string | null {
  if (typeof key === "string") return key;
  if (key && typeof (key as { toString?: unknown }).toString === "function") {
    const text = String(key);
    return text && text !== "[object Object]" ? text : null;
  }
  return null;
}

/** Wallets return `Uint8Array`, a plain array, or something array-like. */
function asBytes(value: unknown): Uint8Array | null {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return new Uint8Array(value);
  if (value && typeof value === "object" && "length" in (value as object)) {
    return new Uint8Array(Object.values(value as Record<string, number>));
  }
  return null;
}
