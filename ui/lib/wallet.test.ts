import { describe, expect, it } from "vitest";
import {
  base58Decode,
  base58Encode,
  fromHex,
  isKeyShaped,
  isMobileUserAgent,
  toHex,
} from "./wallet";

/**
 * Base58 is the one place in this app where a bug is silent and expensive.
 *
 * A wallet reports its key in base58; a cairn funder id is that key in hex. Get
 * the conversion wrong and the funder field names a key nobody holds — so the
 * signature the wallet produces is valid, over the right bytes, under a key the
 * record does not claim, and the objective is refused at drain time with a
 * message about signatures rather than about encoding.
 *
 * So these are vectors, not round trips. A round trip passes for any encoder
 * that is merely self-consistent, including one that drops leading zeros.
 */
describe("base58", () => {
  // From the Bitcoin base58 test vectors, which are the same alphabet Solana
  // uses. Hex on the left, base58 on the right.
  const vectors: [string, string][] = [
    ["", ""],
    ["61", "2g"],
    ["626262", "a3gV"],
    ["516b6fcd0f", "ABnLTmg"],
    ["00000000000000000000", "1111111111"],
    ["00eb15231dfceb60925886b67d065299925915aeb172c06647", "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"],
  ];

  it("decodes the published vectors", () => {
    for (const [hex, b58] of vectors) {
      if (b58 === "") continue; // the empty string is not a decodable input
      expect(toHex(base58Decode(b58)!), b58).toBe(hex);
    }
  });

  it("encodes the published vectors", () => {
    for (const [hex, b58] of vectors) {
      expect(base58Encode(fromHex(hex)!), hex).toBe(b58);
    }
  });

  /**
   * The bug this exists to catch. Roughly one key in 256 begins with a zero
   * byte, and the big-integer arithmetic in a decoder cannot represent a
   * leading zero — it has to be recovered from the leading `1` characters. A
   * decoder that skips that step returns 31 bytes for those keys and is
   * correct for the other 255 in 256, which is exactly the failure rate that
   * gets a bug shipped.
   */
  it("keeps leading zero bytes, which are the digits arithmetic cannot carry", () => {
    const key = new Uint8Array(32);
    key[31] = 1; // 31 leading zero bytes
    const encoded = base58Encode(key);
    expect(encoded.startsWith("1".repeat(31))).toBe(true);
    const decoded = base58Decode(encoded);
    expect(decoded).not.toBeNull();
    expect(decoded!.length).toBe(32);
    expect(toHex(decoded!)).toBe(toHex(key));
  });

  it("refuses characters outside the alphabet rather than guessing", () => {
    // `0`, `O`, `I` and `l` are excluded from base58 precisely because they are
    // confusable; a decoder that silently mapped them would turn a typo into a
    // different valid-looking key.
    for (const bad of ["0", "O", "I", "l", "abc!", "9+9"]) {
      expect(base58Decode(bad), bad).toBeNull();
    }
  });
});

describe("hex", () => {
  it("pads every byte to two characters", () => {
    // The failure here is a 63-character funder id from a key with a low byte,
    // which `isKeyShaped` then rejects for the wrong reason.
    expect(toHex(new Uint8Array([0, 1, 15, 16, 255]))).toBe("00010f10ff");
  });

  it("refuses odd-length and non-hex input", () => {
    expect(fromHex("abc")).toBeNull();
    expect(fromHex("zz")).toBeNull();
  });

  it("round-trips a full-width key", () => {
    const bytes = new Uint8Array(32).map((_, i) => (i * 7) % 256);
    expect(fromHex(toHex(bytes))).toEqual(bytes);
  });
});

describe("isMobileUserAgent", () => {
  it("recognises a phone, which cannot inject an extension", () => {
    expect(
      isMobileUserAgent(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
      ),
    ).toBe(true);
    expect(
      isMobileUserAgent(
        "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36",
      ),
    ).toBe(true);
  });

  it("does not treat desktop Safari or a missing UA as a phone", () => {
    expect(
      isMobileUserAgent(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
      ),
    ).toBe(false);
    expect(isMobileUserAgent("")).toBe(false);
  });
});

describe("isKeyShaped", () => {
  /** Mirrors `records::signed_submitter`: 64 characters, lowercase only. */
  it("accepts exactly what the node accepts", () => {
    expect(isKeyShaped("a".repeat(64))).toBe(true);
    expect(isKeyShaped("0123456789abcdef".repeat(4))).toBe(true);
  });

  it("rejects uppercase, so one key cannot hold two reputations", () => {
    expect(isKeyShaped("A".repeat(64))).toBe(false);
  });

  it("rejects nicknames and wrong lengths", () => {
    expect(isKeyShaped("alice")).toBe(false);
    expect(isKeyShaped("a".repeat(63))).toBe(false);
    expect(isKeyShaped("a".repeat(65))).toBe(false);
  });
});
