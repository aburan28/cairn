import { describe, expect, it } from "vitest";
import { endpointKind, peerAddress } from "./addresses";

describe("human-facing node addresses", () => {
  it.each(["127.0.0.1:9000", "127.42.1.2:80", "http://localhost:8080", "localhost.:8080", "[::1]:9000", "0:0:0:0:0:0:0:1", "[::ffff:127.0.0.1]:9000", "http://2130706433:80"])("labels loopback %s without presenting it as a peer IP", (value) => {
    expect(endpointKind(value)).toBe("local");
    expect(peerAddress(value)).toBe("Local connection");
  });
  it.each(["0.0.0.0:9000", "[::]:9000", "::", "http://0.0.0.0:8080", "[::ffff:0.0.0.0]:9000"])("never advertises wildcard %s", (value) => {
    expect(endpointKind(value)).toBe("unspecified");
    expect(peerAddress(value)).toBe("Not advertised");
  });
  it.each(["192.168.1.23:9000", "10.2.0.9:9010", "198.51.100.7:80", "[2001:db8::7]:9000", "peer.example:9000", "127.example:9000"])("retains the useful node endpoint %s", (value) => {
    expect(endpointKind(value)).toBe("address");
    expect(peerAddress(value)).toBe(value);
  });
  it.each([null, "", "1.2.7.0.0.1", "http://user:secret@peer.example", "javascript:alert(1)"])("does not turn malformed or credential-bearing %s into a node address", (value) => {
    expect(peerAddress(value)).toBe("Not advertised");
  });
});
