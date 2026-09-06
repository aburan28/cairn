import { describe, expect, it } from "vitest";

import { type SeedList, readableEndpoints } from "@/lib/seeds";

const list = (...http: (string | null)[]): SeedList => ({
  version: 1,
  seeds: http.map((h, i) => ({
    name: `s${i}`,
    addr: null,
    transport: null,
    http: h,
  })),
});

describe("readableEndpoints", () => {
  it("keeps https endpoints in the order the list gives them", () => {
    expect(
      readableEndpoints(list("https://b.example", "https://a.example"), "https:"),
    ).toEqual(["https://b.example", "https://a.example"]);
  });

  /**
   * The one that matters. A browser on an HTTPS page blocks a plain-http
   * subresource before it leaves, so listing one would cost a visitor a
   * console message they never see and a site that looks broken.
   */
  it("drops plain-http endpoints on an https page", () => {
    expect(readableEndpoints(list("http://seed.example"), "https:")).toEqual([]);
  });

  /** ...and keeps them during local development, where the page is http too. */
  it("keeps plain-http endpoints on an http page", () => {
    expect(readableEndpoints(list("http://127.0.0.1:8080"), "http:")).toEqual([
      "http://127.0.0.1:8080",
    ]);
  });

  it("ignores entries with no http endpoint, and anything that is not a URL", () => {
    expect(
      readableEndpoints(list(null, "", "  ", "ftp://seed.example", "javascript:alert(1)"), "https:"),
    ).toEqual([]);
  });

  /** `${base}/objectives` is how every caller builds a URL, so a trailing
   *  slash here becomes a double slash there. */
  it("strips trailing slashes and duplicates", () => {
    expect(
      readableEndpoints(list("https://a.example/", "https://a.example"), "https:"),
    ).toEqual(["https://a.example"]);
  });
});
