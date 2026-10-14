import { describe, expect, it } from "vitest";
import { loginHref, signInVisible, signedInLabel, type AuthStatus } from "./auth";

const ready: AuthStatus = {
  available: true,
  authenticated: false,
  anonymous_ok: true,
  required: false,
  login: "/auth/google",
};

describe("optional Google sign-in", () => {
  it("stays hidden on an anonymous node and on a page that is not the node", () => {
    expect(signInVisible("", { available: false, authenticated: false })).toBe(false);
    expect(signInVisible("", null)).toBe(false);
    expect(signInVisible("https://node.example", ready)).toBe(false);
  });

  it("shows a sign-in link only when this origin's node configured Google", () => {
    expect(signInVisible("", ready)).toBe(true);
    expect(signInVisible("", { ...ready, authenticated: true, account: { sub: "1", email: null, name: "Ada" } })).toBe(
      false,
    );
  });

  it("labels a session by name, then email, and treats a missing account as signed out", () => {
    expect(signedInLabel(null)).toBeNull();
    expect(signedInLabel(ready)).toBeNull();
    expect(
      signedInLabel({
        authenticated: true,
        account: { sub: "1", name: "Ada Lovelace", email: "ada@example.com" },
      }),
    ).toBe("Ada Lovelace");
    expect(
      signedInLabel({
        authenticated: true,
        account: { sub: "1", name: "  ", email: "ada@example.com" },
      }),
    ).toBe("ada@example.com");
    expect(signedInLabel({ authenticated: true, account: { sub: "1", name: null, email: null } })).toBe(
      "Signed in",
    );
  });

  it("refuses a login link that would leave this origin", () => {
    expect(loginHref({ login: "/auth/google" })).toBe("/auth/google");
    expect(loginHref({ login: "//evil.example" })).toBe("/auth/google");
    expect(loginHref({ login: "https://accounts.google.com" })).toBe("/auth/google");
    expect(loginHref(null)).toBe("/auth/google");
  });
});
