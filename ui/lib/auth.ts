/**
 * Optional Google sign-in, as `GET /auth` describes it.
 *
 * The session is a cookie on the node that served this page. It is not a
 * cairn identity — a submitter is an ed25519 key — and a node that did not
 * configure Google has nothing to show. A page that talks to a node on
 * another origin cannot hold the cookie either, so it does not offer a
 * button that would sign the reader into a different site.
 */

export type GoogleAccount = {
  sub: string;
  email: string | null;
  name: string | null;
};

export type AuthStatus = {
  provider?: string;
  required?: boolean;
  anonymous_ok?: boolean;
  available?: boolean;
  authenticated?: boolean;
  mode?: string;
  login?: string;
  account?: GoogleAccount | null;
  reason?: string;
};

/** Sign-in is offered only same-origin, and only when the node configured it. */
export function signInVisible(nodeUrl: string, status: AuthStatus | null): boolean {
  return nodeUrl === "" && status?.available === true && status.authenticated !== true;
}

/** A label for a signed-in browser. Null when there is nothing to say. */
export function signedInLabel(status: AuthStatus | null): string | null {
  if (!status?.authenticated || !status.account) return null;
  const name = status.account.name?.trim();
  if (name) return name;
  const email = status.account.email?.trim();
  if (email) return email;
  return "Signed in";
}

/**
 * The login link the node advertised, if it is a path on this origin.
 *
 * The node is the one that would be lying, and a path that starts with `//`
 * is how a relative URL becomes a different host. Anything else is the route
 * this binary actually serves.
 */
export function loginHref(status: AuthStatus | null): string {
  const login = status?.login;
  if (login && login.startsWith("/") && !login.startsWith("//") && !login.includes("\\")) {
    return login;
  }
  return "/auth/google";
}
