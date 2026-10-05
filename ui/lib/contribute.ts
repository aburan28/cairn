/**
 * Ways to take part, what each one pays, and how to start -- the facts behind
 * `/contribute`.
 *
 * The pay column is the part that has to stay true. It is written against
 * what the node's rules actually move today (`Node::gross_paid_within` in
 * `src/node.rs` is the only place a unit is credited), and it says "not paid"
 * where that is the answer. A page that implied validators or relays earn
 * would be the one place on this site making a claim the log cannot back,
 * and docs/design/roles-and-rewards.md is where the reasons and the plan
 * live -- change both together.
 */

import type { Bridge } from "./draft";

export type RoleId = "experimenter" | "compute" | "validator" | "relay" | "funder";

/**
 * A role Cairn.app can turn on from this page: one toggle in its Settings ▸
 * Roles each, named here as `PageRole` in `gui/macos-app` names it. The app
 * writes the setting and restarts the node, after confirming natively --
 * a page is scriptable, and two of these open a port while the third
 * stakes money -- so a button here is a request, never the change itself.
 */
export type AppRole = "validator" | "relay" | "worker-host";

/** A sheet of Cairn.app's that a page may open (`PageSheet`). */
export type AppSheet = "agents" | "work" | "peers" | "settings" | "new-challenge";

/** The messages the app reads; `PageRequest.swift` parses exactly these. */
export type RoleRequest = { kind: "set-role"; role: AppRole; on: boolean };
export type OpenRequest = { kind: "open"; sheet: AppSheet; objective?: string };

/**
 * What the page does for a role when it is inside Cairn.app: flip the
 * app's toggle, open the app's sheet, or both. A browser tab has no app
 * to ask and gets `start.app` and `start.cli` instead.
 */
export type InApp = {
  role?: AppRole;
  open?: { sheet: AppSheet; label: string };
};

export type Pay = "paid" | "bonded" | "unpaid" | "pays";

export type RoleInfo = {
  id: RoleId;
  title: string;
  /** One line: what you are doing for the network. */
  does: string;
  pay: Pay;
  /** How the money moves, in the log's terms. */
  payDetail: string;
  /** What it costs or risks. */
  risk: string;
  /** The `CAIRN_ROLES` name a node declares for this, if any. */
  declares: "coordinator" | "executor" | "verifier" | "relay" | null;
  start: {
    /** Where it is in Cairn.app, for a browser tab that cannot press it. */
    app?: string;
    cli?: string;
    page?: { href: string; label: string };
    /** The button(s) this page shows inside Cairn.app. */
    inApp?: InApp;
  };
};

export const ROLES: RoleInfo[] = [
  {
    id: "experimenter",
    title: "Solve challenges",
    does: "Find answers to open objectives — by hand, with a program, or with an agent.",
    pay: "paid",
    payDetail:
      "The bounty when the pinned checker accepts your answer; on a ratchet, a share in proportion to how far you moved the best score. A copy of someone else's answer earns nothing.",
    risk: "Your time. Scoring a candidate first is free and uses the same checker.",
    declares: null,
    start: {
      app: "Node ▸ Connect an Agent…",
      cli: "cairn try <objective> --submitter <you> --artifact answer.json",
      page: { href: "/objectives", label: "Open objectives" },
      inApp: { open: { sheet: "agents", label: "Connect an agent…" } },
    },
  },
  {
    id: "compute",
    title: "Offer compute",
    does: "Put machines to work on an objective: each takes its own slice and runs a solver you supply.",
    pay: "paid",
    payDetail:
      "For what the machines find, exactly as a solver is: per accepted answer, or per new unit on a divided search. Idle time is not paid, because nothing in the log can show it was spent.",
    risk: "Power and wear. A machine that finds nothing earns nothing.",
    declares: "executor",
    start: {
      app: "Node ▸ Work on This Mac…; Settings ▸ Roles ▸ Worker host for other machines",
      cli: "cairn work --node <url> --objective <id> --worker <name> -- ./solver",
      inApp: { role: "worker-host", open: { sheet: "work", label: "Work on this Mac…" } },
    },
  },
  {
    id: "validator",
    title: "Check answers",
    does: "Re-run each claim's checker on your own machine and sign what it said.",
    pay: "bonded",
    payDetail:
      "Not paid yet. Each check stakes 50,000 units, returned after six epochs; a check shown wrong loses it to whoever caught it. Paying correct checks is held back until a check cannot simply copy the verdict the node already published.",
    risk: "50,000 units per check while it is open, lost if it was wrong.",
    declares: "verifier",
    start: {
      app: "Settings ▸ Roles ▸ Validator",
      cli: "cairn run --attest-identity validator.identity.json",
      inApp: { role: "validator" },
    },
  },
  {
    id: "relay",
    title: "Relay and seed",
    does: "Accept connections from other nodes and serve them the log, so the network stays connected.",
    pay: "unpaid",
    payDetail:
      "Not paid. Nothing in the log can show a relay served anyone. Keeping a copy of a log can be paid from an availability pool on that log, but those records do not travel between nodes yet.",
    risk: "Bandwidth, and a port open to the internet.",
    declares: "relay",
    start: {
      app: "Settings ▸ Roles ▸ Relay",
      cli: "cairn run --listen 0.0.0.0:9000",
      inApp: { role: "relay" },
    },
  },
  {
    id: "funder",
    title: "Fund a question",
    does: "Post an objective with a pinned checker and a bounty.",
    pay: "pays",
    payDetail:
      "You pay: the whole bounty is set aside when it is posted and goes to whoever the checker accepts. It cannot be changed afterwards.",
    risk: "The bounty.",
    declares: "coordinator",
    start: { page: { href: "/submit", label: "Post a challenge" } },
  },
];

/**
 * The `CAIRN_ROLES` name a node declares once an app role is on, so the
 * page can read "on here" from `GET /network` rather than from a setting
 * it cannot see. The same mapping as `NodeSettings.declaredRoles`.
 */
export const DECLARED_BY_ROLE: Record<AppRole, "executor" | "verifier" | "relay"> = {
  "worker-host": "executor",
  validator: "verifier",
  relay: "relay",
};

/** What the toggle button says, by what the node declares now. */
export const ROLE_TOGGLE: Record<AppRole, { on: string; off: string }> = {
  validator: { on: "Stop checking", off: "Check answers here" },
  relay: { on: "Stop relaying", off: "Relay here" },
  "worker-host": { on: "Stop sharing", off: "Share on my network" },
};

/**
 * Ask Cairn.app to turn a role on or off. Resolves once the person has
 * confirmed and the node is restarting -- the app reloads this page when
 * it is back -- and throws the app's own reason otherwise, including
 * "Cancelled." when they declined.
 */
export async function setRole(bridge: Bridge, role: AppRole, on: boolean): Promise<void> {
  try {
    await bridge.postMessage({ kind: "set-role", role, on } satisfies RoleRequest);
  } catch (cause) {
    throw new Error(cause instanceof Error ? cause.message : String(cause));
  }
}

/** Ask Cairn.app to open one of its sheets, on an objective when given. */
export async function openSheet(bridge: Bridge, sheet: AppSheet, objective?: string): Promise<void> {
  const request: OpenRequest = objective ? { kind: "open", sheet, objective } : { kind: "open", sheet };
  try {
    await bridge.postMessage(request);
  } catch (cause) {
    throw new Error(cause instanceof Error ? cause.message : String(cause));
  }
}

export const PAY_LABEL: Record<Pay, string> = {
  paid: "Paid",
  bonded: "Bonded, not paid",
  unpaid: "Not paid",
  pays: "You pay",
};

/** What `GET /network` says about where the node's HTTP side answers. */
export type Reach = { bound: string | null; lan: boolean; urls?: string[] };

export type LanState =
  | { state: "unknown" }
  | { state: "local"; bound: string | null }
  | { state: "lan"; urls: string[] };

/**
 * Whether another machine can reach this node, and at what.
 *
 * `null` reach is a node older than the field; it is "unknown", not "local",
 * because saying a node is closed when it might be open sends an operator to
 * change a setting that was already right. A LAN-bound node whose addresses
 * could not be found falls back to the page's own origin when that is not
 * loopback -- the browser reached it there, so another machine can too.
 */
export function lanState(reach: Reach | null | undefined, pageOrigin: string): LanState {
  if (!reach) return { state: "unknown" };
  if (!reach.lan) return { state: "local", bound: reach.bound };
  const urls = [...(reach.urls ?? [])];
  if (urls.length === 0 && pageOrigin && !/\/\/(localhost|127\.|\[::1\])/.test(pageOrigin)) {
    urls.push(pageOrigin);
  }
  return { state: "lan", urls };
}

/**
 * The command a machine runs to work an objective on this node.
 *
 * A worker name is the submitter on every record, and `|` separates the
 * fields of a commitment's preimage, so the name is cleaned of it here as
 * `cairn work` would refuse it. Placeholders stay in angle brackets so a
 * copy-pasted command fails loudly in the shell rather than quietly working
 * against the wrong node.
 */
export function workCommand(options: {
  node: string;
  objective: string | null;
  worker: string;
  solver?: string;
  /** A fleet leader's `signs_as`: the machine submits under it, the leader
   *  signs and is paid, and the slice stays the machine's own name's. */
  leader?: string | null;
}): string {
  const worker = options.worker.trim().replace(/[|\s]+/g, "-") || "<your-name>";
  return [
    "cairn work",
    `  --node ${options.node || "<node-url>"}`,
    `  --objective ${options.objective || "<objective-id>"}`,
    `  --worker ${worker}`,
    ...(options.leader ? [`  --submitter ${options.leader}`] : []),
    `  -- ${options.solver?.trim() || "./your-solver"}`,
  ].join(" \\\n");
}
