# `ui/` — a reader for the knowledge chain

A small Next.js app that reads one node's epoch chain over `GET /chain` and
draws it as a chain: each link, the link it commits to, and the claims it
settled.

**You probably do not need to run this.** It is built into the binaries and
served by the node itself at **`/ui/`** — so on a machine that installed
proofwork with `install.sh`, reading your own node's chain is a URL, not a
toolchain:

```sh
proofwork-p2p --identity id.json --root-key root.key --checkpoint cp.json \
    --listen 0.0.0.0:9000 --log proofwork.jsonl --root . --serve 0.0.0.0:8080
# then http://localhost:8080/ui/
```

To build it into the binaries from a checkout, `make ui-build` (the `ui` cargo
feature is off by default, because `cargo build` must work without Node).

To work *on* the reader:

```sh
make node          # a node to read, from the repository root
make ui            # the reader in dev mode, http://localhost:3000
```

In dev mode the page is on a different origin from the node, so point it with
`NEXT_PUBLIC_PROOFWORK_NODE=http://127.0.0.1:8080` or just edit the URL in the
page. Served from the node, the default is same-origin and there is nothing to
configure — and the URL box still retargets it, which is the whole value here:
comparing one node's head against a peer's must not need a redeploy.

## What it is for

The head is the settlement anchor. Two nodes holding the same records compute
the same head; two that have **forked** compute different ones. The head alone
tells you *that* you diverged, and comparing chains link by link tells you
*where* — which epoch first differs is the epoch that caused it. That is the
question this page exists to answer.

See [docs/design/settlement-convergence.md](../docs/design/settlement-convergence.md).

## Deliberate choices

**It never re-derives the chain.** The node folds the links; this only reads
them. A second implementation of that fold in TypeScript would be a third place
for a consensus rule to drift, and the rule already lives in two (`src/` and
`reference/rust/`, which must agree).

**It does check that what it was served is actually a chain.** `firstBrokenLink`
walks the links and reports the first whose `prev` is not the one before it.
The node says "here is a chain"; rendering that without checking would be
taking it on faith, which is the one thing this project does not do anywhere
else. A break is shown in red and the head is called untrustworthy.

**No webfont, no CDN, no external request of any kind.** An operator reads this
over an SSH tunnel on a box with no route out. Same reason the server-rendered
page is self-contained.

**A static export, and the objection that used to be here does not apply.** The
old note said `output: "export"` would bake a chain in at build time — "a
snapshot pretending to be a reader". That is true of a *server* component that
fetches during the build. Every page here is `"use client"` and fetches in
`useEffect` against a URL the page lets you edit, so the export contains no
chain, no head and no objective. It is the reader, shipped as files rather than
as a Node process — which is what lets the daemon carry it.

## There are still two of these, on purpose

`proofwork-serve` also renders the chain itself at **`GET /chain.html`**: one
self-contained 3.7 KB page written in Rust, no build step of any kind. It is
what `serve-smoke.sh` tests, and it is what a binary built *without* the `ui`
feature has — `/ui/` then 404s with a message that says so, rather than a
generic one.

This app is the richer client: three pages, a URL you can retarget, and the
consistency check below. It used to need a Node toolchain at *run* time, which a
node operator should not have to install to look at their own chain. Now the
toolchain is needed only to *build* it, once, in CI — `release.yml` has a job
that exports it and every release tarball carries the result.

## If the page renders unstyled

Correct content, serif font, unreadable dark-on-dark, nav links run together:
that is a **stale `.next`**, not a code fault. It happens when `npm run build`
runs while `npm run dev` is running — they share the directory, and the
production build replaces the dev server's stylesheet with one it cannot use.
The tell is that `app/globals.css` is intact on disk while the served
`/_next/static/css/app/layout.css` is a few bytes.

```sh
rm -rf .next && npm run dev
```

Worth knowing because the symptom looks like broken CSS and sends you reading
the stylesheet, which is fine. Stop the dev server before running a build.
