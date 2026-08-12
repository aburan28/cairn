# `ui/` — a reader for the knowledge chain

A small Next.js app that reads one node's epoch chain over `GET /chain` and
draws it as a chain: each link, the link it commits to, and the claims it
settled.

```sh
# a node to read (from the repository root)
make serve

# the reader
cd ui && npm install && npm run dev     # http://localhost:3000
```

Point it elsewhere with `NEXT_PUBLIC_PROOFWORK_NODE`, or just edit the URL in
the page — the whole value of this is comparing one node's head against a
peer's, so switching nodes must not need a redeploy.

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

**Not a static export.** `output: "export"` would bake a chain in at build time
— a snapshot pretending to be a reader.

## There are two of these, on purpose

`proofwork-serve` also renders the chain itself at **`GET /chain.html`**: one
self-contained 3.7 KB page, no Node.js, no build step, nothing to install. That
is the one to use on a server, and it is what `serve-smoke.sh` tests.

This app is the richer client — a URL you can retarget, a visual spine, the
consistency check. It needs a Node toolchain, which a node operator should not
be required to have just to look at their own chain. Hence both.
