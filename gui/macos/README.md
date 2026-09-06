# Cairn Autoresearcher for macOS

A native control surface for `research/crypto-autoresearcher/`: choose what
to post, run the researcher, watch it work, read the node it runs, and act on
the outcomes.

```sh
make autoresearch-gui            # gui/macos/build/Cairn Autoresearcher.app
open "gui/macos/build/Cairn Autoresearcher.app"
```

It is a SwiftPM executable wrapped into an `.app` by `build.sh`, so it builds
with the Command Line Tools alone; Xcode is not needed. The icon is rendered
from `Resources/render-icon.swift` at build time, and the bundle is ad-hoc
signed, which is what a locally built app needs to launch and all it needs
when it is never distributed.

## Panes

**Overview.** Setup checks (checkout, Python, C compiler, a `cairn` binary
that carries the embedded reader, Node for the one-time build), an activity
card with the running engine's own progress line and elapsed time, tiles for
solved / declined / open / earned / spendable, an earnings chart in settlement
order, the accepted claims, and the researcher's state.

**Objectives.** Every objective the researcher has seen, filterable by outcome
and searchable by goal, id or reason. Selecting one shows its outcome
(strategy, solve time, claim, verdict, settlement), the statement as the node
serves it (flagged as untrusted text), the frontier, and the artifact that was
submitted. Actions: **Retry on next sweep** forgets a declined outcome so the
next sweep looks again (while stopped, since the researcher owns its state
file while it runs); **Score a file…** runs the objective's pinned verifier on
an artifact JSON of your own through `cairn propose --dry-run`, recording
nothing; **Open in reader** jumps to the node's page for it. The context menu
copies ids.

**Catalog.** Every `examples/**/objective*.json` in the checkout, grouped by
family, with a checkbox each. The checked set is what the researcher posts at
the next Start; *Researcher default* restores the crypto set it ships with.
Objectives the log already holds are marked *posted* and left alone on a
re-post, which is refused by id.

**Node.** Health, ledger height, epoch links, peers and objective count from
the node's routes; balances for every holder from `cairn balances`; records by
kind; and the node's own reader, chain page, objectives JSON and log JSON in an
embedded web view.

**Journal.** Every event the researcher records, live, colour-coded by kind,
filterable, with an *Outcomes only* switch and follow-tail.

**Console.** The process's own stdout and stderr.

**Settings** (⌘,) hold the checkout, the two listen addresses, the epoch
length, the per-objective compute budget, the sweep interval, settlement
notifications, and **Reset state**, which deletes the researcher's log, node
keys and outcomes and by default keeps the identity, since that is the name
payments went to.

## How it runs the researcher

Start and One sweep run `autoresearcher.py` with the settings as the
environment variables its header documents, so what the app runs is exactly
what `run.sh` runs from a terminal. The researcher starts `cairn run` over its
own log; Stop sends SIGTERM, the researcher closes the node's stdin, and the
node exits. Quitting the app does the same, so nothing is left holding the
port or the log's lock. Build runs `make ui-build`, the build `cairn run`
requires.

Everything the app shows comes from files the researcher writes
(`status.json`, `progress.json`, `journal.jsonl`) and from the node's HTTP
routes; the app never touches the ledger itself.

## Requirements

macOS 13 or newer, Python 3, a C compiler (the solvers are compiled on first
use into `.autoresearcher/`), and Node for the one-time `make ui-build`.

On an external volume, the first launch from Finder may wait on macOS's
"access files on a removable volume" consent before the window appears; allow
it once.
