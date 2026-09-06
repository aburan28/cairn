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

The activity card counts down to the next sweep against the time the
researcher itself published, shows how far through the objective list the
current pass is, and offers **Sweep now**, which cuts the wait short. The
outcome tiles are buttons: each opens the Objectives list filtered to the
rows it counted. **Declined, and why** groups the declines by who made them
-- *out of the repertoire*, meaning nobody has written a strategy, against
*over budget*, meaning the estimate exceeded the compute budget and a larger
one would change the answer -- with the pool each group left on the table.

**Objectives.** Every objective the researcher has seen, filterable by outcome
and searchable by goal, id or reason, sortable by any column and sorted by
reward first, since that is the order an operator reads them in. Selecting one shows its outcome
(strategy, solve time, claim, verdict, settlement, and for a commitment when
its reveal opens), the statement as the node serves it (flagged as untrusted
text), the frontier, and the artifact that was submitted. Actions: **Solve
this one** runs a sweep restricted to that objective -- node up, one
decision, node down; **Retry on next sweep** forgets a declined outcome
(while stopped, since the researcher owns its state file while it runs);
**Journal** filters the journal to that objective; **Score a file…** runs the
objective's pinned verifier on an artifact JSON of your own through
`cairn propose --dry-run`, recording nothing; **Open in reader** jumps to the
node's page for it. The context menu copies ids.

**Catalog.** Every `examples/**/objective*.json` in the checkout, grouped by
family, with a checkbox each and the researcher's own verdict under it,
computed by `autoresearcher.py --plan` at the current budget and recomputed
when the budget changes: *would solve it, about 15s*, *declines: 131-bit
field…*, or *no strategy in the repertoire*. *Solvable only* filters to the
first kind; the Select menu can check exactly those. The checked set is what
the researcher posts at the next Start, or **Post now** appends the unposted
ones with the CLI while no node holds the log. Objectives the log already
holds are marked *posted* and left alone on a re-post, which is refused by
id.

**Node.** Health, the current epoch with a countdown to the next, ledger
height, epoch links, peers and objective count from the node's routes;
balances for every holder from `cairn balances`; the identity's public key
with copy and reveal; records by kind; then a native **Ledger** table of
every entry, a **Peers** table, and the node's own reader, chain page,
objectives JSON and log JSON in an embedded web view. **Audit log** runs
`cairn audit` and shows whether every settled claim re-verifies.

**Add peer…** covers both halves of adding one, because the network has two
and they answer different questions. *Announce in the log* appends a peer
record with `cairn peer` -- this identity vouching that a transport id is
reachable at an address -- so every node that replicates the log learns the
peer from it; it needs the node stopped, since a ledger has one writer.
*Bootstrap file* is the local configuration this node reads at start, holding
the peer's real transport key, which is too large to keep in a log; files can
be chosen or generated with `cairn gen-bootstrap`, and a generated one keeps
its placeholder key until the peer's real one replaces it. *This node* reads
off the transport id and address to give somebody adding this node, and says
so when the address is loopback and therefore reaches nobody else.

Neither half is a trust decision, and the sheet says so: a transport id is
`sha256` of the key the handshake proves, so an entry naming the wrong id
gets no session. A wrong peer costs a dial, never a wrong result.

**Journal.** Every event the researcher records, live, colour-coded by kind,
filterable, with an *Outcomes only* switch and follow-tail. A row about an
objective links to it; the context menu narrows the journal to one objective.

**Overview** also lists commitments waiting for the epoch to turn, with the
seconds until their reveal opens, and the toolbar shows the current epoch.
The Dock icon carries the count of open objectives while a run is on.

**Console.** The process's own stdout and stderr.

**Settings** (⌘,) hold the checkout, the two listen addresses, the epoch
length, the bootstrap files, the per-objective compute budget, the sweep
interval, settlement notifications, the menu bar item, and **Reset state**,
which deletes the researcher's log, node keys and outcomes and by default
keeps the identity, since that is the name payments went to.

A **menu bar item** carries the phase, the counts and Start / Stop / Sweep
now without the window. ⌘1 to ⌘6 walk the panes.

## How it runs the researcher

Start and One sweep run `autoresearcher.py` with the settings as the
environment variables its header documents, so what the app runs is exactly
what `run.sh` runs from a terminal. **Sweep now** sends the running
researcher `SIGUSR1`, which ends its idle wait early; that needs no socket
and nothing listening, and during a sweep it is noted and dropped.

A researcher started **outside** the app -- `run.sh` from a terminal -- is
shown the same way, found by testing whether the pid in `status.json` is
alive. The app watches it and never stops it: whoever started it owns it, so
Start, Stop and everything that writes the log stay disabled while it runs. The researcher starts `cairn run` over its
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
