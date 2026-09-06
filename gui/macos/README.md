# Cairn Autoresearcher for macOS

A native launcher around `research/crypto-autoresearcher/`: one window that
starts the researcher, watches it work, and shows the node it runs.

```sh
make autoresearch-gui            # gui/macos/build/Cairn Autoresearcher.app
open "gui/macos/build/Cairn Autoresearcher.app"
```

It is a SwiftPM executable wrapped into an `.app` by `build.sh`, so it builds
with the Command Line Tools alone; Xcode is not needed. The bundle is ad-hoc
signed, which is what a locally built app needs to launch and all it needs
when it is never distributed.

## What it does

* **Start / One sweep / Stop** run `autoresearcher.py`, which posts the
  objectives in `objectives.txt`, starts `cairn run` over the researcher's own
  log (MCP on stdio, HTTP, P2P, the reader), and works every objective: solved
  and settled, declined with a reason, or out of repertoire. Stop sends
  SIGTERM; the researcher closes the node's stdin, which stops the node. Quitting
  the app does the same, so nothing is left holding the port or the log's lock.
* **Build** runs `make ui-build`, the build `cairn run` requires (the binary
  must carry the embedded reader).
* **Overview** counts solved, declined and open objectives, what was earned
  and the identity's spendable balance, from `status.json`, which the
  researcher rewrites on every change.
* **Objectives** is that file as a table, with each objective's outcome and
  the reason it was declined when it was.
* **Journal** tails `journal.jsonl` live.
* **Console** is the process's own stdout and stderr.
* **Node reader** embeds the node's `/ui/`, `/chain.html` and `/objectives`
  over loopback -- the same pages a browser would show, reading the same node.

Settings (⌘,) hold the checkout path, the two listen addresses, the epoch
length, the per-objective compute budget and the sweep interval. They are
passed to the researcher as the environment variables its header documents,
so what the app runs is exactly what `run.sh` runs from a terminal.

The checkout is guessed by walking up from the bundle's own location, so an
app built by `make autoresearch-gui` opens on the repository it was built in.

## Requirements

macOS 13 or newer, Python 3, a C compiler (the solvers are compiled on first
use into `.autoresearcher/`), and Node for the one-time `make ui-build`.
