# Cairn.app

A window onto a local node, and what the release's `.dmg` installs to
`/Applications` beside the `cairn` command.

Open it and it runs `cairn run`, waits for the node to serve its reader, and
shows the reader. Quit it, or close the window, and the node stops. There is
nothing else in it: every page is the node's own `/ui/`, the same one a
browser opens, so nothing is rendered twice and nothing here can disagree with
what the node says.

```sh
make mac-app                     # gui/macos-app/build/Cairn.app, this Mac's architecture
gui/macos-app/build.sh --universal   # both slices, as release.yml builds it
```

Like `gui/macos`, it is a SwiftPM executable wrapped into a bundle by
`build.sh`, so it builds with the Command Line Tools alone. The icon is the
autoresearcher's, rendered from the same `render-icon.swift`.

## What it runs

The `cairn` at, in order: `$CAIRN_BINARY`, `/usr/local/cairn/bin/cairn`
(where the installer puts it), `/opt/homebrew/bin/cairn`,
`/usr/local/bin/cairn`. Not `$PATH`, which Finder gives an app almost none of,
and not `~/.local/bin`, where the install script leaves the copy most likely
to be stale. Never anything inside the bundle: the app's own executable is
`Cairn`, which on a case-insensitive volume is `cairn`, and a lookup there
finds the app, which starts itself, which starts itself.

A binary built without the embedded reader is refused with a message saying
so, since `cairn run` would refuse to start anyway.

To run a checkout's build, launch it with the variable set:

```sh
open --env CAIRN_BINARY="$PWD/bin/cairn" gui/macos-app/build/Cairn.app
```

## How it runs it

```
CAIRN_SANDBOX_CPUS=<cores> CAIRN_SANDBOX_MEMORY_MB=<MiB> \
cairn --data-dir <folder> --root <folder> [--max-size <n>GB] \
      run --listen 127.0.0.1:<p2p> --serve 127.0.0.1:<http>
```

- **Data** lives in `~/Library/Application Support/Cairn` unless Settings
  names another folder, because an app has no directory a person started it
  from. The node's stderr goes to `node.log` there, rewritten on each start.
- **Ports** are the command line's, 8080 and 9000, when they are free, and any
  free ports when they are not, so it runs beside a `cairn run` of your own.
  The toolbar shows which.
- **Stopping** is the node's own: the app holds the node's stdin open and
  closes it, and `cairn run` stops when stdin closes. A node that has not gone
  in three seconds gets SIGTERM, then SIGKILL. Because the pipe is the signal,
  an app that crashes or is force-quit still takes its node with it: the
  kernel closes the pipe.
- **MCP** is on, as with any `cairn run`, but unused: nothing writes requests
  to the node's stdin, so it never answers on stdout.
- **Links** to anywhere but the node open in your browser.

The **Node** menu has Open in Browser, Restart Node, Show Data Folder and Show
Node Log. If the node exits or never comes up, the window says why, with the
end of its log, a Try Again button and a way into Settings.

## Settings

⌘, or the gear in the toolbar. How much of this Mac the node's work may take,
and where it keeps its data. The work is verification: the node runs each
objective's pinned checker, one at a time, in a jail.

| setting | default | passed to the node as |
|---|---|---|
| CPU cores | all | `CAIRN_SANDBOX_CPUS` |
| Memory for each verifier | 4 GB | `CAIRN_SANDBOX_MEMORY_MB` (`0` when switched off) |
| Data folder | `~/Library/Application Support/Cairn` | `--data-dir` and `--root` |
| Storage limit | off | `--max-size <n>GB` |

The app enforces none of these itself. Each is a setting any `cairn run`
takes, enforced by the node, so the window cannot promise more than the
command line does. [configuration.md](../../docs/configuration.md) says
exactly how each one works. In short:

- **CPU**: a verifier whose processes want more cores than this is paused
  until it is back under, so it runs slower. One that runs out of time is
  `unavailable`, never `reject`.
- **Memory** covers each pinned checker's whole process tree. macOS has no
  `RLIMIT_AS`, so the node measures the tree's footprint and stops it past
  the cap. Replay commands and Lean proofs have never had a memory cap.
- **Storage**: past the limit the node evicts what it can download again. If
  the ledger alone outgrows it, the node stops and the window says so. It
  never prunes the ledger to fit.
- **GPU**: there is no setting. The node does not use the graphics
  processor, and macOS offers no way to cap one process's use of it. A
  verifier paused for CPU cannot submit GPU work while it is paused either.

A change reaches a running node when it restarts. Settings says when the
running node is still on its old settings, with a Restart Node button.

**Changing the data folder** stops the node. If the old folder holds a node
and the new one does not, you choose between copying it across, which keeps
this node's identity and ledger, and starting empty there. Copying never
deletes the old folder: the ledger is the one file that cannot be fetched
again, so removing the original is left to you once the copy has run. A folder
that already holds a node is used as it is. A chosen folder that has gone
missing, such as one on a disk that is not connected, stops the node from
starting. It is never recreated empty, which would quietly start a new node
with a new identity. The first time a folder on an external disk is used,
macOS asks whether Cairn may access files on a removable volume.

## Requirements

macOS 13 or newer, and the `cairn` command, which the `.dmg` installs with it.
