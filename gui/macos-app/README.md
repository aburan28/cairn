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
cairn --data-dir ~/Library/Application\ Support/Cairn \
      --root     ~/Library/Application\ Support/Cairn \
      run --listen 127.0.0.1:<p2p> --serve 127.0.0.1:<http>
```

- **Data** lives in `~/Library/Application Support/Cairn`, because an app has
  no directory a person started it from. The node's stderr goes to
  `node.log` there, rewritten on each start.
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
end of its log and a Try Again button.

## Requirements

macOS 13 or newer, and the `cairn` command, which the `.dmg` installs with it.
