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
`build.sh`, so it builds with the Command Line Tools alone. The icon is
`packaging/macos/icon/AppIcon.icns`, drawn by `make-icon.py` beside it.

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
      [--bootstrap <file> ...] \
      run --listen <p2p-host>:<p2p> --serve 127.0.0.1:<http>
```

- **Data** lives in `~/Library/Application Support/Cairn` unless Settings
  names another folder, because an app has no directory a person started it
  from. The node's stderr goes to `node.log` there, rewritten on each start;
  the run before it is kept as `node.previous.log`, so a failed start's log
  survives Try Again.
- **Ports** are the command line's, 8080 and 9000, when they are free, and any
  free ports when they are not, so it runs beside a `cairn run` of your own.
  The status button in the toolbar shows which.
- **P2P** listens on loopback by default: the node dials out and nothing
  dials in, which is enough to sync from a bootstrap peer, a compiled-in
  seed (`launch/seeds.json`), or a LAN beacon, and not enough to be one.
  Settings can bind `0.0.0.0` instead, and the toolbar's status button says
  which. The HTTP reader stays on loopback either way — this window is for
  you, not for the network. A seed that does not answer is named in
  `node.log` once a minute. Launching with `open --env CAIRN_SEEDS=<file>`
  points the node at another list and `CAIRN_SEEDS=off` at none.
- **Bootstrap** files are optional dial hints, chosen in Settings. Without
  one the node finds peers on the local segment and any seeds the `cairn`
  binary itself dials. A missing file refuses to start rather than leaving
  a silent gap. Generate writes a placeholder key via `cairn gen-bootstrap`;
  the node warns until the peer's real key replaces it.
- **Stopping** is the node's own: the app holds the node's stdin open and
  closes it, and `cairn run` stops when stdin closes. A node that has not gone
  in three seconds gets SIGTERM, then SIGKILL. Because the pipe is the signal,
  an app that crashes or is force-quit still takes its node with it: the
  kernel closes the pipe.
- **MCP** is on, as with any `cairn run`, but unused: nothing writes requests
  to the node's stdin, so it never answers on stdout.
- **Links** to anywhere but the node open in your browser.

The **Node** menu has Open in Browser, Restart / Reconnect, **New
Challenge…** (⇧⌘N, [below](#new-challenge)), **Tasks…**,
**Secrets…**, Peers…, **Test Connectivity…** (⇧⌘K, below), Copy Peer Id,
Show Data Folder and Show Node Log.
**Tasks…** posts a curated objective (including ECC2K-130 orbit piecework)
into this node's log in one click, and its **Show progress…** opens the
reader's Objectives page, where every divided search links to its
dashboard (`/ui/task?id=…`): the orbits the log has paid each worker for,
beside what the workers report they are walking right now. The objectives and the checkers they pin
ship inside the app, copied from `examples/` by `build.sh`, which also fails
if a checker no longer matches its pin; posting puts the checker under the
node's data folder first, so the node can run it and serve it to peers.
Launch with `CAIRN_REPO=<checkout>` to post a checkout's edited copies
instead. **Secrets…** pastes named
operator credentials (AWS keys, `DATABASE_URL`, …) into `~/.cairn/secrets`
via `cairn secret set --stdin` — values are never shown again after Save,
and never go on the command line. **Peers…** announces a peer in the log
(stopping the node briefly — a ledger has one writer), points at bootstrap
management in Settings, and copies what to hand someone adding this node.
The status button in the toolbar says, in a word or two, whether
the node is on this Mac only, attached to another node's URL, or has reached
peers. Its popover has the reader and P2P addresses, the peer id and the
session count, each with a copy button, and **Test…**.

**Test Connectivity…** (⇧⌘K, or **Test…** in that popover) checks the ports
themselves rather than reading a status word, each attempt made now from
this Mac:

- **Reader**: an HTTP request to the page this window shows.
- **P2P listener**: a TCP connect to the port the node said it bound. When
  Settings accepts inbound, also to that port on each of this Mac's LAN
  addresses, with whether the macOS firewall is on (it asks once per program
  whether to accept incoming connections, and a denied answer looks from
  outside exactly like a closed port). It also prints the `nc -vz <address>
  <port>` to run from another machine, which is the one direction a Mac
  cannot test for itself.
- **Peers it dials**: a TCP connect to every bootstrap file's address and to
  every seed the node's log names, beside what that log says about the
  handshake. A port that answers proves a listener, not a cairn node holding
  the key its id names; only the handshake proves that, and only the node
  runs it.
- **Sessions**: how many peer sessions the log reports.

Each attempt is told apart: *refused* (the host answered and nothing listens
there), *no answer* (the host is down or a firewall drops the connection),
or a name that does not resolve. **Copy Report** puts the lot on the
clipboard. The Peers sheet's address field has its own **Test**, so an
address can be checked before it is vouched for in the log.

The page itself is the node's `/ui/`, which recognises this window by the
`CairnApp` its web view appends to the user agent and drops the public site's
pitch and footer: here the sidebar is the only navigation, and the page opens
on the node's numbers.

## Updates

**Cairn → Check for Updates…**, and a check once a day, both by
[Sparkle](https://sparkle-project.org). The feed is `appcast.xml` on the fixed
GitHub release tagged `updates`, which `release.yml` rewrites once a release's
.dmg is up (so a check made while a new release is still building reads the
previous feed and says "up to date", rather than the 404 `releases/latest`
gives in that window); an update is the newest release's .dmg, verified against two keys
built into the app -- Sparkle's Ed25519 over the image, and the app's own
post-quantum ML-DSA-87 over the feed item, checked before anything is
downloaded (`Sources/Cairn/UpdateSignature.swift`) -- and installed by its
own `Install Cairn.pkg` after an administrator password. The installer replaces the `cairn` command
and this app together and opens the app again. Settings has the automatic
check's switch and a Check Now button.

The app's version is under the window title. The toolbar's status popover,
About Cairn and Settings also show the `cairn` command's version, from
`cairn --version`, and the popover warns when the two differ.

A build without both keys in its Info.plist (`SUPublicEDKey` and
`CairnMLDSA87PublicKey`), such as one from `build.sh`, cannot verify an
update, so it never starts Sparkle and the menu item says so, naming the
installer rather than opening a web page. [packaging/README.md](../../packaging/README.md#updates-for-cairnapp)
has the release side and the one secret it needs.

## New challenge

**Node → New Challenge…**, or the sparkles in the toolbar: describe a problem
in plain words, set a reward, and post a challenge without meeting the
objective schema.

The reader's **Post a challenge** page leads to the same place. In this
window the page is one text box: **Draft challenge** hands the description to
the sheet through a script message handler (`PageBridge` in `WebView.swift`,
`ui/lib/draft.ts` on the page's side), and the sheet starts drafting at once
when a key is saved, or as soon as one is pasted. The full form is still
there behind *Fill in every field by hand*, for a scaffolded `objective.json`
or a wallet signature. The handler answers only the top frame of the node
this app runs, so attach mode refuses it and says why on the page.

1. A model you have a key for drafts the parts that need judgment: the
   statement solvers read, the answer's shape, a Python checker, a correct
   answer when it knows one, and a plausible wrong one.
2. The app adds the parts that need none. It writes the checker under the
   node's data folder (`challenges/<goal>-<hash>/checker.py`), pins it by its
   SHA-256, caps it at 60 seconds, and writes `objective.json` beside it.
3. It **tests the checker through the node's own verifier**, in the same
   jail settlement uses. It posts the draft into a throwaway log and runs
   `cairn propose --dry-run` on both answers; the real log is never touched.
   **Post Challenge** stays disabled until the wrong answer is rejected and
   the right one, if there is one, accepted. The review shows both verdicts
   and the checker's code, because that code decides who gets paid.
4. **Redraft** sends the earlier attempt back with whatever failed and
   whatever you typed in *What should change?*.

The statement, goal, reward and funder can be edited in review; the checker
cannot, so what was tested is what is posted. The funder is a name shown on
the bounty, `treasury` by default, unsigned.

**Keys.** The first time, the sheet asks for one inline; **Settings → AI**
chooses the provider and model, tests the key, and removes it.

**Models.** Once a key is saved, Settings asks the provider what it serves
(`GET /models`, with the key, so an account sees its own deployments) and
lists the answer in a menu beside the model field. Typing narrows the menu.
A model the provider does not list -- a default that has been renamed, or a
typo -- is said so on the spot, with the nearest served id offered as a
one-click fix, rather than failing when a draft is first asked for. The
field still takes any id, for a model the list is behind on.

| provider | default model | key saved as |
|---|---|---|
| Claude (Anthropic) | `claude-opus-5-5` | `ANTHROPIC_API_KEY` |
| OpenAI | `gpt-6.1-sol` | `OPENAI_API_KEY` |
| Fireworks AI | `accounts/fireworks/models/kimi-k3` | `FIREWORKS_API_KEY` |
| OpenCode Zen | `kimi-k3` (Claude models also work; GPT models need Zen's Responses API, which this app does not speak) | `OPENCODE_API_KEY` |
| OpenRouter | `moonshotai/kimi-k3` | `OPENROUTER_API_KEY` |
| Other (OpenAI-compatible) | — | `CAIRN_AI_API_KEY` |

Keys go into `~/.cairn/secrets` with `cairn secret set --stdin`, beside
every other credential this app handles, so they also show in **Secrets…**.
They are kept under the names each provider's own tools read, so a terminal
agent can be handed the same key (`cairn secret run --env ANTHROPIC_API_KEY
-- claude`). They are readable by your user only and **not encrypted on
disk**. The node never sees them: the node has no TLS by design
(`tests/cipher_policy.rs`), so the app makes the request. On Claude's own API
the request opts into server-side refusal fallbacks (`fallbacks: "default"`).
What this does and does not protect is in
[docs/threat-model.md](../../docs/threat-model.md#agents-as-authors).

## Settings

⌘, or the gear in the toolbar. How much of this Mac the node's work may take,
and where it keeps its data. The work is verification: the node runs each
objective's pinned checker, one at a time, in a jail.

| setting | default | passed to the node as |
|---|---|---|
| Attach to URL | off (run a local node) | — (no process; window loads the URL) |
| CPU cores | all | `CAIRN_SANDBOX_CPUS` |
| Memory for each verifier | 4 GB | `CAIRN_SANDBOX_MEMORY_MB` (`0` when switched off) |
| P2P listen | this Mac only (`127.0.0.1`) | `--listen <host>:<port>` |
| Bootstrap files | none | `--bootstrap <file>` (repeatable) |
| Data folder | `~/Library/Application Support/Cairn` | `--data-dir` and `--root` |
| Storage limit | off | `--max-size <n>GB` |
| AI provider, model and key | Claude, `claude-opus-5-5`, no key | — (the app's own; see [New challenge](#new-challenge)) |

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
- **P2P listen**: loopback means dial-out only. `0.0.0.0` accepts inbound on
  every interface; the address you hand someone else is this Mac's LAN or
  public address, written into *their* bootstrap file, never into the listen
  field (a cloud public IP is not on any local interface and will not bind).
- **Bootstrap**: each file is an address plus a transport key. The handshake
  authenticates the key, so a wrong file costs a dial and never a wrong
  result. Generate writes a placeholder; replace the key before expecting a
  session.
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
