# Review: the four readers

October 2026. A pass over every surface a person looks at a cairn node
through -- the web reader a node embeds at `/ui/` (which is also the public
site), Cairn.app, Cairn Autoresearcher.app and the iPhone reader -- read as one
system rather than four programs: what each one shows, which of the node's
facts none of them could, and what the node would have to publish for them to.
Written with the node's routes open beside the pages, and against the
constraint the readers share, that **nothing on them is simulated**: every
number is the node's or the shipped log's, labelled as which.

The short version. The readers are unusually honest and unusually consistent
-- one stylesheet, one provenance convention, one "the node decides" rule, no
external request anywhere -- and they were all blind in the same four places,
because the node published nothing there: whom it had reached, what hardware
was working for it, who was about to work what, and what it was for. Those
four landed with this review as four routes and two pages (§3). What remains
is mostly in Swift, which this environment cannot compile, and is named file
by file in §4 so it is a change and not a wish. One structural finding (§2.5)
is about the two macOS apps rather than about any page.

## 1. What is there

| surface | where | runs a node? | reads | writes |
|---|---|---|---|---|
| **the web reader** | `ui/`, Next.js, static export; served by the node at `/ui/` and by GitHub Pages | no | `/objectives`, `/objective/{id}`, `/frontier/{id}`, `/progress/{id}`, `/chain`, `/checkpoint`, `/log`, `/peers`, `/health`, and now `/sessions`, `/network`, `/work_assignment`, `/leases/{id}` | `POST /submit` (an objective, wallet-signed), `POST /objective/prepare`; in Cairn.app's window, hands a draft to the New Challenge sheet |
| **Cairn.app** | `gui/macos-app/`, SwiftPM, a `WKWebView` on the node's `/ui/` | **yes**: starts `cairn run`, holds its stdin, stops it | the same pages; `GET /verifiers` in Settings; `cairn --version`; `node.log` lines for the peer id, listen address and session count | `cairn peer` (announce), `cairn secret set`, `cairn identity`, `cairn gen-bootstrap`, `cairn propose --dry-run` and the real log for a drafted Lean challenge, the MCP stanza for an agent |
| **Cairn Autoresearcher.app** | `gui/macos/`, SwiftPM; a control surface for `research/crypto-autoresearcher/` | runs the researcher, which runs a node | the researcher's `status.json`, `progress.json`, `journal.jsonl`; the node's `/chain`, `/peers`, `/objectives`; `cairn balances`, `cairn audit` | starts and stops the researcher; `cairn peer`; `cairn secret set`; posts curated objectives with the CLI |
| **the iPhone reader** | `gui/ios/`, SwiftUI; `CairnKit` is the decoder and chain check | no, by design (a phone that settled would be a third implementation) | `/objectives`, `/progress/{id}`, `/chain`, `/log`, `/peers`, `/checkpoint`; the launch snapshot when no node answers | nothing |

Four readers, one HTTP surface. That is the right shape and it is the reason
the fix for every finding below is a route before it is a view: a fact the
node publishes once reaches four screens, and a fact it does not publish
reaches none however good the screens are.

## 2. Findings, most important first

### 2.1 No reader could show whom a node was talking to -- landed

`docs/serving.md` said, from the day the HTTP half existed, that *live
session state lives in the p2p service, which serves no HTTP*. So every
reader rendered `GET /peers` -- the log's `peer` records, which are
announcements, append-only and never retracted -- under a disclaimer that it
was not a list of connections. The web page said it in a tooltip and a note;
the phone's `PeersView` opened with the sentence; the autoresearcher's Node
pane labelled its table "log announcements, not live sessions"; and
Cairn.app's status button said "reached peers" from a count of `node.log`
lines containing `session: … ok` (`Node.absorbLog`, `sessionsOK`), which is
the daemon's own stderr parsed back as text. Four readers, one disclaimer,
and the operator who wanted to know whether their node was talking to anyone
read a log file in a terminal.

The daemon knew. It logged every session at four places. It now also writes
them into a roster its HTTP half shares (`src/p2p/sessions.rs`), and
`GET /sessions` answers whom this process has reached, as a window rather than
a socket -- `reached` within two minutes, `recent` within thirty, `lost`
after, `unreached` for a peer only ever dialled and never answered -- with the
address book's sizes and this node's own id, listen address and uptime beside
it. The web reader's Network page draws it (§3). The three native readers do
not yet (§4).

### 2.2 No reader summed the fleet -- landed

Every heartbeat carried `device`, `lanes`, `client` and a rate, and the task
dashboard showed them per objective -- which is the right place for *that*
page. Nothing answered "how much compute is on this network right now, and of
what kind" shorter than opening every task page and adding. `GET /network`
now sums the heartbeat roster across objectives by device, by a device class
the node computes once (`progress::device_class`, so the four readers sum the
same way rather than each inventing a regex) and by objective, over live
workers only, beside the node's own machine probed at startup. The Network
page's compute tiles are those sums, in amber, labelled reported.

### 2.3 Coordination was invisible, and the lab's leases were out of a worker's reach -- landed

The reader could show what a divided search had settled and what workers
reported (`/task`), and nothing about *how it was being divided*: which
epoch, which slice each worker held, which slices nobody held, where two
workers overlapped. `work_assignment` is a pure function anyone can evaluate,
so this was purely a display gap -- and underneath it a real one: the lab had
an advisory lease (`claim`/`release`, `held`/`contended`) for agents sharing a
space, and a worker on a GPU box with nothing but an HTTP address had no way
to say "I am on unit 4,017" to anyone.

`POST /lease`, `POST /lease/release` and `GET /leases/{id}` are that lease
for workers, node-local like a heartbeat and in the lab's vocabulary, and the
Coordination page draws the epoch, the unit space in a reader-chosen number of
partitions coloured by who reports holding each, the leases over it, and the
workers reporting. **A lease is not a lock** -- nothing that pays reads one,
`work_assignment` does not consult it -- and both the route's payload and the
page say so in those words. `docs/design/network-coordination.md` §3 is the
argument for why that must stay true.

### 2.4 Roles existed only in the research program -- landed as a hint

The autoresearcher runs on a coordinator, executors and validators with
enforced authority (`orchestration/roles.yaml`). A cairn node had no way to
say which its operator meant it for, and a reader had no way to tell a node
that funds objectives from one that only holds the log. `CAIRN_ROLES` now
declares `coordinator`, `executor`, `verifier` or `relay`; `GET /network`
publishes the declaration beside the node's own warnings where the
configuration contradicts it, and beside the roles the log *evidences*:
funders, submitters of accepted claims, attestors. The declaration is a hint
about intent and never a permission; a node of strangers has no harness to
enforce one, and the only authority on it is a pinned verifier's verdict. The
page shows the three columns as the three checks a reader can make.

### 2.5 Two macOS apps carry one app's worth of chrome twice -- not landed

`gui/macos-app/` and `gui/macos/` are two SwiftPM executables with two
`Package.swift`, two `build.sh`, two `Info.plist`, two `WebView.swift`, two
`GuiTasks.swift`, two secrets sheets (`SecretsSheet.swift`, `SecretsView.swift`),
two peer sheets (`PeersSheet.swift`, `AddPeer.swift`) and two settings
screens, each pair doing the same job against the same node with slightly
different words. The split is historical: the autoresearcher app came first
as a control surface for the Python researcher, and Cairn.app came later as
the thing the `.dmg` installs. Both READMEs say which is which, so a reader
is not confused; a maintainer is, every time a change to how the node is
started, stopped or read has to land twice. The `ConnectivitySheet` and the
Lean toolchain discovery exist only in Cairn.app; the Journal, Catalog and
Console exist only in the autoresearcher.

Recommendation: a third SwiftPM target, a library both executables depend on,
holding the node process model (`Node.swift`'s start/stop/stdin discipline,
port probing, log sink), the `WKWebView` wrapper with the `CairnApp` user
agent and the `PageBridge`, the secrets sheet, the peers sheet and the HTTP
decoders -- the same move `gui/ios/` already made with `CairnKit`. Then the
autoresearcher's five research panes become either a second window of
Cairn.app or a thin executable over the shared target. This is a refactor
with no user-visible change and it is the one item here that saves work on
every future item, which is why it is 2.5 and not 2.9.

### 2.6 Cairn.app learns about its own node by parsing its stderr -- partly landed

`Node.absorbLog` finds the peer id, the listen address and the session count
by scanning `node.log` for `peer id `, `listening on ` and `session: … ok`.
That worked and it is brittle in the two ways text parsing is: a reworded log
line silently empties the status popover, and the count never goes *down*
(sessions that fail are not subtracted, so "reached peers" is a lifetime
total). `GET /sessions` now carries `this_node.peer_id`, `this_node.listen`,
`this_node.uptime_seconds` and the windowed `reached` count. The log scrape
should stay as the fallback for the seconds before the HTTP half answers and
be replaced by the route once it does (§4.1).

### 2.7 Every reader page carries the same forty lines -- not landed

`task`, `network` and `coordination` each hold a `base` state, a
`NodePicker`, a `resolveNode()` effect, a `load(url, quiet)` callback and a
visibility-aware refresh interval with the same comments. `objectives`,
`peers`, `chain` and `log` carry the first three without the interval. That
is seven copies of one idea, and the next page will be an eighth. A
`useNodeRead(load, { refreshSeconds })` hook in `components/` -- it is React,
so it does not belong in `lib/`, whose tests are DOM-free by design -- would
make a page its data types, its render and nothing else. Not done here
because it touches seven pages for no visible change and this review already
changes the reader enough; it is the first thing to do before a ninth page.

### 2.8 The strips are mouse-only -- partly landed

The task page's coverage strip and the coordination page's partition strip
put their facts in `title` tooltips: the unit range of a cell and who holds
it are unreachable without a pointer, and unreadable to a screen reader
beyond the strip's one `aria-label`. The coordination page carries the same
facts in its tables, so nothing is lost; the task page's strip has no table
under it. A `<details>` block listing the non-empty cells would fix both and
costs no layout. Not done here; noted so it is not forgotten.

### 2.9 Smaller things, in no order

- The objectives page links a divided search to its task dashboard and not to
  its coordination page. Landed: both links, side by side.
- `/peers` is now a subpage of the Network entry in the sidebar (the address
  book is the only place the raw announcements are listed, so it stays), and
  the Network page links to it. The command palette still lists it.
- The public-site mount of `/network` and `/coordination` has no node behind
  it. `resolveNode` walks the published seeds, as every other page does, and
  when none answers the pages say "could not read" rather than showing the
  snapshot, because the snapshot has no sessions and no fleet and inventing
  either would break the readers' one rule. The task page behaves the same
  way, so this is consistent, and it is worth knowing before somebody files
  it as a bug.
- `ui/README.md` describes a Chromium-over-CDP sweep of every route at
  320–1280px that was done by hand. The two new pages were checked by the
  same three rules (`min-w-0` on cards, `anywhere` wrapping on `.mono`,
  `overflow-x-auto` on every table) rather than by the sweep, which should be
  a committed script if it is to be a check and not a memory.
- `src/compute.rs` -- the capability advertisement `docs/README.md` lists as
  **built** -- is not declared in `src/lib.rs` or `src/main.rs`, so it is not
  compiled, tested or linted; the design note that references it links to a
  path rather than an item for that reason. Either declare it or move the
  table row to "written, not wired".

## 3. What landed with this review

| where | change |
|---|---|
| `src/p2p/sessions.rs`, `src/daemon.rs` | the session roster, written at the daemon's four session sites and shared with the HTTP half; `GET /sessions` |
| `src/lease.rs`, `src/serve.rs` | advisory task leases: `POST /lease`, `POST /lease/release`, `GET /leases`, `GET /leases/{id}` |
| `src/network.rs`, `src/progress.rs`, `src/serve.rs` | `CAIRN_ROLES`, the hardware probe, `Board::fleet`, `device_class`, the roles the log evidences; `GET /network` |
| `ui/app/network/`, `ui/lib/network.ts` | the Network page: peers reached, address book, compute and lanes, this node, what a role means, sessions, hardware by class and device, the fleet, the three evidenced roles |
| `ui/app/coordination/`, `ui/lib/leases.ts` | the Coordination page: the epoch, the partition strip, leases, workers reporting; a chooser without `?id=` |
| `ui/components/Shell.tsx`, `ui/app/objectives/` | Network and Coordination in the sidebar and the palette; the objectives page links a divided search to both dashboards |
| `docs/serving.md`, `docs/configuration.md`, `docs/threat-model.md`, `docs/glossary.md` | the routes, the variable, two threat rows (lease squatting; a lying session roster), three glossary entries |
| `docs/design/network-coordination.md` | the design: three kinds of fact, why a lease is not a lock, why a role is not a permission, what is deliberately not built |
| `scripts/node-smoke.sh` | every new route answers from the one process holding the write lock; both pages are served under their paths |

Checked with `cargo test`, `cargo clippy --all-targets -- -D warnings`,
`cargo fmt --check`, `RUSTDOCFLAGS=-D warnings cargo doc`, `tsc --noEmit`,
`vitest` and `next build`, and by running a node with `CAIRN_ROLES` set and
reading the routes and pages from it.

## 4. What is still only on paper, per surface

None of this can be compiled or run from the Linux environment this review
was written in -- there is no Xcode -- and a Swift change nobody ran is worse
than a named one. Each item below names the file and the route so it is an
afternoon, not a design.

### 4.1 Cairn.app (`gui/macos-app/`)

- **`PeersSheet.swift`**: a fourth tab, *Connected*, reading `GET /sessions`
  from the reader URL the app already holds: one row per peer with status,
  age, direction, in/out counts and the last error; the `available: false`
  case says the attached node is a plain publisher. The *Announce* tab stays
  what it is.
- **`App.swift` (`NodeStatusButton`) and `Node.swift`**: replace
  `sessionsOK` with `GET /sessions` → `reached` once the HTTP half answers,
  keeping `absorbLog` as the fallback for the first seconds; take the peer id
  and listen address from `this_node` the same way. The popover's word -- "on
  this Mac only", "attached", "reached peers" -- then comes from a windowed
  count that can go down.
- **`NodeSettings.swift`, `SettingsView.swift`, `Node.childEnvironment`**: a
  *Roles* row (four checkboxes) passed to the node as `CAIRN_ROLES`, with the
  node's `warnings` from `GET /network` shown under it, so "declares verifier
  but can serve no kind" appears where the operator can fix it.
- **`App.swift` (Node menu)**: *Network…* (⇧⌘W is free) opening the reader at
  `/ui/network`, beside *Peers…*; *Tasks…* → *Show progress…* gains a second
  button for the coordination page.
- **`ConnectivitySheet.swift`**: its *Sessions* line ("how many peer sessions
  the log reports") should read `/sessions` and say reached/recent/lost
  rather than a lifetime count.

### 4.2 Cairn Autoresearcher.app (`gui/macos/`)

- **`NodePane.swift`**: the *Peers* tile and table read `/sessions` when it
  answers, with the log's announcements as a second table rather than the
  only one; a *Compute* tile from `GET /network` (`compute.live`,
  `compute.steps_per_second`) beside *Peers*.
- **`TasksView.swift`**: the curated-task rows link to `/ui/coordination?id=`
  as they link to `/ui/task?id=`.
- Then §2.5.

### 4.3 The iPhone reader (`gui/ios/`)

- **`CairnKit/Types.swift`, `NodeClient.swift`**: decoders for `/sessions`
  and `/network`, with a fixture under `Tests/CairnKitTests/Fixtures/` and a
  decode test, as `progress-ecc2k130.json` has.
- **`CairnUI/PeersView.swift`**: a *sessions* section above *announced*, or
  the `available: false` sentence; the opening paragraph loses its "not
  published over HTTP" clause.
- **`CairnUI/`**: a *Network* screen -- the five tiles and hardware by class,
  provenance-labelled -- reachable from `RootView`. The snapshot has no
  sessions and no fleet, so the screen needs a live node and says so, as
  *Progress* does.

### 4.4 The web reader (`ui/`)

- §2.7, the shared read hook, before the next page.
- §2.8, a keyboard-readable list under both strips.
- A `lib/*.test.ts` for the chooser's filter on `/coordination` is missing
  because the filter lives in the page; moving it to `lib/leases.ts` as a
  pure function is the pattern every other page follows and should be
  followed here.

## 5. Method, for whoever does the next one

Read the four surfaces' source against the routes they call, listing for each
page the fields it reads and the node file that writes them; list what the
node knows that no page reads (the daemon's log lines were the giveaway
twice: a fact that is only logged is a fact no reader has); run the node and
read every route it answers; then write the route before the view. Half a
day of reading, and the finding that mattered -- four readers, one
disclaimer -- was visible in the first hour from `grep -rn "not open
connections\|not live sessions\|serves no HTTP"` across `ui/` and `gui/`.
