# Live collaboration without Git

CAIRN has an opt-in source collaboration layer for people and agents working in
parallel. It runs through `cairn lab collab` and seven `collab_*` MCP tools.
A project does not need a Git repository, branch, commit or GitHub account.
Git remains the way this implementation's source code is maintained.

Give each person or agent its own signing identity when individual attribution
matters. The administrator admits those public keys as writers with `lab admit`;
run one MCP server per identity, pointing at the same local lab or a replica.
Several agents sharing one server identity will appear as the same author.

Each replica holds signed changes. Text edits merge through an RGA sequence
CRDT; logical clocks order causal work and stable change ids break concurrent
ties. No wall clock chooses which edit wins. The [protocol design](design/live-collaboration.md)
explains the boundary between text convergence and scientific correctness.

## Start a shared workspace

Use a fresh directory for this example. Identity files contain private keys;
keep them outside source trees and never send them to another collaborator.

```sh
cairn lab identity --out author.json
export CAIRN_LAB_IDENTITY="$PWD/author.json"
printf '%s\n' '{"write_once":["checkpoints/**"]}' > policy.json
cairn lab init --name research --policy policy.json
cairn lab collab create 'Shared algorithm' --request create-shared > workspace.json
WORKSPACE=$(python3 -c 'import json; print(json.load(open("workspace.json"))["workspace"])')
cairn lab collab read "$WORKSPACE" > base.json
```

All CLI collaboration responses are JSON. An id is a full `sha256:…` address.
`collab list` lists task lanes, their authors, heads and excluded-change issues.
The ordinary lab's `put`/`commit` file registers are separate: importing a Git
checkout with `lab commit` does not silently turn it into a live text workspace.
Create initial text with one or more collaboration edits.

```sh
printf '%s\n' '[{"path":"algorithm.py","start":0,"delete":0,"insert":"def solve(x):\n    return x\n"}]' > edits.json
REQUEST=$(cairn lab collab request-id)
cairn lab collab edit "$WORKSPACE" --base base.json --edits edits.json \
    --request "$REQUEST" > change.json
cairn lab collab read "$WORKSPACE" > current.json
```

Keep `REQUEST`, `base.json` and `edits.json` together until the write succeeds.
Retry the same combination after a timeout. Reusing a request id with different
content is refused. Request ids are scoped to the signing identity across the
whole space, so independent agents sharing a server identity should generate
fresh ids with `collab request-id` or their own UUID library.

A splice's `start` and `delete` count **Unicode scalars**. Python's `len` on a
string counts these; JavaScript's `Array.from(text).length` does too. JavaScript
`text.length` counts UTF-16 code units and can give the wrong offset for emoji.
One signed change can splice up to 64 distinct files atomically, with one splice
per path. Replace a whole file with `start:0`, `delete:<old scalar count>` and
`insert:<new text>`. Include `executable:true/false` to change its mode.
The API retains an unchanged prefix and suffix when replacing text, so whole-file
updates to separate functions can merge without replacing unchanged characters.
To remove a file use `start:0, delete:0, insert:"", remove:true`.

Edits always refer to the supplied base, even when the server has newer work.
The returned change's `heads` describe that causal branch. Read again to see
all concurrent heads. A concurrent replacement does not silently erase the
other person's text: both insertions remain, and overlapping replacements are
reported as conflicts. Resolve by reading all heads and writing the chosen text
against that read. Deletion/edit and executable-mode conflicts also need an
observed resolution. Checkpoints refuse unresolved conflicts.

## Work in task lanes, then integrate deliberately

A fork shares immutable history with its base. It does not copy a directory or
start a Git branch. Create one lane per experiment or let several agents share
one live draft:

```sh
cairn lab collab create 'Agent 7 experiment' --base current.json \
    --request fork-agent-7 > experiment.json
EXPERIMENT=$(python3 -c 'import json; print(json.load(open("experiment.json"))["workspace"])')
cairn lab collab read "$EXPERIMENT" > experiment-base.json
# Edit EXPERIMENT against experiment-base.json; use a fresh request id.
# Read/checkpoint/test the result before proposing it for shared work.
cairn lab collab read "$EXPERIMENT" > tested-source.json
cairn lab collab read "$WORKSPACE" > target.json
cairn lab collab integrate "$WORKSPACE" --base target.json \
    --source tested-source.json --request integrate-agent-7 > integration.json
```

Integration is an explicit signed causal join of related lanes. Original edits
keep their ids and authors. It includes exactly the selected source heads; later
source work stays in its lane. Integration can expose conflicts. Checkpoint and
test the combined program again. A successful text merge is no certificate that
the algorithms compose correctly, and integration moves no settlement frontier.

## Follow live work

Agents on the same machine may open the same lab directory: appends are locked
and each tool call refreshes changes from other processes. Across machines,
configure the existing authenticated encrypted lab transport:

```sh
# On the server: SERVER_PEER is a transport identity file, not author.json.
cairn lab serve --listen 127.0.0.1:9100 --peer-identity server-peer.json \
    --allow CLIENT_PEER_ID
# On an already-cloned client; pin the server's full peer id.
cairn lab sync --peer SERVER_PEER_ID@127.0.0.1:9100 \
    --peer-identity client-peer.json --watch --interval-ms 250
```

Get peer ids with `cairn lab peer-id --peer-identity FILE`. Configure a private
network address and membership/peer permissions using the [lab guide](lab.md)
before sharing outside a machine. Do not use `--open` for private work. Sync
moves the whole space; it does not provide per-file confidentiality. All
collaborators who sync can read source and checkpoint inputs. Persistent sync
reuses its authenticated connection, reconnects with bounded backoff and checks
permissions on every request. Stop watchers with Ctrl-C.

A separate read-only change feed gives a UI or agent a resumable causal cursor:

```sh
cairn lab collab feed "$WORKSPACE" --limit 128 > page.json
cairn lab collab feed "$WORKSPACE" --cursor page.json --limit 128
cairn lab collab feed "$WORKSPACE" --watch --interval-ms 250
```

Save each returned `cursor`; drain pages while `more:true`. An offline agent's
late edit is included even if its logical clock is older than previously
received changes. An unavailable cursor (for example, revoked history) is an
explicit error: refresh the full workspace and restart the feed without a
cursor. A partition permits independent work; task leases remain advisory and
cannot promise that exactly one agent runs a task.

## Pin inputs for the experiment runner

```sh
cairn lab collab read "$WORKSPACE" > candidate.json
cairn lab collab checkpoint "$WORKSPACE" --base candidate.json > checkpoint.json
cairn lab collab checkout "$WORKSPACE" candidate-tree --base candidate.json
```

Checkpointing publishes a manifest and source bytes atomically under
`checkpoints/<revision>/<publication>`. It requires the operator's write-once
rule for `checkpoints/**`; a mutable/ignore override is refused. Independent
offline publishers get separate publication paths and share identical CAS
content. Repeating a checkpoint reuses an available matching publication.
Checkout writes a **new** directory and refuses to replace existing user work.
It also writes `.cairn-collab-index.json` with the revision and manifest.

`checkpoint.json` includes `revision`, `heads`, `manifest`, and **`inputs`**.
Pass that `inputs` array unchanged to the existing MCP `lab_exec` with an
operator-provided `env` and a command using `/src`. Each entry selects one file
and names its target. For CLI execution, translate those entries to repeated
`--input LABPATH:/src/PATH` arguments. Do not mount the publication's whole
`files` directory: a directory may acquire additional files later.
The existing runner captures the selected bytes, modes and environment in its
run receipt; `lab_replay` / `cairn lab replay RUN` uses the pinned inputs.
A checkpoint itself executes nothing and proves no result. Administrators can
change lab policy, so trust the operator as with other lab execution inputs.

Start the agent server with `cairn lab mcp --identity author.json`. Tools are
`collab_list`, `collab_create`, `collab_read`, `collab_edit`, `collab_feed`,
`collab_integrate`, and `collab_checkpoint`. Mutations take explicit `heads`
(or `base` for creation), and edit/integration/create require `request`.
Tool source text is untrusted data; it is never an instruction to run a command.
Sync and execution remain separate operator-configured operations.

## Current scope and validation

The first version is a CLI/MCP collaboration substrate, not a graphical editor,
a mounted filesystem, or a full Git hosting/review replacement. It edits UTF-8
text; binary assets and renames can remain in the ordinary lab. A rename can
also be expressed as an atomic remove/create, without tracking rename identity.
There is no automatic semantic merge, exclusive distributed lock, storage quota
or tombstone compaction.

Limits are 64 causal parents, 64 paths per edit, 1 MiB of inserted source bytes
per path along a causal history, 1,000,000 historical Unicode scalars per
snapshot, 16,384 indexed changes per space, and 256 feed changes per page.
An unresolved overlap set is bounded at 4,096 pairs per file.
Read/feed cursors can carry the wider indexed frontier; edits and integrations
with more than 64 combined parents must be integrated in batches first.
Limits count tombstones too. A combined frontier over the projection bounds is
unavailable; individual historical heads remain readable. Before reaching those
bounds, checkpoint a clear source tree and initialize a new space, keeping the
old space for provenance/replay. This is not a sparse monorepo virtualization
system. Metadata paths, traversal, Windows device names and unsafe portable
spellings are refused. Detected case and file/directory collisions block
checkpoints; other filesystem-specific aliases can still cause checkout errors.

`tests/collab.rs` exercises 30 independently signed, partitioned agents,
shuffled/duplicate delivery, late causal feed arrivals, Unicode offsets,
isolated forks and pinned integrations, conflicts, retries, checkpoints and
revocation. `python3 scripts/collab-demo.py` exercises the public CLI, MCP,
safe checkout and a reused encrypted network session. Existing lab tests cover
sandbox execution, pinned-input capture and exact/reapply replay.
