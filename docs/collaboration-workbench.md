# Local collaboration workbench

The workbench edits the same signed UTF-8 workspaces as CLI and MCP agents. It
does not require Git or a public service. Start it from a lab with a writer key:

```sh
cairn lab --lab research web --identity author.json
```

Open the private local link printed by the command. The credential is a URL
fragment: it never reaches an HTTP request, query log or referrer. The browser
removes the fragment and retains the credential in this tab's session storage.
Closing the process invalidates the credential. An explicit numeric loopback
address/port can be selected with `--listen 127.0.0.1:8123`; binding a public
address is refused. The listener is separate from the public node reader and
opens no ledger. It includes its own static assets in every binary, without a
Node installation or the optional chain-reader build.

## Edit and collaborate

- Create a workspace, add source files and save. One save is an atomic group
  of up to 64 file changes. Text positions count Unicode scalars.
- Independent drafts stay attached to their original read when switching lanes.
  Incoming work is shown without replacing a dirty editor. A save retains the
  concurrent edits; overlapping replacements remain visible conflicts.
- A lost response freezes the exact payload and request id. **Retry same save**
  does not manufacture another signed edit. Editing resumes after acknowledgement
  and a fresh read. A failed subsequent read also retains the same request.
- Drafts recover on reload in the same browser tab. Export/import retains the
  signed base, text, modes and a pending request. Import checks the base against
  signed history and checks that a retained request matches the displayed draft.
  Export before closing the tab. Browser session storage and exported JSON are
  plaintext; protect them like checked-out source. The signing key stays in the
  local process.
- Fork a saved lane to explore separately. Integration previews and pins the
  selected source heads, retains the original authors, and does not implicitly
  include work arriving after that read. Related lanes can be integrated.
- Read all incoming heads before choosing a conflict resolution. **Use current
  file as resolution** signs the chosen text even when no character changes.
  Delete/edit, executable-mode, file/directory and case collisions also remain
  visible; removing a conflicting path is an explicit edit. Checkpoints and runs
  stay disabled while conflicts remain.
- Activity provides signed authors, causal parents and read-only historical
  snapshots. No source, filename or receipt is evaluated as browser code.

Each machine runs its own workbench and lab replica. Keep the existing encrypted
`cairn lab sync --watch` process running to exchange edits. Browser polling reads
the local replica; it does not open a public editing server. Cursors are causal,
and a cached read index invalidates for every op, including revocations.
The editor does not provide remote cursors, semantic conflict proofs or a
virtualized monorepo. The protocol's 64-parent edit bound still applies to a
wide read; use explicit CLI integration batches before editing such a frontier.

## Experiments and compute estimates

Import an execution environment with `cairn lab env import`. In **Experiments**,
select it, enter a program and one literal argument per line, and review the
pinned source revision before confirming. The runner mounts the exact checkpoint
file list under `/src`, uses `/src` as the working directory and records the
environment, input bytes and outputs in its existing receipt. Runtime setup
failure is **unavailable**, never a verdict about the program.

The local GUI requires gVisor or bubblewrap, grants no network or host-directory
mounts, runs at most one job at a time, and caps a session at 32 jobs. Time limits
are 1–600 seconds, CPU allocations 1–64 cores and memory 1–262144 MiB; the fresh
host profile and effective capacity can narrow those limits. Requests are
idempotent within a running workbench process. Pending requests and known job ids
recover across a tab reload. A per-process session id prevents silently retrying
a run in a new process. After a process restart, inspect
recorded receipts before starting another experiment: a crash during execution
cannot establish whether a program completed. Full streams remain pinned in the
receipt; the GUI displays a bounded preview. **Replay pinned inputs** uses the
existing exact-replay path and refuses recipes outside the GUI's resource and
isolation bounds. **Use recipe on current source** prepares a new explicit run
against a new checkpoint and records the source recipe as an advisory reference;
it does not claim that a program or its inputs were semantically integrated.
The CLI/MCP replay tools remain available for other operator-reviewed recipes.

**Compute & pricing** shows usable ISA flags, CPU vendor/model, base/maximum
clock when available, effective CPU budget and memory. The status, estimate and
run admission re-sample this process's hardware. They do not execute an instruction
merely because an OS report advertised it. Runtime/OS-gated feature detection is
the authority for usable flags; missing fields remain unknown.

To estimate prices, start the workbench with the same reviewed rate-card file
used by the host agent:

```sh
CAIRN_AGENT_RATE_CARD=/absolute/path/rates.json \
  cairn lab --lab research web --identity author.json
```

See [hardware-compute.md](hardware-compute.md) for the card schema. Rates are
workload-specific and ordered; there is no invented universal AVX-512 premium.
Unknown capacity, unmet ISA/clock requirements, missing rates and arithmetic
overflow refuse a quote. The GUI retains exact integer microunits, including
amounts beyond JavaScript's Number precision, and clears stale quotes as an
allocation changes. The response includes a canonical quote string for exact
export. A host report or operator price is not attestation, measured throughput,
a reservation, a debit or a verified-result reward. Workload calibration is
still required before treating these estimates as billing evidence. Runs can
declare ISA requirements and an optional priced workload; their receipt note
retains the sampled CPU profile, requirements and estimate. These host reports
do not certify which instructions a virtualized sandbox exposes or prove that
the program used them.

## Compact a workspace

Deleting RGA tombstones from a live space can invalidate an offline agent's
anchors. CAIRN instead rolls a pinned workspace into a **new lab generation**:

```sh
cairn lab --lab research collab read "$WORKSPACE" > base.json
cairn lab --lab research collab compact "$WORKSPACE" research-next \
  --base base.json --identity author.json
```

The command requires a current administrator who is also a writer. It refuses
conflicts, missing/damaged referenced bytes and an existing destination. It
preserves the current members' roles and peer identities. The new generation
has a write-once file policy, a fresh workspace with identical current source
bytes/modes, and an immutable `archives/generation.json` plus
`archives/source.bundle`. The manifest binds the old space, selected heads and
revision, all archived lab heads, bundle address and new baseline. Original
signatures remain in the bundle; the fresh baseline is identified as the
administrator's import. This changes no ledger record or settlement rule.

The source lab is not modified or deleted. Other old lanes and receipts stay in
the archive rather than being silently copied into the new active graph.
Environment root filesystems must be re-imported and verified against their
recorded digest for replay; the bundle retains the environment metadata, pinned
inputs and available referenced output bytes, not a container runtime. If a
rollover fails after directory creation, `ROLLOVER_INCOMPLETE` remains for
inspection. Do not sync a partial generation.

Recover the original signed history into another **new** directory:

```sh
cairn lab --lab research-next collab recover recovered-research
cairn lab --lab recovered-research verify
```

Recovery checks the founder-signed immutable publication, bundle digest,
every signature/blob, archived lab heads and the selected source snapshot.
The recovered replica has the old space id. It can receive late old-space ops
with the existing encrypted or directory sync tools and replay old receipts.
Do not ingest these ops into the new space. Keep the old replica until every
offline contributor has migrated; review late work and explicitly port it to a
new lane. Rollover reduces active graph cost and resets character/change limits;
it does not reclaim archive disk space or automatically translate cross-generation
edits. This is a recoverable handoff, not a claim of coordination-free garbage
collection.

## Validation

`tests/collab_compact.rs` checks exact source/mode preservation, original
authorship and checkpoint-byte recovery, late offline ops, permissions, existing
paths, conflicts and missing bytes. The local HTTP tests cover framing,
credentials, DNS rebinding/origin/proxy refusal, shared retry semantics and cache
invalidation on concurrent revocation. `node scripts/workbench-model.test.mjs`
checks Unicode drafts, retries/reload, modes/deletion, explicit resolutions,
integer amounts and prototype-named source paths.

`python3 scripts/workbench-demo.py` drives the actual CLI and local HTTP server,
including a sandboxed run when available or an explicit unavailable result.
Set `CAIRN_WORKBENCH_BROWSER=1` with Playwright installed in `ui` to exercise
320/360/1280 layouts, recovery, concurrent updates, a lost response, conflict
resolution, checkpoints and pricing. CI runs these paths alongside the existing
collaboration laws, reader checks and independent conformance audits.
