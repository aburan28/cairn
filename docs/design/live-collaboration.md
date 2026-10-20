# Live source collaboration without Git

This builds on the lab's signed, causally authorised operations and encrypted
replica sync. It does not change settlement records or claim that an edit, a
checkpoint or an execution receipt proves a program correct.

The motivating reference is Anthropic's [Scion engineering article, 13 October
2026](https://www.anthropic.com/engineering/redesigning-source-control). Its
server APIs, incremental changes and cheap working copies are useful ideas.
The CRDT editing protocol below is CAIRN's own layer, using established RGA
sequence semantics rather than claiming Scion implements this protocol.

## Contract

- A workspace is a signed creation change. A fork names the exact causal heads
  of an existing workspace; it shares immutable history without copying files.
- Changes are versioned values in the existing lab document namespace
  `cairn.collab/v1`. Their identifiers hash their canonical payload. The outer
  lab operation supplies membership, signature and transport authentication.
- Every edit supplies the heads the caller actually read. A positional Unicode
  splice is converted to stable character identifiers before publication.
  Concurrent insertions converge by logical clock and change id, preserving
  each inserted run. A deletion removes only observed characters.
- Multi-file edits are one signed change. Concurrent deletion/edit and
  executable-mode conflicts, overlapping replacements and detected path
  collisions remain visible and block checkpointing. A file write resolves
  an overlapping replacement only if it observes both conflicting changes.
- A signed integration joins exact heads from related task lanes, retaining
  the original changes' authors and ids. Source edits published later remain
  isolated. The resulting text still needs validation.
- A caller request id is an idempotency key scoped to its author. Retrying the
  same request returns the same change; reusing it for different content fails.
- Feed cursors are causal frontiers, not wall clocks, array positions or
  Lamport offsets. Late concurrent work is included. Bounded pagination advances
  only through delivered changes. Revoked or unavailable cursor history requires
  a reset instead of silently claiming continuity.
- A checkpoint pins heads and content-addressed file bytes in one manifest and
  publishes the manifest and files atomically to the ordinary lab. Existing
  `lab_exec` / exact replay consumes the returned per-file input list. A unique
  publication path prevents offline publishers from creating conflicts in
  write-once file registers. A directory mount is deliberately not returned:
  its input set could grow. No runner executes draft content implicitly.
- Each process works through a local replica. Continuous encrypted sync reuses
  a connection, reconnects with bounded backoff and exposes changes promptly.
  A network partition permits continued work and can duplicate advisory tasks;
  it cannot establish that a task ran only once.

The first version edits UTF-8 source files, retains history/tombstones and
bounds individual requests and projections. It does not virtualize a monorepo,
provide binary CRDT editing, automatically reconcile program semantics, or
replace an organization's deployment/review policy. Converged text can still
fail tests. Proposed integrations require a fresh checkpoint and verification.
