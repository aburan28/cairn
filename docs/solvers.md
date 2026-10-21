# Solver packages: `cairn-solver/v1`

A **solver package** is the program an objective's author publishes with the
objective, so that anyone can contribute by pressing **Start** in Cairn.app's
*Share this Mac…* (or running `cairn work --package auto`) without finding,
choosing or trusting a program themselves.

Three promises, each enforced rather than asked for:

1. **One standard interface.** Every package speaks the same process ABI,
   below, so a solver can be written in anything that runs on the target and
   the worker that drives it never changes.
2. **It has to pass.** A package carries known-answer tests. The author's
   machine, the node that offers the package, and every contributor's machine
   run them in the sandbox before the package does any work there.
3. **It cannot do anything else.** Every run is in the same kernel-enforced
   jail as the objective's pinned checker: no network, none of the
   contributor's files, no inherited environment, bounded CPU, memory and time.

The code is `src/solver/`; the threat model is the *Solver packages* section
of [threat-model.md](threat-model.md).

## Why a process ABI and not WebAssembly

The obvious portable plugin format is a WASI module, and it is the strongest
isolation available: a module can only call what its host hands it. It is not
the format here for now, for three reasons that are about this repository
rather than about WASI:

- every WASM runtime fast enough for an ECDLP walk compiles with a JIT, which
  brings a large dependency tree (and, today, C) into a crate whose release is
  a static musl binary with no `cc` in its graph;
- the searches people actually run want native integer throughput, many
  threads and eventually GPUs, which WASI either lacks or charges for;
- the jail already exists, is probed at startup, and is what every pinned
  checker runs in, so a solver gets a boundary the project already tests.

The manifest is ready for it: an unknown target name is kept and skipped
rather than refused, so a package can add a `wasm32-wasip1` build next to its
native ones the day a runtime lands, and older nodes run the targets they know.

[BOINC](https://boinc.berkeley.edu/) is the other prior art worth naming: a
project publishes signed per-platform application versions and clients run
them under a low-privilege account. Packages here are the same shape with a
hash in place of the signature, because the objective that pins a package is
already signed by its funder.

## The package

A directory with `solver.json` at its top:

```json
{
  "abi": "cairn-solver/v1",
  "name": "ecc2k-23-orbit-walk",
  "version": "1.0.0",
  "summary": "What it does, for the person about to run it.",
  "objective": "sha256:…",
  "targets": {
    "python3":      {"entry": "orbit_solver.py", "args": ["--job", "jobs/ecc2k-23.json"]},
    "darwin-arm64": {"entry": "bin/solve-darwin-arm64"},
    "linux-x86_64": {"entry": "bin/solve-linux-x86_64", "args": ["--fast"]}
  },
  "files": {
    "orbit_solver.py": {"sha256": "…", "size": 2644}
  },
  "resources": {"memory_mb": 256, "round_seconds": 120},
  "tests": [
    {
      "name": "first unit of a slice",
      "assignment": {"epoch": 1, "units": {"first": 0, "end": 64}},
      "round": 0,
      "expect": [{"dps": [ … ]}],
      "verify": "accept"
    }
  ]
}
```

| field | meaning |
|---|---|
| `abi` | exactly `cairn-solver/v1` |
| `name`, `version` | shown to the person pressing Start. `name` is 1-64 of `a-z 0-9 . _ -` |
| `summary` | optional, at most 500 characters. Written by the publisher: untrusted text |
| `objective` | optional. The objective this package was written for, when it is an *approach* to one that pinned nothing (below). A package an objective pins leaves it out, because its id is computed before the objective's |
| `targets` | platform → `{entry, args}`. `entry` is one of `files`; `args` are fixed by the package, never by the contributor. Known platforms: `darwin-arm64`, `darwin-x86_64`, `linux-x86_64`, `linux-arm64`, `python3`. Unknown names are kept and skipped |
| `files` | every file, by path, with its SHA-256 and size. Up to 256 files, 32 MiB each, 64 MiB in all. Paths are relative, `/`-separated, `[A-Za-z0-9._-]`, nothing hidden, no `.` or `..` |
| `resources` | `memory_mb` (64-16384, default 1024) and `round_seconds` (1-3600, default 600) |
| `tests` | 1-16 known-answer tests, each `expect`, `verify: "accept"`, or both |

**The package id is the SHA-256 of the canonical `solver.json`**, written
`sha256:…`. Because the manifest names every file by hash, the one id pins the
program, its data, its arguments and its tests, exactly as `checker_sha256`
pins a checker. Unknown top-level fields are refused: two nodes must not read
one manifest two ways.

A native entry is checked against its platform's executable format (Mach-O
for `darwin-*`, ELF for `linux-*`, a universal binary counts when it has the
slice) at every check, so a Linux binary filed under `darwin-arm64` is refused
with that sentence rather than failing inside the jail. A Linux build should be
static. A `python3` target runs under the interpreter pinned checkers use
(`CAIRN_PYTHON`, else `python3` on `PATH`; not a pyenv/asdf shim), with the
standard library only.

`cairn solver pack DIR` writes `files` from what is on disk and prints the id.

## The interface

Once per round, the worker starts the target's entry:

- **cwd**: the package directory, read-only.
- **argv**: the target's `args`, and nothing a contributor typed.
- **stdin**: the round's assignment, `GET /work_assignment` for this worker's
  slice, as one line of canonical JSON, then EOF.
- **environment**, and nothing else from anywhere:

  | variable | value |
  |---|---|
  | `CAIRN_ABI` | `cairn-solver/v1` |
  | `CAIRN_ASSIGNMENT` | the same line as stdin |
  | `CAIRN_OBJECTIVE` | the objective id |
  | `CAIRN_WORKER` | this worker's roster name |
  | `CAIRN_EPOCH`, `CAIRN_EPOCH_ENDS_IN` | from the assignment |
  | `CAIRN_ROUND` | zero-based round number for this worker process |
  | `CAIRN_ROUND_SECONDS` | the package's `round_seconds` |
  | `CAIRN_THREADS`, `OMP_NUM_THREADS`, `RAYON_NUM_THREADS` | threads offered |
  | `TMPDIR`, `HOME` | a private scratch directory, deleted after the round |
  | `PATH`, `LANG`, `LC_ALL` | the minimum a runtime needs |

- **stdout**: zero or more candidate artifacts, **one JSON object per line**,
  no floats (canonical JSON has none), at most 256. Blank lines are ignored.
- **exit**: `0`, and the candidates are committed this epoch and revealed in a
  later one by the worker. Exit `0` with nothing printed is "nothing this
  round". Any other exit, a signal, or overrunning `round_seconds` discards
  the round.
- **stderr**: a log. The worker shows its tail.

A solver never talks to the node, signs, cites or submits. `cairn work` does
all of that outside the jail, under the contributor's key, which is why a
package cannot redirect payment however it is written. Determinism is not
required by the ABI but is by `expect` tests: take randomness from the
assignment and `CAIRN_ROUND`, not from the clock.

## The sandbox

A round runs in one of these, chosen once per process
([`src/solver/executor.rs`](../src/solver/executor.rs)) and named in the
worker's startup line (`solver … sandbox runsc`), in `cairn solver check`, and
in the report `GET /solvers` shows:

| executor | boundary | used when |
|---|---|---|
| `runsc` | gVisor: a user-space kernel serves the solver's syscalls | Linux, `runsc` starts a sandbox here, and the worker is root (see below) |
| `kata` | a guest kernel in a lightweight VM | Linux, a container engine runs the Kata runtime, and `CAIRN_SOLVER_KATA_IMAGE` names an image |
| `bwrap` | namespaces over the host kernel | Linux, neither of the above works |
| `sandbox-exec` | seatbelt | macOS, always |

`gVisor` and `Kata` are the host agent's executors
([`src/agent/`](../src/agent/)): a round is built as an executor job and run by
[`agent::job::run`](../src/agent/job.rs), so a solver gets the jail an executor
job gets. The choice is `auto` unless `CAIRN_SOLVER_SANDBOX` says `strongest`
(Kata, else gVisor, never the host), `runsc`, `kata` or `bwrap`. A pinned
executor that cannot run makes the round fail with the reason; it never
quietly runs under a weaker one. Under `auto` a stronger executor that was
passed over is named with its reason in the startup line, for example
`sandbox bwrap (runsc: not on PATH)`.

Whichever runs it, the guarantees are the same:

- no network of any kind: under gVisor and Kata the job is started with
  networking off, so the sandbox has no route to the node or to anything on
  the host's loopback or LAN;
- reads: the package (at `/pkg`, read-only), the system's own directories and,
  for `python3`, the interpreter; never the home directory. Under gVisor the
  sandbox's root is built from nothing but those, not from the host's `/`;
- writes: a scratch directory and a size-limited `/tmp` only, both gone when
  the round ends;
- the scrubbed environment above, `HOME` and `TMPDIR` pointing at scratch;
- the offered threads, `memory_mb`, and `round_seconds` of wall clock. gVisor
  holds memory and CPU with cgroups, which an unprivileged `runsc --rootless`
  does not have. So gVisor is chosen only for a root worker (a systemd service
  is the usual way), and otherwise `auto` falls back to bubblewrap, whose limits
  are enforced, and the startup line says so.

The assignment reaches the solver on stdin through a shell redirect from a
read-only file inside the sandbox, so the sandbox needs `/bin/sh`.
For Kata the image must have `/bin/sh`, `python3` for python3 targets, and a
libc a native target was built for. Job directories and gVisor's state live in
`~/.cairn/solver-run` (`CAIRN_SOLVER_STATE`).

A host with no working jail refuses to run a package, with the fix in the
message (`apt install bubblewrap`). `--allow-unjailed` overrides that for
development and the report says `sandbox: none`. There is no GPU in the jail
yet; a package gets CPU threads only.

### macOS

macOS has seatbelt (`sandbox-exec`) and nothing stronger is wired in. It is a
kernel-enforced policy over the host kernel, the same class as bubblewrap, not
a user-space or virtualised kernel. `CAIRN_SOLVER_SANDBOX=runsc` or `kata` on a
Mac fails with "Linux only".

What a VM-based executor on macOS would take, not built:

- a Linux guest booted with Apple's Virtualization.framework (what Lima,
  Colima and Apple's own container tooling build on), carrying `runsc` or a
  Kata-capable runtime, `/bin/sh` and `python3`;
- the package directory shared read-only into the guest (virtiofs) and the
  assignment and candidates passed in and out over vsock or a pipe, so the
  guest has no network device at all;
- the VM's memory and CPU count set when it is created, which is a hard limit
  for free, with one warm VM per worker and a gVisor or Kata sandbox per round
  inside it rather than a VM boot per round;
- on Apple silicon the guest is arm64 Linux: `linux-arm64` and `python3`
  targets would run, a `darwin-*` native target could not;
- the worker, not the node, owning the VM, and the guest image being pinned
  and hash-checked like a package.

Until then a contributor on a Mac who wants a VM boundary can run the worker
inside a Linux VM they already have (`cairn work --package auto` there picks
gVisor if it is root and has `runsc`).

## Publishing

There are two ways a package becomes the thing that runs.

**Pinned by its objective.** The author packs the solver, puts its id in the
objective's verifier, and checks the two together before posting:

```json
"verifier": {
  "kind": "certificate", "checker": "…", "checker_sha256": "…", "entrypoint": "check",
  "capabilities": {"worker": {"mode": "package", "package": "sha256:<package id>"}}
}
```

```sh
cairn solver pack my-solver/
cairn --root R --log L solver add my-solver/ --objective objective.json
cairn --root R --log L post objective.json
```

`capabilities` is the routing hint verifiers already ignore
([scheduling](../src/scheduling.rs)), so the pin is inside the objective's id
and its funding signature without a new record field, and older nodes read the
objective exactly as before. `cairn post` **refuses** an objective whose pinned
package this node does not hold or whose tests did not pass here. That rule
lives in the author's command only: record sync and peers never apply it, so it
changes nothing about which records a node admits.

**An approach to an objective that pinned none.** Every objective posted
before packages existed, and any objective whose author shipped no solver, can
still get one: name it in `solver.json` (`"objective": "sha256:…"`) and add it
to a node. `--package auto` runs the newest approach that passed on that node.
When an objective *does* pin a package, a node that lacks it offers nothing in
its place: the author chose that program.

`cairn solver add` runs every test on every target this host can run, scoring
`verify: "accept"` tests with the objective's own pinned verifier exactly as
the node scores a submission, and files the package in `ROOT/.cairn/solvers`
only if they pass. A node that can run none of the package's targets (a Linux
node and a macOS-only package) files it on format and hashes alone and says
so; each worker then runs the tests it can on its own platform.

## Running

```sh
cairn work --node http://127.0.0.1:8080 --objective sha256:… --worker garage --package auto
```

The worker asks `GET /solvers?objective=` which package to run, downloads the
manifest and each file (`GET /solvers/{id}`, `GET /solvers/{id}/files/{path}`),
hashes every byte against the id before writing it where the jail can see it,
keeps the copy in `~/.cairn/solvers/<id>` (re-hashed on every start), runs the
package's tests here, and only then takes its first slice. Cairn.app's
*Share this Mac…* does exactly this: it shows the package's name and version,
offers CPU threads and a daily limit, and has no field that names a program.

`GET /objectives` carries a `solver` field per objective (`package`, `name`,
`version`, `pinned`, `ready`), so a picker can say whether Start will work
without asking twice.

## What is not done yet

- **Packages do not travel between nodes.** They live in each node's store.
  A contributor whose own node synced an objective but not its package is told
  the solver is not on this node; they can work against a node that has it.
  Moving packages over the p2p exchange, as pinned checkers already move, is
  the next step.
- **No GPU** inside the jail, and no WASI target yet (above).
- **Publishing is local.** `cairn solver add` writes the store of the node it
  runs beside; there is no HTTP upload, by design for now: a route that
  accepts executables from the network needs its own authorization story.
