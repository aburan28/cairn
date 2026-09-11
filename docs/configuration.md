# Configuration

Everything that changes what `cairn` does and is not a command flag: the
environment variables, where files land, and which ports get opened. Command
flags are in [cli.md](cli.md).

Two of the variables below are **consensus-critical**: set differently on two
nodes, they make those nodes disagree about what the log says. They are marked,
and they are not conveniences.

## Environment variables

| variable | default | what it does |
|---|---|---|
| `CAIRN_LOG_PATH` | `cairn.jsonl` | the ledger file, when `--log` is not given |
| `CAIRN_LOG_LEVEL` | `info` | stderr log level for the daemons: `trace`, `debug`, `info`, `warn`, `error`, `off` |
| `CAIRN_LOG` | — | **deprecated**, and ambiguous by construction — see below |
| `CAIRN_DATA` | — | the data directory, when `--data-dir` is not given |
| `CAIRN_KEY` | `~/.cairn/key` | the at-rest key file |
| `CAIRN_PASSPHRASE` | — | passphrase for a wrapped at-rest key |
| `CAIRN_REQUIRE_SANDBOX` | unset | `1` refuses to run objective code at all without a working jail |
| `CAIRN_SANDBOX_MEMORY_MB` | `4096` (MiB) | address-space cap for pinned pure functions; `0` disables it |
| `CAIRN_EPOCH_SECONDS` | `600` | **consensus-critical.** Epoch length, in seconds |
| `CAIRN_FINALITY_EPOCHS` | `1` | **consensus-critical.** Closed epochs that must pass before an epoch may settle |
| `CAIRN_REQUIRE_BEACON` | unset | `1` refuses a log whose epochs settled without a recorded beacon |
| `CAIRN_BEACON_PORT` | `47396` | moves the LAN discovery beacon port; `off` or `0` disables beacons |
| `CAIRN_LEDGER_FSYNC` | unset | `1` calls `fsync` after every append |

`RUST_LOG` is **not** read. This is not `env_logger`, and pretending otherwise
would promise a directive syntax (`p2p=debug,swarm=trace`) that does not work.
There is one global level, because the question an operator actually has is
"show me more", not "show me more about exactly this module".

### `CAIRN_LOG` is deprecated, and why the deprecation is loud

`CAIRN_LOG` used to mean two things: the stderr log *level* to the daemons, and
the ledger *path* to the CLI. An operator who exported `CAIRN_LOG=debug` to turn
up a daemon's logging and then ran `cairn audit` audited a nonexistent file
called `debug` — which opens as an empty log and **audits clean**.

So the CLI now refuses it rather than guessing:

- a value that parses as a level (`debug`, `WARN`, ` off `) is a usage error
  naming both replacements;
- a value that is unmistakably a path (it has a separator, or the log's
  extension) is honoured with a warning, so an old script still finds its
  ledger;
- anything else — a bare word that is neither, like `verbose` or `mylog` — is
  refused, because a misspelled level looks exactly like a filename.

The daemons still read a level there when `CAIRN_LOG_LEVEL` is unset, so an
existing shell keeps working. Set `CAIRN_LOG_PATH` for the ledger and
`CAIRN_LOG_LEVEL` for the level, and the ambiguity is gone.

### The consensus-critical two

**`CAIRN_EPOCH_SECONDS`** decides which epoch a record falls in. Commit–reveal
requires a reveal to land in a *strictly later* epoch than its commitment, and
settlement batches by epoch. Two nodes with different epoch lengths disagree
about which epoch a record is in, and therefore about what settled and in what
order. Shorten it for a local demo against a log used for nothing else; never on
a node that talks to other nodes.

**`CAIRN_FINALITY_EPOCHS`** decides when a closed epoch becomes eligible to
settle. Two nodes disagreeing about the delay disagree about which epochs are
eligible, which is precisely the fork the constant exists to prevent.

Neither value enters a record, so changing one moves no canonical bytes and
nothing in the log reports the disagreement. That is exactly what makes it
silent, and why both defaults are constants in the source with an override
documented as demo-only.

**`CAIRN_SANDBOX_MEMORY_MB` is not in that class, but it is not cosmetic
either.** It bounds a verifier's address space, and a verifier killed for
exceeding the cap does not return the verdict it would otherwise have returned —
so a node with a smaller cap can differ from its peers on a heavy artifact. The
jail mechanism a node actually used is recorded in the verdict's evidence for
this reason: when auditors compare disagreeing verdicts, how the loser ran it is
the first question.

### The two refusal switches

`CAIRN_REQUIRE_SANDBOX=1` and `CAIRN_REQUIRE_BEACON=1` both turn a documented
weaker mode into a refusal. Neither is the default, for the same reason in both
cases: defaulting them on would fail hosts and logs that are working today —
every machine with no jail mechanism, and every log written before the beacon
record existed, including the published one. An audit that cries wolf is an
audit nobody reads.

Set `CAIRN_REQUIRE_SANDBOX=1` on any node that verifies objectives it did not
write. That is the whole point of the switch: objective-authored code runs on
your machine, and without a jail it runs unconfined. With the switch, a host
that cannot jail it answers `unavailable` instead of running it.

`CAIRN_REQUIRE_BEACON=1` is a *reader's* policy, not a writer's. It gates
acceptance, not settlement — refusing to settle an epoch that already closed
without a beacon would strand its claims permanently rather than protect
anybody.

## The sandbox

Verifier code is pinned by content hash and written by whoever posted the
objective. It runs in an OS jail: **bubblewrap** on Linux (`apt install
bubblewrap`), **seatbelt** on macOS. There is no Windows build, because there is
no third jail.

What the jail does: no network, declared reads only, confined writes, a
deadline, and the address-space cap above. What it does not do: survive a kernel
or policy bug. `verifiers::SANDBOXING` in the source documents exactly what is
and is not covered, and [threat-model.md](threat-model.md) marks the rest.

## Files and directories

### The data directory

`--data-dir`, else `$CAIRN_DATA`, else — for `cairn run` only — `.local`.

```
<data>/
  log/cairn.jsonl        the ledger
  cache/                 re-fetchable content: blobs, shards
  tmp/                   scratch
  node.identity.json     `run`'s peer identity, generated on first use
  root.key               `run`'s checkpoint signing key, generated on first use
  checkpoint.json        `run`'s signed checkpoint, rewritten each round
  queue/                 `run`'s submission spool
```

`--max-size` caps it (`20GB`, `20GiB`). `cairn store status` reports what is
used, what is pinned and what is reclaimable; `cairn store gc` reclaims.

### The at-rest key

`$CAIRN_KEY`, else `~/.cairn/key`. **Deliberately not inside the data
directory**: the default has to be the safe one, because the unsafe one is
invisible — a key beside its ciphertext looks fine right up until the directory
is synced somewhere else, and then it was never encryption at all. `cairn sync`
refuses to copy it.

If neither exists, `~/.proofwork/key` is read as a fallback: this project was
once called `proofwork`, and a rename that quietly looked elsewhere would have
turned every existing operator's sealed log into ciphertext nobody could open.
Nothing writes there — `keygen` creates `~/.cairn` — and it can be deleted once
nobody is upgrading across the rename.

Encryption at rest is a *storage* concern and the hash chain an *integrity* one,
so a sealed log and a plaintext one holding the same records have the same entry
hashes and the same Merkle root. See [storage.md](storage.md).

## Ports

| what | default | changed by |
|---|---|---|
| HTTP API and `/ui/` | `127.0.0.1:8080` | `--serve` (`run`, `p2p`), `--listen` (`serve`) |
| P2P | `127.0.0.1:9000` | `--listen` (`run`, `p2p`), `--p2p-listen` (`serve`) |
| LAN discovery beacon | multicast | `CAIRN_BEACON_PORT`, or `off` |
| MCP | none — stdio | — |

The defaults bind loopback, so a first `cairn run` exposes nothing. Binding
`0.0.0.0` is a deliberate act, and everything the HTTP server publishes is
public by design.

Server limits, which are constants rather than settings: 64 concurrent
connections (past that it answers `503` and says to come back, rather than
dropping silently — a silent close is indistinguishable from a broken server), a
15-second per-request timeout, and 4096 undrained queued records before
submissions are refused (`--max-queue`).

## MCP

`cairn run` and `cairn mcp` speak MCP over **stdin/stdout**, so stdout carries
JSON-RPC and nothing else; every operational message goes to stderr. Closing
stdin stops the process.

```json
{
  "mcpServers": {
    "cairn": { "command": "cairn", "args": ["run"] }
  }
}
```

`--mcp-identity FILE` signs an agent's submissions. `--no-mcp` is for when stdin
belongs to something else, such as a service manager. Running more than one
client at once needs a log per client — [agents.md](agents.md) has that, and the
ten tools.

## Networking through a proxy

`cairn p2p --proxy socks5://127.0.0.1:9050` routes every dial through a SOCKS5
proxy: a Tor client, or an obfs4 bridge. See [censorship.md](censorship.md) for
what that does and does not hide.
