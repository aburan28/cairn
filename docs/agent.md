# The host agent: `cairn agent`

A node holds the log and runs pinned verifiers. A worker walks a search and
submits claims. `cairn agent` is the third thing: a long-running process on a
Linux machine with hardware, installed once under systemd, that **registers
what the machine is** -- CPUs, memory, NUMA, every GPU, and which sandboxes
can run untrusted code there -- with one or more nodes, and **runs executor
jobs** dropped into its spool, each inside gVisor or Kata Containers, leaving
a receipt that says exactly which jail held it.

```sh
sudo cairn agent install --node http://node.lan:8080 --roles executor
journalctl -u cairn-agent -f
curl -s http://node.lan:8080/hosts | python3 -m json.tool
```

Three commands and the machine is on the Network page of every reader of
that node, under *Registered hosts*, with its hardware and its jails -- and
a job it is handed runs inside one of those jails with the resources the job
asked for.

## What it is not

**Not a dispatcher.** Nothing on the network pushes work to an agent, and
nothing here should: [coordination.md](coordination.md) says why a dispatcher
is a wound the network does not need. A job reaches an agent as a file in its
spool, written by whatever the operator trusts to write there -- the research
program's own dispatcher, a cron job, `cairn agent submit`, a hand. The node
sees the job only as an advisory lease and a line in a registration, which is
advice to readers and permission to nobody.

**Not a verifier.** A job's output proves nothing. If it is a candidate,
something still submits it and the objective's pinned verifier still grades
it. A receipt says what ran, where, under which jail, with what exit status;
it is a fact about this host and never a fact about a result.

**Not trusted by the node.** A registration is held in the node's memory like
a heartbeat: bounded, unverified, forgotten after a day, never written to the
log, never gossiped. Anyone can post one under any name. See
[Registrations](#registrations-post-hosts) below and
[serving.md](serving.md).

## Commands

| command | what it does |
|---|---|
| `cairn agent probe [--json]` | what this machine is, and which sandboxes work here. Run it first; it is what the registration will say |
| `cairn agent run --node URL …` | the loop a service runs: register every interval, run the queue |
| `cairn agent exec … -- CMD` | run one job now and print its receipt |
| `cairn agent submit FILE` | validate a job spec and queue it for `run` |
| `cairn agent jobs` | queued, running and finished jobs with their receipts |
| `cairn agent install --node URL …` | write the unit and its environment file, create the user, enable and start |
| `cairn agent uninstall [--purge]` | stop, disable, remove; `--purge` also removes the data directory |

Every flag has an environment variable (`CAIRN_AGENT_NODES`,
`CAIRN_AGENT_NAME`, …), which is what the service's environment file sets;
flags win. [cli.md](cli.md#agent) has every flag, and
[configuration.md](configuration.md) every variable.

## The probe

```
$ cairn agent probe
cairn-agent/1.15.3 on gpu-box-1
  linux/x86_64 kernel 6.8.0
  cpus: 128 (AMD EPYC 7763 64-Core Processor; 2 socket(s), 2 numa node(s)) [adx aes avx avx2 bmi2 fma sha_ni]
  memory: 515821 MiB (cgroup caps: no cpus, no MiB)
  gpu 0: nvidia NVIDIA A100-SXM4-80GB 81920 MiB 0000:17:00.0
  gpu 1: nvidia NVIDIA A100-SXM4-80GB 81920 MiB 0000:65:00.0
  kvm: yes
sandboxes:
  kata   usable via docker:kata, gpu (containerd-shim-kata-v2 version 3.8.0)
  runsc  usable via native, docker:runsc, gpu (runsc version release-20250901.0)
  bwrap  usable via native (bubblewrap 0.9.0)
  engine docker 27.3.1 runtimes: io.containerd.runc.v2, kata, runc, runsc
```

Everything comes from `/proc` and `/sys`, plus one `nvidia-smi` for GPU
memory where there is one and one `docker info` (or `podman`, `nerdctl`) for
the runtimes the engine has configured. A number the host does not state is
`null`, never guessed: the node sums these, and a guess is the kind of number
a reader multiplies. The CPU features listed are the ones a solver cares
about -- AVX-512, SHA, carry-less multiply, SVE -- not the whole flags line.
`cgroup` is what the agent's own cgroup caps it to, so a unit with
`CPUQuota=` shows the quota, not the socket count.

Every sandbox is **probed, not assumed**: `runsc do /bin/true`, `bwrap …
/bin/true`, and the engine's runtime list. A binary on `PATH` that cannot
start a sandbox is the common case -- no user namespaces in this container,
no `/dev/kvm` in this VM, the engine socket owned by a group this user is
not in -- and the time to learn that is in a line of the probe, not in the
receipt of a job that ran nowhere.

## Sandboxes: gVisor and Kata, and why both

| sandbox | boundary | driven by | GPU |
|---|---|---|---|
| `kata` | a separate guest kernel in a lightweight VM (Kata Containers) | an engine with the `kata` runtime configured; needs `/dev/kvm` | VFIO passthrough, set up by the operator; the engine is asked |
| `runsc` | gVisor's user-space kernel; a filtered few syscalls reach the host | the engine with the `runsc` runtime, or `runsc` itself over a root filesystem directory | `nvproxy`, in the runtime's daemon configuration; the engine is asked |
| `bwrap` | Linux namespaces over the host kernel | `bwrap` over a root filesystem directory | no |
| `none` | nothing | only by a job's explicit request; the receipt says so | no |

An executor job is code the operator did not write, by definition, and
bubblewrap is namespaces over the host kernel: every syscall the job makes
reaches the kernel the agent runs on. gVisor puts a user-space kernel in
between; Kata puts a hardware-virtualised one. Kata is the stronger boundary
and the one a GPU job usually needs, and it needs a container engine and a
hypervisor to exist; gVisor runs from one static binary over a directory and
is what a box without `/dev/kvm` can offer.

So a job (or `--sandbox`, or `CAIRN_AGENT_SANDBOX`) names a **preference**:

- `auto` -- gVisor if it works here, else Kata, else bubblewrap. The default,
  because gVisor is what most hosts have and what a root-filesystem job can
  use without an engine.
- `strongest` -- Kata, else gVisor. For a job whose author wants the furthest
  it can get from the host kernel.
- `kata`, `runsc`, `bwrap` -- exactly that one, or a refusal.
- `none` -- unconfined. Never chosen by `auto`; a job has to ask, and its
  receipt lists `isolation` under `unenforced`.

The receipt names what it got (`"sandbox": "kata", "via": "docker:kata"`), so
a reader comparing results across hosts sees when two differ in how far their
job was from the metal.

**Engines.** Kata and gVisor plug into Docker, Podman and nerdctl as OCI
runtimes, and that is how a job that names an *image* runs: the engine pulls
and the runtime jails. The agent asks the engine which runtimes it has
(`docker info`) and uses them by name -- `runsc` and `kata` by convention,
`CAIRN_AGENT_RUNSC_RUNTIME` and `CAIRN_AGENT_KATA_RUNTIME` when the operator's
`daemon.json` spells them differently; nerdctl's are the containerd shim names
`io.containerd.runsc.v1` and `io.containerd.kata.v2`. A job that names a
*root filesystem directory* instead goes through the lab's runner
(`src/lab/exec.rs`, the same code `cairn lab exec` uses), which drives
`runsc` or `bwrap` directly and needs no engine. Kata has no engine-free path
worth offering: its runtime is a containerd shim.

**GPU.** Through an engine only, and only as far as the engine takes it:
Docker and nerdctl take `--gpus all`, Podman a CDI device
(`nvidia.com/gpu=all`). The agent reports `gpu: true` on a sandbox when the
NVIDIA container toolkit is registered with that engine, passes a job's
`gpus` through, and refuses a GPU job that would land on a sandbox the engine
will not hand a device to. What it cannot see or do: whether `runsc` has
`--nvproxy` in its runtime arguments, or whether a Kata guest has VFIO
passthrough of that card. Both are the operator's configuration, both are
said in the receipt's notes, and the engine's own refusal is captured in
`stderr` when either is missing.

## Jobs

A job is a JSON file. `cairn agent submit FILE` validates it and copies it
into the spool; `cairn agent run` picks up the oldest, moves it to
`running/<id>/`, runs it, and moves the directory to `done/<id>/` with the
receipt, the captured streams and whatever the job wrote to `/out`.

```json
{
  "id": "walk-0017",
  "objective_id": "sha256:…",
  "task": "unit:4017",
  "image": "ghcr.io/example/walker:1",
  "argv": ["python3", "walk.py", "--unit", "4017"],
  "env": {"SEED": "7"},
  "inputs": [{"source": "/data/job.json", "target": "/in/job.json"}],
  "cpus": 4, "memory_mb": 8192, "gpus": 1, "pids": 256,
  "timeout_seconds": 3600, "network": false, "sandbox": "strongest"
}
```

| field | meaning |
|---|---|
| `id` | `[A-Za-z0-9._-]`, at most 96; the directory name. Defaults to the file's stem. An id that already ran is refused -- a job is run once, by construction |
| `image` **or** `rootfs` | a container image (through an engine, under Kata or gVisor) or an absolute path to a root filesystem directory (through `runsc` or `bwrap` directly) |
| `argv` | the command, as an array |
| `cwd`, `env` | inside the sandbox |
| `inputs` | host paths mounted read-only, at `target` or `/in/<name>` |
| `cpus`, `memory_mb`, `pids` | limits; `0` is none. Memory is a cgroup limit under an engine or gVisor and a resident-set watchdog under bubblewrap, never an address-space cap -- computer algebra systems reserve far more than they touch |
| `gpus` | how many; the engine is asked for all of them |
| `timeout_seconds` | wall clock, 1 to a week, default an hour. Enforced by killing the container by name, not the client |
| `network` | off by default and recorded either way |
| `sandbox` | the preference above |
| `objective_id`, `task` | optional and advisory: with both, the agent leases the task on its nodes while the job runs and releases it with the outcome, so the roster shows who is on what |

The receipt:

```json
{"job_id": "walk-0017", "host": "gpu-box-1", "agent": "cairn-agent/1.15.3",
 "sandbox": "kata", "via": "docker:kata", "sandbox_version": "…",
 "exit_status": 0, "succeeded": true, "timed_out": false, "limit_exceeded": false,
 "error": null, "started": "…", "finished": "…", "wall_ms": 184022,
 "stdout": "…/done/walk-0017/stdout", "stderr": "…", "out": "…/done/walk-0017/out",
 "gpus_requested": 1, "unenforced": [], "notes": []}
```

**An infrastructure failure is not a result.** `error` is set when the jail
could not be built or the engine could not start the container (an engine's
125/126/127 with its stderr), and `exit_status` is then `null`: nothing is
known about the program. Only a status the program itself produced is an
`exit_status`. The same rule as `Unavailable` in the verifiers and the lab:
a receipt must never present a broken host as a fact about the job.

`cairn agent exec` builds the same spec from flags, runs it at once in
`done/<id>/`, and prints the receipt; `--json` prints it as JSON. Its exit
code is `0` for success, `1` for a job that ran and failed, `3` for a host
that could not run it.

## Registrations: `POST /hosts`

Every interval (default 60 s, under the node's 180 s live threshold with two
misses to spare) the agent posts to each node:

```json
{"host": "gpu-box-1", "agent": "cairn-agent/1.15.3", "roles": ["executor"],
 "hardware": {"cpus": 128, "memory_mb": 515821, "gpus": [{"index": 0, "vendor": "nvidia", "model": "NVIDIA A100-SXM4-80GB", "memory_mb": 81920, "bus": "0000:17:00.0", "driver": "nvidia"}, …], "cpu_model": "…", "sockets": 2, "numa_nodes": 2, "cpu_features": ["avx2", …], "kernel": "6.8.0", "cgroup": {"cpus": null, "memory_mb": null}, "kvm": true},
 "sandboxes": {"kata": {"usable": true, "via": ["docker:kata"], "gpu": true, "version": "…"}, "runsc": {…}, "bwrap": {…}, "engines": [{"name": "docker", "version": "27.3.1", "runtimes": ["kata", "runc", "runsc"]}]},
 "jobs": {"running": 1, "capacity": 2, "completed": 17, "failed": 2, "sandbox": "auto"},
 "objectives": ["sha256:…"]}
```

The node answers `202` and holds it in memory. `GET /hosts` lists every host
with its standing (`live` within 180 s, `stale` within 30 min, `gone` after,
forgotten after a day) and sums the live ones: CPUs, memory, GPUs, job
capacity, and how many hosts can use each sandbox. `GET /network` carries the
same table under `compute.hosts`, beside -- and never added to -- the
heartbeating workers under `compute`: a host is where workers run, a worker
is a process on one, and a box with eight GPUs and no worker yet is a fact
about capacity, not about work.

The `hardware`, `sandboxes` and `jobs` blocks travel through the node
**opaque**: it caps the encoded size at 16 KiB, lifts out the few integers it
sums, and hands the rest back verbatim. That shape will grow as hosts grow
stranger, and a server that validated every field would refuse the next one
anybody added. The roster is capped at 4096 hosts and answers `429` past it
rather than evicting; a `host` must be printable and short; fields the node
does not know at the top level are named back in `ignored`.

**A registration is not a record, not evidence, and not trusted.** It is
never appended, gossiped or verified, and nothing that moves money reads it.
A forged one misleads an operator looking at a page and nobody else, costs
the node a bounded allocation, and is undone the moment the real host posts
again. [threat-model.md](threat-model.md) has the row.

The same words as the roles a node declares with `CAIRN_ROLES` --
`coordinator`, `executor`, `verifier`, `relay` -- and the same rule: a hint
about what the operator intends the machine for, never a permission.

## The service

`cairn agent install` writes:

- `/etc/systemd/system/cairn-agent.service`, from the template compiled into
  the binary (`src/agent/cairn-agent.service`); `--print` shows exactly what
  would be written and writes nothing;
- `/etc/cairn-agent/agent.env`, the variables the flags became, mode `0640`;
- `/var/lib/cairn-agent/` (`--data-dir`), with `jobs/{queue,running,done}`
  and the gVisor state root;
- a system user `cairn-agent` with no login, in the `docker`/`podman`, `kvm`
  and `render`/`video` groups where those exist (`--user` picks another;
  `--user root` is honoured and said back).

Then `systemctl daemon-reload`, `enable`, and `--now` unless `--no-start`.
The unit is hardened for a process that only talks to an engine's socket and
reads `/proc` and `/sys`: `NoNewPrivileges`, `ProtectSystem=full`,
`ProtectHome`, `PrivateTmp`, kernel tunables and cgroups read-only, with the
data directory the one writable path. **That is the agent's own
confinement, not the job's**: the job's is gVisor or Kata, chosen per job.
`KillMode=mixed` with a two-minute stop timeout gives a job in flight that
long to finish after `systemctl stop`; past it the control group is killed,
container client included, and the lease the job held expires on its own.
Logs go to stderr, which is the journal: `journalctl -u cairn-agent -f`.

This is the one route that installs a service, and it is explicit for the
reason [install.md](install.md) gives for the packages installing none: where
a node's state lives is the operator's decision. An operator who runs
`cairn agent install` has made it, and can read the unit first.

**Running as root.** A native `runsc` job with cgroup limits, and `bwrap` on
a distribution that disables unprivileged user namespaces, both need it.
Everything through an engine does not -- the engine's daemon is already
root, and the agent's user needs only the socket. Prefer the system user and
an engine; pass `--user root` when the probe, run as that user, shows the
sandbox you need as unusable and says why.

**Reaching the node.** A node's HTTP side is plaintext on purpose
(`tests/cipher_policy.rs` keeps TLS out of the tree), so `--node` is a
loopback, a LAN, a WireGuard or SSH tunnel -- never the open internet in the
clear. Several `--node`s register with each; a node that is down is retried
every interval and logged once when it changes state.

## Checking it

`./scripts/agent-demo.sh` (`make agent-demo`) drives all of it against a node
it shares nothing with: a probe of the host, a registration read back off
`GET /hosts` and `GET /network`, a queued job and an `exec` job with receipts
naming their jail, an unparsable spec moved aside, and the unit rendered
without being written. On a host with gVisor or bubblewrap the jailed job
runs jailed; on one without, it must be refused with a receipt saying why,
and only the job that asked for `none` runs. CI runs it on every push.
