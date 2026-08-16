# Local developer entry points.  The MCP server speaks JSON-RPC on stdin/stdout,
# so `make mcp` intentionally stays attached to the terminal for an MCP client.

CARGO ?= cargo
PYTHON ?= python3

ROOT := $(abspath .)
LOCAL_DIR ?= .local
LOG ?= $(abspath $(LOCAL_DIR)/proofwork.jsonl)
# `make mcp` and `make p2p` each get their own log so they can run together in
# one workspace. Both binaries append and both take the ledger's exclusive lock
# (Ledger::open_exclusive) -- two writers over one hash-linked file each compute
# `prev` from their own view of the tail. Pointed at the same path, whichever
# starts second dies at startup with "another process is already writing".
#
# Separate logs are also the arrangement docs/agents.md recommends on its own
# merits: an agent's log and a node's log are different things, and the daemon
# reconciles them by anti-entropy rather than by sharing a file descriptor. To
# get that reconciliation, run a second daemon over this log:
#
#   make p2p LOG=$(MCP_LOG) LISTEN=127.0.0.1:9001 CHECKPOINT=... IDENTITY=...
P2P_LOG ?= $(abspath $(LOCAL_DIR)/proofwork-p2p.jsonl)
MCP_LOG ?= $(abspath $(LOCAL_DIR)/proofwork-mcp.jsonl)
RELEASE_DIR ?= target/release
CLI := $(RELEASE_DIR)/proofwork
MCP := $(RELEASE_DIR)/proofwork-mcp
P2P := $(RELEASE_DIR)/proofwork-p2p
SERVE := $(RELEASE_DIR)/proofwork-serve
FUZZ_CASES ?= 2000
IDENTITY ?= $(abspath $(LOCAL_DIR)/node.identity.json)
ROOT_KEY ?= $(abspath $(LOCAL_DIR)/root.key)
CHECKPOINT ?= $(abspath $(LOCAL_DIR)/checkpoint.json)
# ---------------------------------------------------------------------------
# One port number, and everything derived from it
# ---------------------------------------------------------------------------
#
# There used to be four independently-editable defaults -- p2p on 9000, HTTP on
# 8080, the UI on 3000, the seed on 5000 -- three of which had to agree about
# something and none of which were derived from each other. They drifted, and
# the drift was invisible: a seed operator running `make p2p` bound :9000 on
# loopback while every client dialled :5000, which fails as `Connection refused`
# with no hint that the number is the problem. Binding loopback succeeds, so
# nothing complains at the end that is doing the wrong thing.
#
# So: one knob. `PORT` is this node's peer-to-peer port; HTTP is the next one
# and the UI the one after, because three processes speaking three protocols
# cannot share a TCP port and pretending otherwise would be a lie in a Makefile.
# What they *can* share is a single number to set.
PORT ?= 5000
P2P_PORT := $(PORT)
HTTP_PORT := $(shell expr $(PORT) + 1)
UI_PORT ?= $(shell expr $(PORT) + 2)

# Loopback, because the common case is a *client*: it dials out and nothing
# needs to dial it. `make node BIND=0.0.0.0` is the seed, and it is the same
# command rather than a second one -- see the `node` target.
BIND ?= 127.0.0.1
LISTEN ?= $(BIND):$(P2P_PORT)
SERVE_LISTEN ?= $(BIND):$(HTTP_PORT)

GEN_BOOTSTRAP := $(RELEASE_DIR)/proofwork-gen-bootstrap
# The *remote* seed to dial, which is a different thing from the ports above --
# but its port is derived from the same knob, because a network whose members
# disagree about the port is a network with no members. Override the host alone
# with SEED_HOST, or the whole address with SEED_ADDR.
SEED_HOST ?= 44.229.170.164
SEED_ADDR ?= $(SEED_HOST):$(PORT)
SEED_BOOTSTRAP ?= $(abspath $(LOCAL_DIR)/seed.json)
BOOTSTRAP_ARGS ?= --bootstrap $(SEED_BOOTSTRAP)
# A seed does not bootstrap against itself. Set it to peer with other seeds.
SEED_BOOTSTRAP_ARGS ?=
SERVE_ARGS ?=
# The spool `proofwork-serve` writes POST /submit into and the daemon drains
# each round. One directory, shared by the two halves of one node: the daemon
# holds the log's exclusive lock, so an accepting HTTP server cannot write the
# log itself and queues instead. See docs/serving.md.
QUEUE ?= $(abspath $(LOCAL_DIR)/queue)
P2P_ARGS ?=
# Which MCP client `make mcp-setup` writes a stanza for.
CLIENT ?= claude

.DEFAULT_GOAL := help

# `ui/node_modules` is deliberately absent: it is a real directory whose
# freshness against the lockfile is the whole point of the rule.
.PHONY: help build debug cli mcp mcp-setup node p2p seed serve ui ui-check demo ratchet shard-demo identity \
	interop differential fuzz mcp-smoke serve-smoke canary dispute attest arena blob rekey p2p-demo try examples \
	test test-rust \
	test-reference fmt clippy docs tla check

help:
	@printf '%s\n' \
	  'proofwork local commands:' \
	  '  make node                The whole node, one command: peers + HTTP reader.' \
	  '  make node UI=1           ...and the Next.js reader as well.' \
	  '  make node PORT=6000      Every port derives from PORT (peers, HTTP+1, UI+2).' \
	  '  make node BIND=0.0.0.0   Serve strangers. `make seed` is exactly this.' \
	  '  make seed                Run as a public seed. One line: it delegates to node.' \
	  '  make mcp                 Build, write opencode.json, and run the MCP server (stdio).' \
	  '  make mcp-setup           Wire an MCP client to this checkout (default: Claude Code).' \
	  '  make mcp-setup CLIENT=opencode   ...or opencode / codex.' \
	  '  make p2p                 The daemon alone, with no HTTP and no reader.' \
	  '  make mcp MCP_LOG=my-path  Use a custom MCP ledger path.' \
	  '  make p2p P2P_LOG=my-path  Use a custom P2P ledger path.' \
	  '  make opencode.json       (Re)write the OpenCode MCP config without starting the server.' \
	  '  make serve               Publish this log over HTTP (read-only).' \
	  '  make ui                  Run the Next.js UI against a node already running.' \
	  '  make ui-check            Typecheck and build the UI, as CI does.' \
	  '  make cli ARGS="..."      Run the release CLI against the local ledger.' \
	  '  make build               Build every release binary.' \
	  '  make demo                Run the end-to-end walkthrough.' \
	  '  make canary              Mint canaries and catch a rubber-stamper.' \
	  '  make attest              Bonded verification, end to end, both implementations.' \
	  '  make dispute             A bonded dispute settled by trace bisection.' \
	  '  make arena               Play attack strategies for money against the rules.' \
	  '  make shard-demo          Six holders, one shard each, one of them lying.' \
	  '  make tla                 Model-check every TLA+ module in spec/tla.' \
	  '  make check               Run the full required verification suite.' \
	  '                           (Everything AGENTS.md lists except ui-check,' \
	  '                            which needs a Node toolchain.)' \
	  '' \
	  'Logs: serve and cli share LOG=.local/proofwork.jsonl; mcp uses' \
	  '      MCP_LOG=.local/proofwork-mcp.jsonl; p2p uses' \
	  '      P2P_LOG=.local/proofwork-p2p.jsonl. mcp and p2p both append and' \
	  '      take an exclusive lock, so aiming them at one file makes whichever' \
	  '      starts second refuse. See docs/agents.md.' \
	  '' \
	  'Ports: PORT=5000 is the only number to set. Peers bind PORT, HTTP binds' \
	  '       PORT+1, the Next.js reader binds PORT+2. Three protocols cannot' \
	  '       share one TCP port; they share one knob instead.' \
	  '' \
	  'P2P overrides: BIND=127.0.0.1 BOOTSTRAP_ARGS="--bootstrap peer.json"' \
	  '             IDENTITY=.local/node.identity.json ROOT_KEY=.local/root.key' \
	  '             CHECKPOINT=.local/checkpoint.json QUEUE=.local/queue' \
	  '             SEED_HOST=44.229.170.164  the seed to dial; its port is PORT,' \
	  '                                     so the two cannot drift apart.' \
	  '                                     .local/seed.json is generated on first' \
	  '                                     run with a placeholder key -- see' \
	  '                                     proofwork-gen-bootstrap and docs/p2p.md'

build:
	$(CARGO) build --release --bins

debug:
	$(CARGO) build --bins

$(LOCAL_DIR):
	mkdir -p "$@"

# opencode.json tells OpenCode how to launch the MCP server. Generated once;
# rebuilds when Makefile changes (the only time the paths inside could differ).
#
# Delegates to scripts/mcp-config.sh rather than writing the file directly --
# an earlier version of this target did `open('opencode.json', 'w').write(...)`
# unconditionally, which is exactly the failure mode the script exists to
# avoid: overwriting a config that might hold other MCP servers, wholesale,
# because one stanza needed adding. One implementation instead of two also
# means this and `make mcp-setup CLIENT=opencode` cannot drift apart.
opencode.json: Makefile | $(LOCAL_DIR)
	@./scripts/mcp-config.sh --client opencode --log "$(MCP_LOG)" --identity "$(IDENTITY)"

# `exec` preserves the MCP process's stdin/stdout unchanged: stdout is protocol
# data, so a wrapper must never add banners or diagnostics to it.
mcp: build opencode.json | $(LOCAL_DIR)
	exec "$(MCP)" --log "$(MCP_LOG)" --root "$(ROOT)"

# Writes the client's config rather than running the server: the client spawns
# its own copy. Depends on `build` so the path written is one that exists --
# a stanza naming a binary that was never compiled fails inside the client,
# where the error is a connection timeout rather than "no such file".
mcp-setup: build | $(LOCAL_DIR)
	./scripts/mcp-config.sh --client "$(CLIENT)" --log "$(MCP_LOG)" --identity "$(IDENTITY)"

# A placeholder bootstrap file for SEED_ADDR: structurally valid, but the key
# inside is freshly generated, not the real seed's. It authenticates nobody
# until "public" is replaced with the seed's actual key -- see
# proofwork-gen-bootstrap.rs. Regenerated only if missing, so a real key
# dropped in by hand is never overwritten.
#
# Never overwriting is right and it has a cost: change `SEED_ADDR` after the
# file exists and the daemon keeps dialling the old address, because the address
# it dials comes from the file and not from the variable. That fails as
# `Connection refused`, which reads as "the seed is down" rather than "you are
# calling the wrong number". Said here rather than left to be worked out from a
# retry loop.
$(SEED_BOOTSTRAP): build | $(LOCAL_DIR)
	@test -f "$(SEED_BOOTSTRAP)" || "$(GEN_BOOTSTRAP)" --addr "$(SEED_ADDR)" --out "$(SEED_BOOTSTRAP)"
	@have=$$(sed -n 's/.*"addr"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$(SEED_BOOTSTRAP)"); \
	  if [ -n "$$have" ] && [ "$$have" != "$(SEED_ADDR)" ]; then \
	    printf 'make: %s says addr %s, but SEED_ADDR is %s -- the file wins.\n' \
	      "$(SEED_BOOTSTRAP)" "$$have" "$(SEED_ADDR)" >&2; \
	    printf '      rm %s to regenerate it for the new address.\n' "$(SEED_BOOTSTRAP)" >&2; \
	  fi

# The daemon creates the identity, root key, and signed checkpoint files on the
# first run. Keep them under .local by default; these files contain secrets and
# must not be committed.
#
# The daemon alone, with no HTTP and no reader. `make node` is the one to run;
# this stays because a peer-to-peer problem is easier to read without two other
# processes logging into the same terminal.
p2p: build $(SEED_BOOTSTRAP) | $(LOCAL_DIR)
	exec "$(P2P)" --identity "$(IDENTITY)" --root-key "$(ROOT_KEY)" \
	  --checkpoint "$(CHECKPOINT)" --listen "$(LISTEN)" \
	  --log "$(P2P_LOG)" --root "$(ROOT)" $(BOOTSTRAP_ARGS) $(P2P_ARGS)

# ---------------------------------------------------------------------------
# `make node` -- the whole node, one command
# ---------------------------------------------------------------------------
#
# The daemon and the HTTP publisher over one log, plus the reader if you ask for
# it. They compose rather than conflict, and the reason is worth knowing before
# changing any of it: `proofwork-p2p` opens the ledger with
# `Ledger::open_exclusive` because it is the writer, and `proofwork-serve` opens
# it read-only. So the HTTP half cannot admit a submission itself -- it queues
# into `QUEUE`, and the daemon drains that spool each round through the same
# `serve::drain_into` the CLI uses. One copy of admission, two processes.
#
# **`UI=1` is optional and that is the point.** `proofwork-serve` renders the
# chain at `/chain.html` with no build step, so the default is one command, two
# processes and no Node toolchain at all. `ui/` is the richer client, not the
# only one.
#
# `make node BIND=0.0.0.0` is the seed. Not a second target: an instance's
# public address is NAT'd to it and is on no local interface, so `--listen
# <public ip>` cannot bind -- you bind the wildcard and publish the public
# address in the bootstrap file you hand out. The peer id is the hash of the
# key, so an address is only ever a dial hint. See docs/p2p.md.
ifeq ($(UI),1)
NODE_UI_DEP := $(ROOT)/ui/node_modules
else
NODE_UI_DEP :=
endif

node: build $(SEED_BOOTSTRAP) $(NODE_UI_DEP) | $(LOCAL_DIR)
	@printf '\n  peers   %s\n  reader  http://%s:%s/chain.html\n' \
	  "$(LISTEN)" "$(if $(filter 0.0.0.0,$(BIND)),127.0.0.1,$(BIND))" "$(HTTP_PORT)"
	@$(if $(filter 1,$(UI)),printf '  ui      http://127.0.0.1:%s\n' "$(UI_PORT)";,true)
	@printf '  log     %s\n  queue   %s\n\n' "$(P2P_LOG)" "$(QUEUE)"
	@mkdir -p "$(QUEUE)"
	@# `kill 0` signals the whole process group, so one Ctrl-C stops all of
	@# them. Deliberately no `set -m`: job control would put each background
	@# job in its own group and `kill 0` would then reach none of them.
	@trap 'kill 0' INT TERM EXIT; \
	  "$(P2P)" --identity "$(IDENTITY)" --root-key "$(ROOT_KEY)" \
	    --checkpoint "$(CHECKPOINT)" --listen "$(LISTEN)" \
	    --log "$(P2P_LOG)" --root "$(ROOT)" --queue "$(QUEUE)" \
	    $(BOOTSTRAP_ARGS) $(P2P_ARGS) & \
	  "$(SERVE)" --log "$(P2P_LOG)" --root "$(ROOT)" \
	    --listen "$(SERVE_LISTEN)" --queue "$(QUEUE)" \
	    --checkpoint "$(CHECKPOINT)" $(SERVE_ARGS) & \
	  $(if $(filter 1,$(UI)),( cd "$(ROOT)/ui" \
	    && NEXT_PUBLIC_PROOFWORK_NODE="http://127.0.0.1:$(HTTP_PORT)" \
	       npm run dev -- -p $(UI_PORT) ) & ,) \
	  wait

# Run *as* the seed everyone else's default bootstrap points at.
#
# One line, because a seed is `make node` with a different bind address and
# nothing else. It used to be a second copy of the daemon invocation, which is
# how it came to bind a port the clients were not dialling.
#
# Two things this cannot do for you: open the port inbound (a security group
# that drops rather than refuses looks exactly like silence on both ends), and
# put your real public key in the bootstrap files other people hold. Print
# yours from the "public" field of $(IDENTITY).
seed:
	@$(MAKE) --no-print-directory node BIND=0.0.0.0 \
	  BOOTSTRAP_ARGS="$(SEED_BOOTSTRAP_ARGS)"

cli: build | $(LOCAL_DIR)
	"$(CLI)" --log "$(LOG)" --root "$(ROOT)" $(ARGS)

identity: build
	./scripts/identity-demo.sh

demo: build
	PROOFWORK_BIN="$(abspath $(CLI))" ./scripts/demo.sh

ratchet: build
	PROOFWORK_BIN="$(abspath $(CLI))" ./scripts/ratchet-demo.sh

shard-demo: build
	RUST_BIN="$(abspath $(CLI))" ./scripts/shard-demo.sh

differential: build
	./scripts/differential.sh

# The scripts AGENTS.md requires before claiming a change works, each with the
# same name as the thing it guards. They were reachable only by typing the path,
# which is how `make check` came to run a smaller suite than CI while calling
# itself "the full required verification suite".
canary: build
	./scripts/canary-demo.sh

dispute: build
	./scripts/dispute-demo.sh

attest: build
	./scripts/attestation-demo.sh

arena: build
	$(CARGO) run --release --bin arena

blob: build
	./scripts/blob-demo.sh

rekey: build
	./scripts/rekey-demo.sh

p2p-demo: build
	./scripts/p2p-demo.sh

try: build
	./scripts/try-demo.sh

examples: build
	./scripts/check-examples.sh

fuzz: build
	./scripts/fuzz-differential.sh $(FUZZ_CASES)

interop: build
	RUST_BIN="$(abspath $(CLI))" ./scripts/interop.sh

mcp-smoke: build
	RUST_BIN="$(abspath $(CLI))" MCP_BIN="$(abspath $(MCP))" ./scripts/mcp-smoke.sh

serve-smoke: build
	RUST_BIN="$(abspath $(CLI))" SERVE_BIN="$(abspath $(SERVE))" ./scripts/serve-smoke.sh

# Publish this node's log over HTTP. Read-only unless QUEUE is set, because
# publishing is safe for anyone and accepting is a decision.
serve: build
	$(SERVE) --log "$(LOG)" --root "$(ROOT)" --listen "$(SERVE_LISTEN)" $(SERVE_ARGS)

# `npm ci` from the committed lockfile, not `npm install`: it installs exactly
# what the lockfile says and fails if the two disagree, which is the same
# argument `--locked` makes on the Rust side and what CI's ui job runs.
#
# A directory target, so it re-runs when the lockfile is newer and does nothing
# otherwise. Without it, `make ui` on a fresh checkout ran `next` before
# anything had installed it and stopped at `sh: next: command not found` --
# a build step missing from a Makefile, reported as a missing binary.
$(ROOT)/ui/node_modules: $(ROOT)/ui/package-lock.json
	@command -v npm >/dev/null || { \
	  echo "make: ui needs npm (Node 22 or newer); see ui/README.md" >&2; exit 1; }
	cd "$(ROOT)/ui" && npm ci
	@touch "$(ROOT)/ui/node_modules"

# Run the Next.js UI that reads from the serve endpoint.
#
# It reads from `make serve`, which is a separate process: the UI on its own
# renders an empty network rather than an error, so start both.
ui: $(ROOT)/ui/node_modules
	cd "$(ROOT)/ui" && npm run dev -- -p $(UI_PORT)

# What CI's ui job actually gates on. `make ui` is the dev server and proves
# nothing about whether the thing compiles.
ui-check: $(ROOT)/ui/node_modules
	cd "$(ROOT)/ui" && npx tsc --noEmit
	cd "$(ROOT)/ui" && npm run build

# `--locked`, `fmt` and `clippy` here as well as on the primary: CI gates the
# reference on all four and this target claimed to stand in for it.
test-reference:
	$(CARGO) test --manifest-path reference/rust/Cargo.toml
	$(CARGO) fmt --check --manifest-path reference/rust/Cargo.toml
	$(CARGO) clippy --manifest-path reference/rust/Cargo.toml --all-targets -- -D warnings
	$(CARGO) build --release --locked --manifest-path reference/rust/Cargo.toml
	./reference/rust/target/release/proofwork-reference conformance conformance/vectors.json
	./reference/rust/target/release/proofwork-reference signed-records conformance/signed-records.json
	./reference/rust/target/release/proofwork-reference signatures conformance/signatures.json

# `--locked` and `--all-features`, because that is what CI runs. Without the
# first, a stale lockfile passes here and fails there; without the second, gated
# code is never compiled and the doc gate below never sees it.
test-rust:
	$(CARGO) test --locked --all-targets
	$(CARGO) test --locked --all-targets --all-features

test: test-rust test-reference

fmt:
	$(CARGO) fmt --check

clippy:
	$(CARGO) clippy --locked --all-targets -- -D warnings
	$(CARGO) clippy --locked --all-targets --all-features -- -D warnings

# Neither `clippy` nor `test` can see these: a public item linking to a private
# one, and a redundant explicit link target. Both have turned a branch red after
# it built, tested and linted clean -- twice in one week, which is why AGENTS.md
# names it and why it is in `check` rather than left to CI.
docs:
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --no-deps --locked --all-features

# scripts/tla.sh exits 3 when it could not check anything -- no JDK and no
# cached jar. Tolerated here so `make check` still works on a machine without a
# JVM, and deliberately NOT tolerated in CI, where the runner is ours and a
# missing toolchain is a broken job rather than an environment to live with.
tla:
	@./scripts/tla.sh; status=$$?; \
	  if [ $$status -eq 3 ]; then \
	    echo "make: tla skipped -- no JDK. Nothing was checked."; exit 0; \
	  fi; \
	  exit $$status

# The suite AGENTS.md actually requires, in roughly ascending cost. It was five
# scripts short of that while calling itself the full one -- canaries, disputes,
# bonded verification, the arena and the examples were all reachable only by
# typing their paths, so a change to any of those mechanisms passed `make check`
# without ever being exercised.
#
# `ui-check` is not here and that is deliberate: it needs a Node toolchain, and
# a Rust contributor who has never installed one should not be told the suite
# failed. CI runs it on a machine that has one.
check: test fmt clippy docs \
	demo ratchet try identity examples \
	canary dispute attest arena \
	shard-demo blob rekey p2p-demo \
	interop differential fuzz mcp-smoke serve-smoke tla
