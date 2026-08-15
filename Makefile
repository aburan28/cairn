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
# Loopback, because the common case is a *client*: it dials out and nothing
# needs to dial it. Serving strangers is `make seed`, which binds the wildcard
# deliberately rather than by having everyone edit this.
LISTEN ?= 127.0.0.1:9000
GEN_BOOTSTRAP := $(RELEASE_DIR)/proofwork-gen-bootstrap
SEED_ADDR ?= 44.229.170.164:5000
SEED_BOOTSTRAP ?= $(abspath $(LOCAL_DIR)/seed.json)
BOOTSTRAP_ARGS ?= --bootstrap $(SEED_BOOTSTRAP)
# Derived from SEED_ADDR, never written twice. `LISTEN` and `SEED_ADDR` are two
# independently-editable defaults that have to agree about a port, and they did
# not: clients dialled :5000 while a seed operator running `make p2p` bound
# :9000 on loopback -- reachable by nobody, on the wrong port, with no error
# because binding loopback succeeds. Deriving the port removes the class of
# mistake rather than re-syncing two numbers that will drift again.
#
# `subst` then `lastword` also survives an IPv6 SEED_ADDR: `[::1]:5000` becomes
# `[  1] 5000`, whose last word is still the port.
SEED_PORT = $(lastword $(subst :, ,$(SEED_ADDR)))
SEED_LISTEN ?= 0.0.0.0:$(SEED_PORT)
# A seed does not bootstrap against itself. Set it to peer with other seeds.
SEED_BOOTSTRAP_ARGS ?=
 SERVE_LISTEN ?= 127.0.0.1:8080
SERVE_ARGS ?=
UI_PORT ?= 3000
P2P_ARGS ?=
# Which MCP client `make mcp-setup` writes a stanza for.
CLIENT ?= claude

.DEFAULT_GOAL := help

.PHONY: help build debug cli mcp mcp-setup p2p seed serve node ui ui-build install demo ratchet shard-demo identity interop differential fuzz mcp-smoke serve-smoke node-smoke \
	test test-rust \
	test-reference fmt clippy tla check

help:
	@printf '%s\n' \
	  'proofwork local commands:' \
	  '  make mcp                 Build, write opencode.json, and run the MCP server (stdio).' \
	  '  make mcp-setup           Wire an MCP client to this checkout (default: Claude Code).' \
	  '  make mcp-setup CLIENT=opencode   ...or opencode / codex.' \
	  '  make p2p                 Build and run a local p2p node (dials out; binds loopback).' \
	  '  make seed                Run as a public seed: binds 0.0.0.0 on SEED_ADDR'"'"'s port.' \
	  '  make mcp MCP_LOG=my-path  Use a custom MCP ledger path.' \
	  '  make p2p P2P_LOG=my-path  Use a custom P2P ledger path.' \
	  '  make opencode.json       (Re)write the OpenCode MCP config without starting the server.' \
	  '  make serve               Publish this log over HTTP (read-only).' \
	  '  make node                One process: p2p sync AND HTTP, sharing a log.' \
	  '  make install             Install the released binaries from GitHub.' \
	  '  make ui                  Run the Next.js reader in dev mode (port UI_PORT).' \
	  '  make ui-build            Export the reader and build it INTO the binaries.' \
	  '  make cli ARGS="..."      Run the release CLI against the local ledger.' \
	  '  make build               Build both release binaries.' \
	  '  make demo                Run the end-to-end walkthrough.' \
	  '  make shard-demo          Six holders, one shard each, one of them lying.' \
	  '  make tla                 Model-check every TLA+ module in spec/tla.' \
	  '  make check               Run the full required verification suite.' \
	  '' \
	  'Logs: serve and cli share LOG=.local/proofwork.jsonl; mcp uses' \
	  '      MCP_LOG=.local/proofwork-mcp.jsonl; p2p uses' \
	  '      P2P_LOG=.local/proofwork-p2p.jsonl. mcp and p2p both append and' \
	  '      take an exclusive lock, so aiming them at one file makes whichever' \
	  '      starts second refuse. See docs/agents.md.' \
	  '' \
	  'P2P overrides: LISTEN=127.0.0.1:9000 BOOTSTRAP_ARGS="--bootstrap peer.json"' \
	  '             IDENTITY=.local/node.identity.json ROOT_KEY=.local/root.key' \
	  '             CHECKPOINT=.local/checkpoint.json' \
	  '             SEED_ADDR=44.229.170.164:5000  default bootstrap peer address;' \
	  '                                     .local/seed.json is generated on first' \
	  '                                     `make p2p` with a placeholder key -- see' \
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
$(SEED_BOOTSTRAP): build | $(LOCAL_DIR)
	@test -f "$(SEED_BOOTSTRAP)" || "$(GEN_BOOTSTRAP)" --addr "$(SEED_ADDR)" --out "$(SEED_BOOTSTRAP)"

# The daemon creates the identity, root key, and signed checkpoint files on the
# first run. Keep them under .local by default; these files contain secrets and
# must not be committed.
p2p: build $(SEED_BOOTSTRAP) | $(LOCAL_DIR)
	exec "$(P2P)" --identity "$(IDENTITY)" --root-key "$(ROOT_KEY)" \
	  --checkpoint "$(CHECKPOINT)" --listen "$(LISTEN)" \
	  --log "$(P2P_LOG)" --root "$(ROOT)" $(BOOTSTRAP_ARGS) $(P2P_ARGS)

# Run *as* the seed everyone else's default bootstrap points at.
#
# Binds the wildcard, which is the counterintuitive part and the one that
# matters on a cloud host: an instance's public address is NAT'd to it and is
# on no local interface, so `--listen <public ip>` cannot bind at all. Bind
# 0.0.0.0 and publish the public address in the bootstrap file you hand out --
# an address is only ever a dial hint, because the peer id is the hash of the
# key and the key is what decides who answered. See docs/p2p.md.
#
# Two things this cannot do for you: open the port inbound (a security group
# that drops rather than refuses looks exactly like silence on both ends), and
# put your real public key in the bootstrap files other people hold.
seed: build | $(LOCAL_DIR)
	@printf 'seeding on %s -- hand out this "public" key, not .local/seed.json:\n  %s\n' \
	  "$(SEED_LISTEN)" "$(IDENTITY)"
	exec "$(P2P)" --identity "$(IDENTITY)" --root-key "$(ROOT_KEY)" \
	  --checkpoint "$(CHECKPOINT)" --listen "$(SEED_LISTEN)" \
	  --log "$(P2P_LOG)" --root "$(ROOT)" $(SEED_BOOTSTRAP_ARGS) $(P2P_ARGS)

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

fuzz: build
	./scripts/fuzz-differential.sh $(FUZZ_CASES)

interop: build
	RUST_BIN="$(abspath $(CLI))" ./scripts/interop.sh

mcp-smoke: build
	RUST_BIN="$(abspath $(CLI))" MCP_BIN="$(abspath $(MCP))" ./scripts/mcp-smoke.sh

serve-smoke: build
	RUST_BIN="$(abspath $(CLI))" SERVE_BIN="$(abspath $(SERVE))" ./scripts/serve-smoke.sh

# The seam for `daemon::run`: one process that queues a submission over HTTP
# and admits it itself. `serve-smoke` cannot cover that -- it drains with a
# separate command, which is the topology this replaces.
node-smoke: build
	RUST_BIN="$(abspath $(CLI))" P2P_BIN="$(abspath $(P2P))" SERVE_BIN="$(abspath $(SERVE))" \
	  ./scripts/node-smoke.sh

# Publish this node's log over HTTP. Read-only unless QUEUE is set, because
# publishing is safe for anyone and accepting is a decision.
#
# Takes no lock and holds no Node: safe to point at a log something else is
# writing. It can only ever *queue* a submission -- see `node` for the half
# that can admit one.
serve: build
	$(SERVE) --log "$(LOG)" --root "$(ROOT)" --listen "$(SERVE_LISTEN)" $(SERVE_ARGS)

# The whole node in one process: p2p sync, HTTP publishing, and the queue
# drained by the process that holds the write lock.
#
# This is `make p2p` and `make serve` at once, against one log, which is the
# only arrangement in which a submission arriving over HTTP can actually be
# admitted -- a Ledger has one writer. Uses the p2p log and identity, since
# that is the half that needs them.
node: build $(SEED_BOOTSTRAP) | $(LOCAL_DIR)
	exec "$(P2P)" --identity "$(IDENTITY)" --root-key "$(ROOT_KEY)" \
	  --checkpoint "$(CHECKPOINT)" --listen "$(LISTEN)" \
	  --log "$(P2P_LOG)" --root "$(ROOT)" \
	  --serve "$(SERVE_LISTEN)" $(BOOTSTRAP_ARGS) $(P2P_ARGS)

# Install the *released* binaries, not this checkout's. The script resolves the
# latest tag, checks the tarball against its published sha256, and installs to
# ~/.local/bin unless PROOFWORK_BIN says otherwise.
install:
	./scripts/install.sh

# Run the Next.js reader against a dev server, for working *on* the reader.
# Reading a node does not need this -- see `ui-build`.
ui:
	cd "$(ROOT)/ui" && npm run dev -- -p $(UI_PORT)

# Export the reader and build it into the binaries.
#
# Two steps because they need two toolchains, and separating them is what keeps
# `cargo build` working for somebody with no Node installed: the `ui` feature is
# off by default, and this is the target that turns it on. Afterwards
# `proofwork-p2p --serve ADDR` answers the reader at /ui/.
ui-build:
	cd "$(ROOT)/ui" && npm ci && npm run build
	$(CARGO) build --release --features ui --bins

test-reference:
	cargo test --manifest-path reference/rust/Cargo.toml
	cargo build --release --locked --manifest-path reference/rust/Cargo.toml
	./reference/rust/target/release/proofwork-reference conformance conformance/vectors.json

test-rust:
	$(CARGO) test --all-targets

test: test-rust test-reference

fmt:
	$(CARGO) fmt --check

clippy:
	$(CARGO) clippy --all-targets -- -D warnings

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

check: test fmt clippy demo ratchet shard-demo identity interop differential fuzz mcp-smoke serve-smoke node-smoke tla
