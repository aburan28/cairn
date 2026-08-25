# Local developer entry points.  The MCP server speaks JSON-RPC on stdin/stdout,
# so `make mcp` intentionally stays attached to the terminal for an MCP client.

CARGO ?= cargo
PYTHON ?= python3

ROOT := $(abspath .)
LOCAL_DIR ?= .local
LOG ?= $(abspath $(LOCAL_DIR)/cairn.jsonl)
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
P2P_LOG ?= $(abspath $(LOCAL_DIR)/cairn-p2p.jsonl)
MCP_LOG ?= $(abspath $(LOCAL_DIR)/cairn-mcp.jsonl)
RELEASE_DIR ?= target/release
CLI := $(RELEASE_DIR)/cairn
MCP := $(RELEASE_DIR)/cairn-mcp
P2P := $(RELEASE_DIR)/cairn-p2p
SERVE := $(RELEASE_DIR)/cairn-serve
FUZZ_CASES ?= 2000
IDENTITY ?= $(abspath $(LOCAL_DIR)/node.identity.json)
ROOT_KEY ?= $(abspath $(LOCAL_DIR)/root.key)
CHECKPOINT ?= $(abspath $(LOCAL_DIR)/checkpoint.json)
# Loopback, because the common case is a *client*: it dials out and nothing
# needs to dial it. Serving strangers is `make seed`, which binds the wildcard
# deliberately rather than by having everyone edit this.
LISTEN ?= 127.0.0.1:9000
GEN_BOOTSTRAP := $(RELEASE_DIR)/cairn-gen-bootstrap
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

# `ui/node_modules` is deliberately absent: it is a real directory whose
# freshness against the lockfile is the whole point of the rule.
.PHONY: help build debug cli mcp mcp-setup p2p seed serve node ui ui-check ui-build site-snapshot install demo ratchet shard-demo identity \
	interop differential fuzz mcp-smoke serve-smoke node-smoke canary dispute attest arena blob rekey p2p-demo try examples \
	test test-rust \
	test-reference fmt clippy docs tla check

help:
	@printf '%s\n' \
	  'cairn local commands:' \
	  '  make mcp                 Build, write opencode.json, and run the MCP server (stdio).' \
	  '  make mcp-setup           Wire an MCP client to this checkout (default: Claude Code).' \
	  '  make mcp-setup CLIENT=opencode   ...or opencode / codex.' \
	  '  make p2p                 The daemon alone, with no HTTP and no reader.' \
	  '  make mcp MCP_LOG=my-path  Use a custom MCP ledger path.' \
	  '  make p2p P2P_LOG=my-path  Use a custom P2P ledger path.' \
	  '  make opencode.json       (Re)write the OpenCode MCP config without starting the server.' \
	  '  make serve               Publish this log over HTTP (read-only).' \
	  '  make node                One process: p2p sync AND HTTP, sharing a log.' \
	  '  cairn run                Installed release: P2P + HTTP + embedded UI.' \
	  '                           From a checkout, run make ui-build first.' \
	  '  make install             Install the released binaries from GitHub.' \
	  '  make ui                  Run the Next.js reader in dev mode (port UI_PORT).' \
	  '  make ui-check            Typecheck and build the UI, as CI does.' \
	  '  make ui-build            Export the site and build it INTO the binaries.' \
	  '  make site-snapshot       Regenerate the site fallback from launch/.' \
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
	  'Logs: serve and cli share LOG=.local/cairn.jsonl; mcp uses' \
	  '      MCP_LOG=.local/cairn-mcp.jsonl; p2p uses' \
	  '      P2P_LOG=.local/cairn-p2p.jsonl. mcp and p2p both append and' \
	  '      take an exclusive lock, so aiming them at one file makes whichever' \
	  '      starts second refuse. See docs/agents.md.' \
	  '' \
	  'P2P overrides: LISTEN=127.0.0.1:9000 BOOTSTRAP_ARGS="--bootstrap peer.json"' \
	  '             IDENTITY=.local/node.identity.json ROOT_KEY=.local/root.key' \
	  '             CHECKPOINT=.local/checkpoint.json' \
	  '             SEED_ADDR=44.229.170.164:5000  default bootstrap peer address;' \
	  '                                     .local/seed.json is generated on first' \
	  '                                     `make p2p` with a placeholder key -- see' \
	  '                                     cairn-gen-bootstrap and docs/p2p.md'

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
# cairn-gen-bootstrap.rs. Regenerated only if missing, so a real key
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
	CAIRN_BIN="$(abspath $(CLI))" ./scripts/demo.sh

ratchet: build
	CAIRN_BIN="$(abspath $(CLI))" ./scripts/ratchet-demo.sh

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
# ~/.local/bin unless CAIRN_BIN says otherwise.
install:
	./scripts/install.sh

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

# Run the Next.js reader against a dev server, for working *on* the reader.
# Reading a node does not need this -- see `ui-build`.
ui: $(ROOT)/ui/node_modules
	cd "$(ROOT)/ui" && npm run dev -- -p $(UI_PORT)

# Export the reader and build it into the binaries.
#
# Two steps because they need two toolchains, and separating them is what keeps
# `cargo build` working for somebody with no Node installed: the `ui` feature is
# off by default, and this is the target that turns it on. Afterwards
# `cairn-p2p --serve ADDR` answers the reader at /ui/.
ui-build: site-snapshot
	cd "$(ROOT)/ui" && npm ci && npm run build
	$(CARGO) build --release --features ui --bins

# Regenerate the site's fallback snapshot from the settled log in launch/.
#
# Committed output, so building the site needs Node and nothing else -- but it
# is produced by the *node*, over HTTP, because relating a ledger entry to an
# objective's record id means canonical hashing, and a third implementation of
# that in JavaScript is a third place for a consensus rule to drift.
site-snapshot: build
	./scripts/site-snapshot.sh

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
	./reference/rust/target/release/cairn-reference conformance conformance/vectors.json
	./reference/rust/target/release/cairn-reference signed-records conformance/signed-records.json
	./reference/rust/target/release/cairn-reference signatures conformance/signatures.json

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
	interop differential fuzz mcp-smoke serve-smoke node-smoke tla
