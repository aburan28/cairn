# Local developer entry points.  The MCP server speaks JSON-RPC on stdin/stdout,
# so `make mcp` intentionally stays attached to the terminal for an MCP client.

CARGO ?= cargo
PYTHON ?= python3

ROOT := $(abspath .)
LOCAL_DIR ?= .local
LOG ?= $(abspath $(LOCAL_DIR)/proofwork.jsonl)
# `make mcp` gets its own log, because it cannot share one with `make p2p`.
# Both binaries append, so both take the ledger's exclusive lock
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
MCP_LOG ?= $(abspath $(LOCAL_DIR)/agent.jsonl)
RELEASE_DIR ?= target/release
CLI := $(RELEASE_DIR)/proofwork
MCP := $(RELEASE_DIR)/proofwork-mcp
P2P := $(RELEASE_DIR)/proofwork-p2p
SERVE := $(RELEASE_DIR)/proofwork-serve
FUZZ_CASES ?= 2000
IDENTITY ?= $(abspath $(LOCAL_DIR)/node.identity.json)
ROOT_KEY ?= $(abspath $(LOCAL_DIR)/root.key)
CHECKPOINT ?= $(abspath $(LOCAL_DIR)/checkpoint.json)
LISTEN ?= 127.0.0.1:9000
GEN_BOOTSTRAP := $(RELEASE_DIR)/proofwork-gen-bootstrap
SEED_ADDR ?= 44.229.170.164:5000
SEED_BOOTSTRAP ?= $(abspath $(LOCAL_DIR)/seed.json)
BOOTSTRAP_ARGS ?= --bootstrap $(SEED_BOOTSTRAP)
SERVE_LISTEN ?= 127.0.0.1:8080
SERVE_ARGS ?=
P2P_ARGS ?=

.DEFAULT_GOAL := help

.PHONY: help build debug cli mcp p2p serve demo ratchet identity interop differential fuzz mcp-smoke serve-smoke \
	test test-rust \
	test-reference fmt clippy tla check

help:
	@printf '%s\n' \
	  'proofwork local commands:' \
	  '  make mcp                 Build and run the local MCP server (stdio).' \
	  '  make p2p                 Build and run a local p2p node.' \
	  '  make serve               Publish this log over HTTP (read-only).' \
	  '  make cli ARGS="..."      Run the release CLI against the local ledger.' \
	  '  make build               Build both release binaries.' \
	  '  make demo                Run the end-to-end walkthrough.' \
	  '  make tla                 Model-check every TLA+ module in spec/tla.' \
	  '  make check               Run the full required verification suite.' \
	  '' \
	  'Logs: p2p, serve, and cli share LOG=.local/proofwork.jsonl; mcp has its' \
	  '      own MCP_LOG=.local/agent.jsonl. p2p and mcp both append and both' \
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

# `exec` preserves the MCP process's stdin/stdout unchanged: stdout is protocol
# data, so a wrapper must never add banners or diagnostics to it.
mcp: build | $(LOCAL_DIR)
	exec "$(MCP)" --log "$(MCP_LOG)" --root "$(ROOT)"

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
	  --log "$(LOG)" --root "$(ROOT)" $(BOOTSTRAP_ARGS) $(P2P_ARGS)

cli: build | $(LOCAL_DIR)
	"$(CLI)" --log "$(LOG)" --root "$(ROOT)" $(ARGS)

identity: build
	./scripts/identity-demo.sh

demo: build
	PROOFWORK_BIN="$(abspath $(CLI))" ./scripts/demo.sh

ratchet: build
	PROOFWORK_BIN="$(abspath $(CLI))" ./scripts/ratchet-demo.sh

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

# Publish this node's log over HTTP. Read-only unless QUEUE is set, because
# publishing is safe for anyone and accepting is a decision.
serve: build
	$(SERVE) --log "$(LOG)" --root "$(ROOT)" --listen "$(SERVE_LISTEN)" $(SERVE_ARGS)

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

check: test fmt clippy demo ratchet identity interop differential fuzz mcp-smoke serve-smoke tla
