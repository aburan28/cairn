# Local developer entry points.  The MCP server speaks JSON-RPC on stdin/stdout,
# so `make mcp` intentionally stays attached to the terminal for an MCP client.

CARGO ?= cargo
PYTHON ?= python3

ROOT := $(abspath .)
LOCAL_DIR ?= .local
LOG ?= $(abspath $(LOCAL_DIR)/proofwork.jsonl)
RELEASE_DIR ?= target/release
CLI := $(RELEASE_DIR)/proofwork
MCP := $(RELEASE_DIR)/proofwork-mcp
P2P := $(RELEASE_DIR)/proofwork-p2p
IDENTITY ?= $(abspath $(LOCAL_DIR)/node.identity.json)
ROOT_KEY ?= $(abspath $(LOCAL_DIR)/root.key)
CHECKPOINT ?= $(abspath $(LOCAL_DIR)/checkpoint.json)
LISTEN ?= 127.0.0.1:9000
BOOTSTRAP_ARGS ?=
P2P_ARGS ?=

.DEFAULT_GOAL := help

.PHONY: help build debug cli mcp p2p demo ratchet interop mcp-smoke test test-rust \
	test-python fmt clippy tla check

help:
	@printf '%s\n' \
	  'proofwork local commands:' \
	  '  make mcp                 Build and run the local MCP server (stdio).' \
	  '  make p2p                 Build and run a local p2p node.' \
	  '  make cli ARGS="..."      Run the release CLI against the local ledger.' \
	  '  make build               Build both release binaries.' \
	  '  make demo                Run the end-to-end walkthrough.' \
	  '  make tla                 Model-check every TLA+ module in spec/tla.' \
	  '  make check               Run the full required verification suite.' \
	  '' \
	  'P2P overrides: LISTEN=127.0.0.1:9000 BOOTSTRAP_ARGS="--bootstrap peer.json"' \
	  '             IDENTITY=.local/node.identity.json ROOT_KEY=.local/root.key' \
	  '             CHECKPOINT=.local/checkpoint.json'

build:
	$(CARGO) build --release --bins

debug:
	$(CARGO) build --bins

$(LOCAL_DIR):
	mkdir -p "$@"

# `exec` preserves the MCP process's stdin/stdout unchanged: stdout is protocol
# data, so a wrapper must never add banners or diagnostics to it.
mcp: build | $(LOCAL_DIR)
	exec "$(MCP)" --log "$(LOG)" --root "$(ROOT)"

# The daemon creates the identity, root key, and signed checkpoint files on the
# first run. Keep them under .local by default; these files contain secrets and
# must not be committed.
p2p: build | $(LOCAL_DIR)
	exec "$(P2P)" --identity "$(IDENTITY)" --root-key "$(ROOT_KEY)" \
	  --checkpoint "$(CHECKPOINT)" --listen "$(LISTEN)" \
	  --log "$(LOG)" --root "$(ROOT)" $(BOOTSTRAP_ARGS) $(P2P_ARGS)

cli: build | $(LOCAL_DIR)
	"$(CLI)" --log "$(LOG)" --root "$(ROOT)" $(ARGS)

demo: build
	PROOFWORK_BIN="$(abspath $(CLI))" ./scripts/demo.sh

ratchet: build
	PROOFWORK_BIN="$(abspath $(CLI))" ./scripts/ratchet-demo.sh

interop: build
	RUST_BIN="$(abspath $(CLI))" ./scripts/interop.sh

mcp-smoke: build
	RUST_BIN="$(abspath $(CLI))" MCP_BIN="$(abspath $(MCP))" ./scripts/mcp-smoke.sh

test-rust:
	$(CARGO) test --all-targets

test-python:
	cd reference/python && $(PYTHON) -m pytest -q

test: test-rust test-python

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

check: test fmt clippy interop mcp-smoke tla
