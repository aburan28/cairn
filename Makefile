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

.DEFAULT_GOAL := help

.PHONY: help build debug cli mcp demo ratchet interop mcp-smoke test test-rust \
	test-python fmt clippy check

help:
	@printf '%s\n' \
	  'proofwork local commands:' \
	  '  make mcp                 Build and run the local MCP server (stdio).' \
	  '  make cli ARGS="..."      Run the release CLI against the local ledger.' \
	  '  make build               Build both release binaries.' \
	  '  make demo                Run the end-to-end walkthrough.' \
	  '  make check               Run the full required verification suite.' \
	  '' \
	  'Overrides: LOG=/path/to/log ROOT=/path/to/repo CARGO=cargo'

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

check: test fmt clippy interop mcp-smoke
