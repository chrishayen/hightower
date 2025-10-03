ifndef MAKE_VERSION
$(error Please run this file with GNU Make (gmake))
endif

CARGO_BIN ?= cargo
HT_TOKEN ?= test-token
RUST_LOG ?= debug

.PHONY: dev
## Run the application in dev mode with debug logging and a test token
dev:
	HT_TOKEN=$(HT_TOKEN) RUST_LOG=$(RUST_LOG) $(CARGO_BIN) run -- --node
