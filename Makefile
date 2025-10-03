ifndef MAKE_VERSION
$(error Please run this file with GNU Make (gmake))
endif

CARGO_BIN ?= cargo
HT_AUTH_KEY ?= test-auth-key
RUST_LOG ?= debug

.PHONY: dev
## Run the application in dev mode with debug logging and a test auth key
dev:
	HT_AUTH_KEY=$(HT_AUTH_KEY) RUST_LOG=$(RUST_LOG) $(CARGO_BIN) run -- dev

devroot:
	HT_AUTH_KEY=$(HT_AUTH_KEY) RUST_LOG=$(RUST_LOG) $(CARGO_BIN) run -- root

devnode:
	HT_AUTH_KEY=$(HT_AUTH_KEY) RUST_LOG=$(RUST_LOG) $(CARGO_BIN) run -- node

test:
	cargo test
