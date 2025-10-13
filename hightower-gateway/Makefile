ifndef MAKE_VERSION
$(error Please run this file with GNU Make (gmake))
endif

CARGO_BIN ?= cargo
HT_AUTH_KEY ?= test-auth-key
HT_DEFAULT_USER ?= admin
HT_DEFAULT_PASSWORD ?= admin
RUST_LOG ?= debug


.PHONY: dev
## Run the gateway in dev mode with debug logging and a test auth key
dev:
	HT_AUTH_KEY=$(HT_AUTH_KEY) \
	HT_DEFAULT_USER=$(HT_DEFAULT_USER) \
	HT_DEFAULT_PASSWORD=$(HT_DEFAULT_PASSWORD) \
	DISABLE_HTTPS=true \
	HTTP_PORT=8008 \
	RUST_LOG=$(RUST_LOG) $(CARGO_BIN) run

.PHONY: test
## Run all tests
test:
	$(CARGO_BIN) test

.PHONY: check
## Run cargo check
check:
	$(CARGO_BIN) check

.PHONY: clean
## Clean build artifacts
clean:
	$(CARGO_BIN) clean

.PHONY: help
## Show this help message
help:
	@echo "Available targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
