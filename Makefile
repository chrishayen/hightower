ifndef MAKE_VERSION
$(error Please run this file with GNU Make (gmake))
endif

CARGO_BIN ?= cargo
HT_AUTH_KEY ?= test-auth-key
HT_DEFAULT_USER ?= admin
HT_DEFAULT_PASSWORD ?= admin
RUST_LOG ?= debug

.PHONY: build
build: ## Build the node binary
	$(CARGO_BIN) build

.PHONY: build-release
build-release: ## Build the node binary in release mode
	$(CARGO_BIN) build --release

.PHONY: test
test: ## Run tests
	$(CARGO_BIN) test

.PHONY: run
run: ## Run the node with debug logging and test auth key
	HT_AUTH_KEY=$(HT_AUTH_KEY) \
	HT_DEFAULT_USER=$(HT_DEFAULT_USER) \
	HT_DEFAULT_PASSWORD=$(HT_DEFAULT_PASSWORD) \
	RUST_LOG=$(RUST_LOG) $(CARGO_BIN) run

.PHONY: dev
dev: ## Run the node in dev mode (clean data directory first)
	rm -rf ~/.hightower
	HT_AUTH_KEY=$(HT_AUTH_KEY) \
	HT_DEFAULT_USER=$(HT_DEFAULT_USER) \
	HT_DEFAULT_PASSWORD=$(HT_DEFAULT_PASSWORD) \
	RUST_LOG=$(RUST_LOG) $(CARGO_BIN) run

.PHONY: clean
clean: ## Clean build artifacts
	$(CARGO_BIN) clean

.PHONY: help
help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
