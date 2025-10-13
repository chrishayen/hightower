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
	HT_GATEWAY_URL=http://127.0.0.1:8008 \
	RUST_LOG=$(RUST_LOG) $(CARGO_BIN) run

.PHONY: prod
prod: ## Run the node in prod mode (clean data directory, connect to gateway.shotgun.dev)
	rm -rf ~/.hightower
	HT_AUTH_KEY=ht_bcad807af02cb99e6cc9782cfce863ad09e3a15680bae8093fb69cc5fd152906 \
	HT_DEFAULT_USER=$(HT_DEFAULT_USER) \
	HT_DEFAULT_PASSWORD=$(HT_DEFAULT_PASSWORD) \
	HT_GATEWAY_URL=https://gateway.shotgun.dev \
	RUST_LOG=$(RUST_LOG) $(CARGO_BIN) run

.PHONY: clean
clean: ## Clean build artifacts
	$(CARGO_BIN) clean

.PHONY: use-local-client
use-local-client: ## Switch hightower-client dependency to local path
	@sed -i 's|^hightower-client = .*|hightower-client = { path = "../hightower-client" }|' Cargo.toml
	@echo "Switched to local hightower-client at ../hightower-client"

.PHONY: use-published-client
use-published-client: ## Switch hightower-client dependency to published version
	@sed -i 's|^hightower-client = .*|hightower-client = "0.1"|' Cargo.toml
	@echo "Switched to published hightower-client (latest 0.1.x version)"

.PHONY: help
help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
