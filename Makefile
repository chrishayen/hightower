ifndef MAKE_VERSION
$(error Please run this file with GNU Make (gmake))
endif

.PHONY: help
.DEFAULT_GOAL := help

# Configuration
CARGO_BIN ?= cargo
HT_AUTH_KEY ?= test-auth-key
HT_DEFAULT_USER ?= admin
HT_DEFAULT_PASSWORD ?= admin
RUST_LOG ?= debug

# STUN server deployment config
STUN_BINARY_NAME = ht-stun-server
STUN_REMOTE_USER = root
STUN_REMOTE_HOST = 46.62.214.173
STUN_REMOTE_PATH = /usr/local/bin/$(STUN_BINARY_NAME)
STUN_TARGET = aarch64-unknown-linux-gnu

# Deployment config
DEPLOY_HOST = gateway.shotgun.dev
DEPLOY_USER = root

## Workspace targets

build: ## Build all workspace crates in release mode
	$(CARGO_BIN) build --release

build-debug: ## Build all workspace crates in debug mode
	$(CARGO_BIN) build

build-x86_64: ## Build for x86_64 Linux using cross
	cross build --release --target x86_64-unknown-linux-gnu

build-arm64: ## Build for ARM64 (aarch64) Linux using cross
	cross build --release --target aarch64-unknown-linux-gnu

build-all: build-x86_64 build-arm64 ## Build for both x86_64 and ARM64

install: ## Install hightower CLI to ~/.local
	$(CARGO_BIN) install --path cli --root ~/.local

test: ## Run all tests in workspace
	$(CARGO_BIN) test

check: ## Run cargo check on workspace
	$(CARGO_BIN) check

clean: ## Clean all build artifacts
	$(CARGO_BIN) clean

## Gateway targets

gateway-dev: ## Run gateway in dev mode with debug logging
	HT_AUTH_KEY=$(HT_AUTH_KEY) \
	HT_DEFAULT_USER=$(HT_DEFAULT_USER) \
	HT_DEFAULT_PASSWORD=$(HT_DEFAULT_PASSWORD) \
	DISABLE_HTTPS=true \
	HTTP_PORT=8008 \
	RUST_LOG=$(RUST_LOG) $(CARGO_BIN) run -p hightower-gateway

gateway-test: ## Run gateway tests
	$(CARGO_BIN) test -p hightower-gateway

gateway-check: ## Run cargo check on gateway
	$(CARGO_BIN) check -p hightower-gateway

## Node targets

node-build: ## Build the node binary
	$(CARGO_BIN) build -p hightower-node

node-build-release: ## Build the node binary in release mode
	$(CARGO_BIN) build --release -p hightower-node

node-run: ## Run the node with debug logging and test auth key
	HT_AUTH_KEY=$(HT_AUTH_KEY) \
	HT_DEFAULT_USER=$(HT_DEFAULT_USER) \
	HT_DEFAULT_PASSWORD=$(HT_DEFAULT_PASSWORD) \
	RUST_LOG=$(RUST_LOG) $(CARGO_BIN) run -p hightower-node

node-dev: ## Run node in dev mode (clean data directory, connect to local gateway)
	rm -rf ~/.hightower
	HT_AUTH_KEY=$(HT_AUTH_KEY) \
	HT_DEFAULT_USER=$(HT_DEFAULT_USER) \
	HT_DEFAULT_PASSWORD=$(HT_DEFAULT_PASSWORD) \
	HT_GATEWAY_URL=http://127.0.0.1:8008 \
	RUST_LOG=$(RUST_LOG) $(CARGO_BIN) run -p hightower-node

node-prod: ## Run node in prod mode (clean data directory, connect to gateway.shotgun.dev)
	rm -rf ~/.hightower
	HT_AUTH_KEY=ht_bcad807af02cb99e6cc9782cfce863ad09e3a15680bae8093fb69cc5fd152906 \
	HT_DEFAULT_USER=$(HT_DEFAULT_USER) \
	HT_DEFAULT_PASSWORD=$(HT_DEFAULT_PASSWORD) \
	HT_GATEWAY_URL=https://gateway.shotgun.dev \
	RUST_LOG=$(RUST_LOG) $(CARGO_BIN) run -p hightower-node

node-test: ## Run node tests
	$(CARGO_BIN) test -p hightower-node

## STUN targets

stun-run: ## Run STUN server via hightower CLI
	$(CARGO_BIN) run -p hightower-cli --bin ht -- stun

stun-build: ## Build STUN server binary for deployment
	$(CARGO_BIN) build --release --target $(STUN_TARGET) --bin $(STUN_BINARY_NAME)

stun-deploy: stun-build ## Deploy STUN server to remote host
	scp target/$(STUN_TARGET)/release/$(STUN_BINARY_NAME) $(STUN_REMOTE_USER)@$(STUN_REMOTE_HOST):$(STUN_REMOTE_PATH)
	ssh $(STUN_REMOTE_USER)@$(STUN_REMOTE_HOST) 'pkill -9 $(STUN_BINARY_NAME) || true'
	ssh $(STUN_REMOTE_USER)@$(STUN_REMOTE_HOST) 'nohup $(STUN_REMOTE_PATH) > /var/log/$(STUN_BINARY_NAME).log 2>&1 &'
	@echo "Deployed $(STUN_BINARY_NAME) to $(STUN_REMOTE_HOST)"

stun-test: ## Run STUN tests
	$(CARGO_BIN) test -p hightower-stun

## Packaging targets

deb: build ## Build Debian package
	$(CARGO_BIN) deb -p hightower-cli

deb-arm64: ## Build Debian package for ARM64
	$(CARGO_BIN) deb -p hightower-cli --target aarch64-unknown-linux-gnu

rpm: build ## Build RPM package
	$(CARGO_BIN) generate-rpm -p hightower-cli

aur: ## Generate AUR package files
	$(CARGO_BIN) aur -p hightower-cli
	@echo "AUR package files generated in target/cargo-aur/"
	@ls -la target/cargo-aur/

## Deployment targets

deploy-test: deb-arm64 ## Deploy deb package to test server
	@echo "Deploying to $(DEPLOY_HOST)..."
	scp target/aarch64-unknown-linux-gnu/debian/hightower_*.deb $(DEPLOY_USER)@$(DEPLOY_HOST):/tmp/
	ssh $(DEPLOY_USER)@$(DEPLOY_HOST) 'dpkg -i /tmp/hightower_*.deb && \
		systemctl restart hightower-stun.service && \
		systemctl restart hightower-gateway.service && \
		systemctl restart hightower-node.service && \
		rm /tmp/hightower_*.deb'
	@echo "Deployment complete!"

## Development workflow targets

dev-full: ## Start gateway and node in dev mode (in separate terminals)
	@echo "Starting gateway in dev mode..."
	@echo "Run 'make gateway-dev' in one terminal"
	@echo "Run 'make node-dev' in another terminal"

## Utility targets

use-local-client: ## Switch node's hightower-client dependency to local path
	@sed -i 's|^hightower-client = .*|hightower-client = { path = "../hightower-client" }|' hightower-node/Cargo.toml
	@echo "Switched to local hightower-client in hightower-node"

use-published-client: ## Switch node's hightower-client dependency to published version
	@sed -i 's|^hightower-client = .*|hightower-client = "0.1"|' hightower-node/Cargo.toml
	@echo "Switched to published hightower-client in hightower-node"

help: ## Show this help message
	@echo "Hightower Workspace Makefile"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
