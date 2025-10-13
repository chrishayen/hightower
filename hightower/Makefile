.PHONY: build build-x86_64 build-arm64 build-all install test clean deb deb-arm64 rpm aur deploy-test run-gateway-dev
DEFAULT: install

# Default build for native architecture
build:
	cargo build --release

# Build for x86_64 Linux
build-x86_64:
	cross build --release --target x86_64-unknown-linux-gnu

# Build for ARM64 (aarch64) Linux
build-arm64:
	cross build --release --target aarch64-unknown-linux-gnu

# Build for both architectures
build-all: build-x86_64 build-arm64

install:
	cargo install --path . --root ~/.local

test:
	cargo test

clean:
	cargo clean

run-stun:
	cargo run --bin ht -- stun

run-gateway-dev:
	@mkdir -p /tmp/hightower-gateway-dev
	HTTP_PORT=8008 DISABLE_HTTPS=true cargo run --bin ht -- run gateway --kv-path /tmp/hightower-gateway-dev

deb: build
	cargo deb

deb-arm64:
	cargo deb --target aarch64-unknown-linux-gnu

rpm: build
	cargo generate-rpm

aur:
	cargo aur
	@echo "AUR package files generated in target/cargo-aur/"
	@ls -la target/cargo-aur/

deploy-test: deb-arm64
	@echo "Deploying to gateway.shotgun.dev..."
	scp target/aarch64-unknown-linux-gnu/debian/hightower_*.deb root@gateway.shotgun.dev:/tmp/
	ssh root@gateway.shotgun.dev 'dpkg -i /tmp/hightower_*.deb && \
		systemctl restart hightower-stun.service && \
		systemctl restart hightower-gateway.service && \
		systemctl restart hightower-node.service && \
		rm /tmp/hightower_*.deb'
	@echo "Deployment complete!"

