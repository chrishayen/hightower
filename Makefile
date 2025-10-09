.PHONY: build build-x86_64 build-arm64 build-all install test clean

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
