.PHONY: build install test clean

build:
	cargo build

install:
	cargo install --path . --root ~/.local

test:
	cargo test

clean:
	cargo clean
