.PHONY: test install build clean

test:
	zig build test

build:
	zig build install

install: build
	mkdir -p ~/.local/bin
	cp zig-out/bin/ht ~/.local/bin/
	cp zig-out/bin/stun_server ~/.local/bin/
	cp zig-out/bin/stun_client ~/.local/bin/

clean:
	rm -rf zig-out zig-cache
