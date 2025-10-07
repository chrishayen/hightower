.PHONY: build deploy clean

BINARY_NAME = hightower-stun
REMOTE_USER = root
REMOTE_HOST = 46.62.214.173
REMOTE_PATH = /usr/local/bin/$(BINARY_NAME)
TARGET = aarch64-unknown-linux-gnu

build:
	cargo build --release --target $(TARGET)

deploy: build
	scp target/$(TARGET)/release/$(BINARY_NAME) $(REMOTE_USER)@$(REMOTE_HOST):$(REMOTE_PATH)
	ssh $(REMOTE_USER)@$(REMOTE_HOST) 'pkill -9 $(BINARY_NAME) || true'
	ssh $(REMOTE_USER)@$(REMOTE_HOST) 'nohup $(REMOTE_PATH) > /var/log/$(BINARY_NAME).log 2>&1 &'
	@echo "Deployed $(BINARY_NAME) to $(REMOTE_HOST)"

clean:
	cargo clean
