# Mirrors Platform/portal's makefile so deploys look the same across services.
APP_NAME = ais_domains
BIN_NAME = ais_domains
BIN_DIR = /opt/artisan/bin

build:
	cargo build --release

test:
	cargo test

# Install and restart the service.
install: build
	@echo "Installing binary..."
	@systemctl stop $(APP_NAME) || true
	install -m 0755 target/release/$(BIN_NAME) $(BIN_DIR)/$(APP_NAME)
	@systemctl start $(APP_NAME)

# Install without touching the running service.
install_safe: build
	install -m 0755 target/release/$(BIN_NAME) $(BIN_DIR)/$(APP_NAME)

# Apply database migrations without starting the service.
migrate:
	cargo run --release -- migrate

clean:
	cargo clean

# Dev-only: refreshes the vendored proto from the sibling ais_auth checkout.
# Not part of build/install -- production builds compile the local copy as-is,
# with no dependency on ais_auth's source being present.
sync-proto:
	cp ../ais_auth/proto/accounts.proto proto/accounts.proto

.PHONY: build test install install_safe migrate clean sync-proto
