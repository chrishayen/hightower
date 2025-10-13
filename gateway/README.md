# Hightower Gateway

Gateway service for the Hightower project.

## Building

```bash
cargo build
```

## Running

Using the Makefile (recommended):

```bash
make dev
```

Or directly with cargo:

```bash
HT_AUTH_KEY=test-auth-key cargo run
```

## Testing

```bash
make test
# or
cargo test
```

## Configuration

The gateway can be configured using environment variables:

- `HT_AUTH_KEY` - Authentication key for the gateway (required)
- `HT_DEFAULT_USER` - Default admin username (default: `admin`)
- `HT_DEFAULT_PASSWORD` - Default admin password (default: `admin`)
- `RUST_LOG` - Log level (default: `info`, use `debug` for verbose output)

## Key-Value Store

By default, the gateway uses a temporary directory for the KV store. To use a persistent directory:

```bash
cargo run -- --kv /path/to/store
```

## Web Console

The web console is rendered server-side using Askama templates located in the `templates/` directory:

- `templates/login.html` - Login page
- `templates/dashboard.html` - Dashboard page
- `templates/login_alert.html` - Login alert fragment
- `templates/nodes_table.html` - Nodes table fragment

The templates compile with the Rust code, so no separate build step is needed.
