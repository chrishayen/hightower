# hightower-node

Hightower node client - connects to a Hightower gateway and joins the mesh network.

## Usage

```bash
ht-node [OPTIONS]
```

### Options

- `--kv <DIR>` - Path to the key-value data directory (optional, defaults to temporary directory)

### Environment Variables

- `HT_AUTH_KEY` - **Required**. Authentication token for connecting to the gateway
- `RUST_LOG` - Log level (default: `info`). Example values: `debug`, `info`, `warn`, `error`
- `HT_DEFAULT_USER` - Default admin username (default: `admin`)
- `HT_DEFAULT_PASSWORD` - Default admin password (default: `admin`)

## Example

```bash
# Run with authentication token
HT_AUTH_KEY=your-auth-token ht-node

# Run with custom KV directory and debug logging
HT_AUTH_KEY=your-auth-token RUST_LOG=debug ht-node --kv /var/lib/hightower-node

# Run with custom gateway URL (stored in KV as gateway/url key)
HT_AUTH_KEY=your-auth-token ht-node --kv /path/to/data
```

## Building

```bash
cargo build --release
```

## Testing

```bash
cargo test
```
