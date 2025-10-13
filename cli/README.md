# Hightower

Hightower CLI - WireGuard networking toolkit with STUN server, gateway, and peer connection utilities.

## Installation

```bash
cargo install hightower
```

Or build from source:

```bash
git clone https://github.com/chrishayen/hightower.git
cd hightower
make install
```

## Binaries

### ht

The main Hightower CLI tool with multiple subcommands:

```bash
# Run STUN server
ht stun --bind 0.0.0.0:3478

# Run gateway server
ht gateway

# Run node client
ht node
```

### Fetch content from peers

Fetch content from WireGuard peer endpoints via Hightower gateway:

```bash
# Basic usage
ht curl http://<peer-ip>/endpoint --auth-token YOUR_TOKEN

# Specify custom gateway
ht curl http://<peer-ip>/endpoint --gateway http://localhost:8008 --auth-token YOUR_TOKEN

# Verbose output
ht curl http://<peer-ip>/endpoint --auth-token YOUR_TOKEN --verbose
```

You can also set the auth token via environment variable:

```bash
export HIGHTOWER_AUTH_TOKEN=your_token
ht curl http://<peer-ip>/endpoint
```

## License

MIT
