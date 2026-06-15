# Hightower

Hightower is a Rust workspace for building an app-level mesh network: applications register with a gateway, exchange endpoint metadata and public keys, discover local/STUN candidates, and open encrypted peer streams without depending on kernel-level routes for virtual IPs.

The project is inspired by Tailscale's logical components, but it operates at the application layer instead of creating a host-wide network interface.

## What is in this repo

| Crate | Purpose |
| --- | --- |
| `hightower-cli` / `ht` | Command-line entry point for running services, querying STUN, and curling peer apps through Hightower. |
| `hightower-client` | Library that apps import to register with a gateway, persist identity, resolve peers, and dial encrypted streams. |
| `hightower-gateway` | Coordination server for auth, endpoint registration, virtual IP assignment, key sharing, candidate exchange, and connection intents. |
| `hightower-stun` | Lightweight RFC 8489 STUN client/server for discovering public UDP mappings. |
| `hightower-wireguard` | WireGuard-like Noise_IK transport and stream layer used for encrypted app-level sessions. |
| `hightower-kv` | Embedded log-structured KV store used by gateway/node services. |
| `hightower-node` | Node service wrapper around gateway/client context. |
| `hightower-mdns` | Local-network mDNS discovery utilities. |
| `hightower-naming` | Human-readable endpoint name generation. |
| `hightower-cnet` | Experimental connection/network utility binary. |

## Current architecture

```text
Application
  |
  | imports hightower-client
  v
Hightower client
  |-- creates/restores WireGuard-style keypair
  |-- opens UDP transport socket
  |-- discovers local + STUN public endpoint candidates
  |-- registers endpoint metadata with gateway
  |-- creates connection intents before dialing peers
  v
Gateway coordination API
  |-- authenticates clients
  |-- assigns logical 100.64.x.x identities
  |-- stores endpoint public keys and candidates
  |-- shares initiator/target metadata for authorized sessions
  v
Encrypted app-level peer stream
  |-- selects a real SocketAddr candidate
  |-- performs WireGuard-like handshake
  |-- carries app bytes over the selected UDP path
```

Virtual IPs are logical identities. They are useful for lookup and stable addressing, but the client ultimately dials real socket candidates such as LAN addresses, STUN public mappings, or future relay addresses.

## Status

The main branch includes the first app-level virtual-network path:

- endpoint registration with candidate lists;
- local/STUN public candidate discovery using the actual transport socket;
- gateway lookup by endpoint ID or assigned virtual IP;
- connection-intent API so the responder can learn and authorize the initiator before handshakes arrive;
- NAT punch probe plumbing for public/hole-punch candidates;
- `HightowerConnection::dial(peer, port)` for opening encrypted app-level streams;
- CLI `ht curl` path that resolves a Hightower peer and sends an HTTP request over the app-level stream.

Still planned / incomplete:

- robust NAT-to-NAT validation across two truly NATed peers;
- relay fallback for networks where UDP hole punching fails;
- stronger production packaging/configuration docs;
- polished public API ergonomics around services/ports and listener dispatch.

## Requirements

- Rust 2021 toolchain
- `cargo`
- GNU Make for the provided `Makefile` targets

Optional tools:

- `cross` for cross-compilation targets
- `cargo-deb`, `cargo-generate-rpm`, or `cargo-aur` for package generation

## Build and test

```bash
# Build everything in debug mode
cargo build --workspace

# Run the full test suite
cargo test --workspace

# Or use the Makefile wrappers
make build-debug
make test
```

Release build:

```bash
make build
# or
cargo build --release --workspace
```

Install the CLI locally:

```bash
make install
# installs ht under ~/.local/bin
```

## Running a local gateway

For local development, run the gateway with HTTP enabled on port `8008`:

```bash
HT_AUTH_KEY=test-auth-key \
HT_DEFAULT_USER=admin \
HT_DEFAULT_PASSWORD=local-admin-password \
DISABLE_HTTPS=true \
HTTP_PORT=8008 \
RUST_LOG=debug \
cargo run -p hightower-gateway
```

Equivalent Make target:

```bash
make gateway-dev
```

The gateway exposes:

- registration and lookup APIs under `/api/endpoints`;
- connection intent APIs under `/api/connections`;
- a server-rendered web console for login, dashboard, endpoints, and settings.

## Running a STUN server

```bash
cargo run -p hightower-cli --bin ht -- stun-server --bind 0.0.0.0:3478
```

Query a STUN server:

```bash
cargo run -p hightower-cli --bin ht -- stun 127.0.0.1:3478
```

Clients can override the STUN server used for candidate discovery:

```bash
export HT_STUN_SERVER=stun.example.com:3478
```

## Using the client library

Add the client crate to an application in this workspace or depend on the published crate when available:

```toml
[dependencies]
hightower-client = "0.1"
tokio = { version = "1", features = ["full"] }
```

Minimal example:

```rust
use hightower_client::HightowerConnection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let conn = HightowerConnection::connect(
        "http://127.0.0.1:8008",
        "test-auth-key",
    )
    .await?;

    println!("endpoint_id={}", conn.endpoint_id());
    println!("assigned_ip={}", conn.assigned_ip());

    // Dial by endpoint ID or assigned virtual IP. The port is the app-level
    // service port requested through the gateway connection intent.
    let mut stream = conn.dial("ht-example-peer", 8080).await?;
    stream.send(b"hello").await?;

    conn.disconnect().await?;
    Ok(())
}
```

Connection identity is persisted by default, so reconnecting to the same gateway reuses stored keys and endpoint identity until `disconnect()` removes the stored registration.

## CLI examples

Fetch a path from a registered Hightower peer:

```bash
export HIGHTOWER_AUTH_TOKEN=test-auth-key
ht curl http://ht-example-peer:8080/health \
  --gateway http://127.0.0.1:8008 \
  --verbose
```

Run the E2E echo example in two terminals:

```bash
# terminal 1: listener
export HT_AUTH_TOKEN=test-auth-key
export HT_GATEWAY_URL=http://127.0.0.1:8008
cargo run -p hightower-client --example e2e_echo -- listen

# terminal 2: dialer, using endpoint ID printed by terminal 1
export HT_AUTH_TOKEN=test-auth-key
export HT_GATEWAY_URL=http://127.0.0.1:8008
cargo run -p hightower-client --example e2e_echo -- dial <endpoint-id>
```

## Important environment variables

| Variable | Used by | Purpose |
| --- | --- | --- |
| `HT_AUTH_KEY` | gateway/node dev flows | Bootstrap/root API auth key. |
| `HIGHTOWER_AUTH_TOKEN` | `ht curl` | Auth token for CLI peer fetches. |
| `HT_AUTH_TOKEN` | client examples | Auth token for example clients. |
| `HT_GATEWAY_URL` | client examples/node/cnet | Gateway URL, usually `http://127.0.0.1:8008` in development. |
| `HT_STUN_SERVER` | client | STUN server override for candidate discovery. |
| `HTTP_PORT` | gateway | HTTP listen port. |
| `DISABLE_HTTPS` | gateway | Set `true` for local HTTP-only development. |
| `RUST_LOG` | all services | Logging level/filter. |

## Development notes

- Prefer `cargo test --workspace` before pushing changes.
- `cargo fmt --all` may require a properly configured rustup/cargo-fmt installation depending on the host.
- The app-level mesh code intentionally treats `100.64.x.x` addresses as logical identities, not OS-routable destinations.
- Full relay support is not implemented yet; current peer connectivity depends on local/public candidate success and NAT behavior.

## License

MIT. See crate-level `LICENSE` files.
