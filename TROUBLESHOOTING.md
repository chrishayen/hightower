# Hightower Troubleshooting Guide

This guide covers common issues, error scenarios, and their solutions when working with Hightower.

## Table of Contents
- [Client Errors](#client-errors)
- [Gateway Errors](#gateway-errors)
- [Network Discovery Issues](#network-discovery-issues)
- [WireGuard Transport Issues](#wireguard-transport-issues)
- [Storage Issues](#storage-issues)
- [Peer-to-Peer Connection Issues](#peer-to-peer-connection-issues)
- [Debugging Techniques](#debugging-techniques)

## Client Errors

### Configuration Errors

#### `gateway_url cannot be empty`
**Cause**: No gateway URL provided when calling `HightowerConnection::connect()`.

**Solution**:
```rust
// Wrong
let conn = HightowerConnection::connect("", "token").await?;

// Correct
let conn = HightowerConnection::connect("http://gateway.example.com:8008", "token").await?;
```

#### `gateway_url must start with http:// or https://`
**Cause**: Gateway URL is missing the scheme.

**Solution**:
```rust
// Wrong
let conn = HightowerConnection::connect("gateway.example.com:8008", "token").await?;

// Correct
let conn = HightowerConnection::connect("http://gateway.example.com:8008", "token").await?;
```

**Reference**: client/src/connection.rs:540-547

#### `auth_token cannot be empty`
**Cause**: No authentication token provided.

**Solution**:
```bash
# Set environment variable
export HT_AUTH_TOKEN="your-token-here"

# Or pass directly in code
let conn = HightowerConnection::connect(gateway_url, "your-token-here").await?;
```

### Request Errors

#### Connection Refused
**Error**: `Request(reqwest::Error { kind: Connect, ... })`

**Common Causes**:
1. Gateway is not running
2. Wrong port number
3. Firewall blocking connection

**Solutions**:
```bash
# 1. Check if gateway is running
curl http://localhost:8008/api/health

# 2. Verify gateway is listening on expected port
netstat -an | grep 8008

# 3. Check firewall rules (Linux)
sudo iptables -L -n | grep 8008

# 4. Start the gateway if not running
HT_AUTH_KEY=test-auth-key cargo run --bin ht gateway
```

#### DNS Resolution Failure
**Error**: `Request(reqwest::Error { kind: Connect, message: "dns error" })`

**Solutions**:
```bash
# 1. Verify DNS resolution
nslookup gateway.example.com

# 2. Try using IP address instead
let conn = HightowerConnection::connect("http://192.168.1.100:8008", "token").await?;

# 3. Check /etc/resolv.conf (Linux)
cat /etc/resolv.conf
```

#### TLS Handshake Failure
**Error**: `Request(reqwest::Error { kind: Connect, message: "tls handshake" })`

**Common Causes**:
1. Self-signed certificate
2. Certificate expired
3. Certificate hostname mismatch

**Solutions**:
```bash
# 1. Use HTTP instead of HTTPS for testing
let conn = HightowerConnection::connect("http://gateway.example.com:8008", "token").await?;

# 2. Verify certificate
openssl s_client -connect gateway.example.com:8443 -servername gateway.example.com

# 3. Check certificate validity
curl -v https://gateway.example.com:8443/api/health
```

### Gateway Errors

#### 401 Unauthorized
**Error**: `GatewayError { status: 401, message: "Unauthorized" }`

**Cause**: Invalid or missing authentication token.

**Solutions**:
```bash
# 1. Verify token is correct
echo $HT_AUTH_TOKEN

# 2. Check gateway configuration
# Gateway expects X-HT-Auth header to match HT_AUTH_KEY environment variable

# 3. Regenerate token if needed (on gateway host)
# The token should match the value of HT_AUTH_KEY when starting the gateway
```

**Reference**: gateway/src/api/mod.rs (authentication middleware)

#### 404 Not Found
**Error**: `GatewayError { status: 404, message: "Endpoint not found" }`

**Common Scenarios**:
1. Querying peer that doesn't exist
2. Using wrong endpoint ID format
3. Peer has disconnected

**Solutions**:
```rust
// 1. Verify endpoint ID format (should be like "ht-festive-penguin-abc123")
let peer_info = conn.get_peer_info("ht-festive-penguin-abc123").await?;

// 2. Try querying by IP instead
let peer_info = conn.get_peer_info("100.64.0.5").await?;

// 3. List all endpoints via gateway web console
// Navigate to http://gateway:8008 in browser
```

#### 503 Service Unavailable
**Error**: `GatewayError { status: 503, message: "Gateway at capacity" }`

**Cause**: Gateway has reached maximum concurrent connections or IP exhaustion.

**Solutions**:
1. Check gateway logs for resource issues
2. Increase gateway resources (CPU, memory)
3. Check IP allocation range (gateway/src/ip_allocator.rs)

## Network Discovery Issues

### STUN Server Unreachable
**Error**: `NetworkDiscovery("failed to discover network info via STUN")`

**Common Causes**:
1. STUN server is down
2. Firewall blocking UDP port 3478
3. No internet connectivity

**Solutions**:
```bash
# 1. Test STUN server connectivity
nc -u stun.l.google.com 3478

# 2. Try different STUN server
# Edit client/src/ip_discovery.rs or pass custom STUN server

# 3. Check firewall rules for UDP
sudo iptables -L -n | grep udp

# 4. Verify internet connectivity
ping 8.8.8.8
```

**Reference**: client/src/ip_discovery.rs:14-40

### Malformed STUN Response
**Error**: `NetworkDiscovery("invalid STUN response")`

**Cause**: STUN server returned unexpected data.

**Solutions**:
1. Use a well-known public STUN server (Google, Cloudflare)
2. Run your own STUN server: `cargo run --bin ht stun-server`
3. Check network for STUN packet manipulation

**Debugging**:
```bash
# Enable debug logging
RUST_LOG=debug cargo run --example simple_register
```

## WireGuard Transport Issues

### Failed to Bind UDP Socket
**Error**: `Transport("failed to create transport connection: bind failed")`

**Common Causes**:
1. Port already in use (rare since we use 0.0.0.0:0)
2. Permission denied
3. System resource limits

**Solutions**:
```bash
# 1. Check for port conflicts (if binding to specific port)
netstat -an | grep :51820

# 2. Verify user has permission to bind sockets
# No special privileges needed for ephemeral ports

# 3. Check system limits
ulimit -n  # File descriptor limit
```

### Failed to Add Peer
**Error**: `Transport("failed to add peer: invalid public key")`

**Common Causes**:
1. Corrupted public key from gateway
2. Invalid hex encoding
3. Wrong key format (not 32 bytes)

**Solutions**:
```bash
# 1. Verify public key format (should be 64 hex chars = 32 bytes)
echo "036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe34213c3eec785f1c12" | wc -c
# Should output 65 (64 chars + newline)

# 2. Check gateway response
curl -H "X-HT-Auth: your-token" http://gateway:8008/api/endpoints/id/ht-example-abc123
```

**Reference**: client/src/connection.rs:459-472

### Connection Handshake Timeout
**Error**: `Transport("failed to connect to peer: handshake timeout")`

**Common Causes**:
1. Peer is offline
2. NAT traversal failed
3. Firewall blocking WireGuard packets
4. Incorrect peer endpoint information

**Solutions**:
```bash
# 1. Verify peer is online via gateway API
curl -H "X-HT-Auth: token" http://gateway:8008/api/endpoints/id/peer-id

# 2. Check UDP connectivity to peer's public endpoint
# (if known from peer info)
nc -u peer_public_ip peer_public_port

# 3. Try connecting via assigned IP instead
# The gateway should relay traffic if direct connection fails

# 4. Enable WireGuard debug logging
RUST_LOG=wireguard=debug,hightower_client=debug cargo run
```

**Reference**: wireguard/src/connection.rs (handshake timeout is typically 5-10 seconds)

## Storage Issues

### Permission Denied
**Error**: `Storage("permission denied: ~/.hightower/gateway/example.com")`

**Cause**: Cannot write to storage directory.

**Solutions**:
```bash
# 1. Check directory permissions
ls -la ~/.hightower/

# 2. Create directory with correct permissions
mkdir -p ~/.hightower
chmod 700 ~/.hightower

# 3. Use ephemeral mode if persistence is not needed
let conn = HightowerConnection::connect_ephemeral(gateway_url, token).await?;
```

### Corrupted Storage File
**Error**: `Storage("invalid stored key format")`

**Cause**: Storage file was corrupted or modified externally.

**Solutions**:
```bash
# 1. Delete corrupted storage
rm -rf ~/.hightower/gateway/example.com/

# 2. Force fresh connection
let conn = HightowerConnection::connect_fresh(gateway_url, token).await?;

# 3. Backup and inspect storage file
cat ~/.hightower/gateway/example.com/connection.json | jq .
```

**Reference**: client/src/storage.rs:67-120

### Insufficient Disk Space
**Error**: `Storage("failed to persist connection: No space left on device")`

**Solutions**:
```bash
# 1. Check disk space
df -h ~

# 2. Clean up old storage
du -sh ~/.hightower/gateway/*
rm -rf ~/.hightower/gateway/old-gateway.com/

# 3. Use ephemeral mode
let conn = HightowerConnection::connect_ephemeral(gateway_url, token).await?;
```

## Peer-to-Peer Connection Issues

### Peer Not Found
**Error**: `GatewayError { status: 404, message: "Endpoint not found" }`

**Solutions**:
```rust
// 1. Verify peer is registered
// Via gateway web console or API

// 2. Check endpoint ID spelling
let peer = "ht-festive-penguin-abc123"; // Correct format

// 3. Try using assigned IP instead of endpoint ID
let stream = conn.dial("100.64.0.5", 8080).await?;
```

### Connection Refused by Peer
**Error**: `Transport("connection refused")`

**Cause**: Peer is not listening on the specified port.

**Solutions**:
```rust
// 1. Verify peer is listening on the port
// On peer machine:
// let listener = conn.transport().server().listen(8080).await?;

// 2. Check port number
let stream = conn.dial("ht-peer-id", 8080).await?; // Correct port?

// 3. Verify peer's transport is active
// Peer must have an active HightowerConnection
```

### Invalid Peer Public Key
**Error**: `InvalidResponse("invalid peer public key hex")`

**Cause**: Gateway returned malformed public key for peer.

**Solutions**:
1. Report bug to gateway administrator
2. Check gateway version compatibility
3. Verify peer registered correctly

## Debugging Techniques

### Enable Debug Logging

```bash
# Full debug output
RUST_LOG=debug cargo run

# Component-specific logging
RUST_LOG=hightower_client=debug cargo run
RUST_LOG=wireguard=trace cargo run

# Multiple components
RUST_LOG=hightower_client=debug,wireguard=debug,reqwest=info cargo run
```

### Inspect Network Traffic

```bash
# Capture WireGuard traffic (UDP)
sudo tcpdump -i any -n udp port 51820

# Capture HTTP API traffic
sudo tcpdump -i any -A -n tcp port 8008

# Use Wireshark for detailed analysis
sudo wireshark
```

### Check Gateway State

```bash
# 1. Gateway health check
curl http://localhost:8008/api/health

# 2. List all registered endpoints (web console)
# Navigate to: http://localhost:8008
# Login with HT_DEFAULT_USER and HT_DEFAULT_PASSWORD

# 3. Query specific endpoint
curl -H "X-HT-Auth: your-token" \
  http://localhost:8008/api/endpoints/id/ht-festive-penguin-abc123
```

### Verify WireGuard Handshake

```rust
// After connecting, ping the gateway
let conn = HightowerConnection::connect(gateway_url, token).await?;

match conn.ping_gateway().await {
    Ok(()) => println!("WireGuard tunnel to gateway is working"),
    Err(e) => println!("WireGuard tunnel failed: {:?}", e),
}
```

**Reference**: client/src/connection.rs:346-383

### Test STUN Discovery

```bash
# Run STUN client example
cargo run --example get_public_ip

# Use external STUN test tool
stunclient stun.l.google.com
```

### Check Storage State

```bash
# View stored connection info
cat ~/.hightower/gateway/example.com/connection.json | jq .

# Expected format:
# {
#   "endpoint_id": "ht-festive-penguin-abc123",
#   "token": "...",
#   "gateway_url": "http://example.com:8008",
#   "assigned_ip": "100.64.0.5",
#   "private_key_hex": "...",
#   "public_key_hex": "...",
#   "gateway_public_key_hex": "...",
#   "created_at": 1234567890,
#   "last_connected_at": 1234567890
# }
```

### Test Minimal Connection

```bash
# Use simple_register example to isolate issues
export HT_AUTH_TOKEN="your-token"
export HT_GATEWAY_URL="http://localhost:8008"

cargo run --example simple_register
```

## Common Error Patterns

### Transient vs Persistent Errors

**Transient** (retry may help):
- Network timeouts
- Gateway temporarily unavailable (503)
- STUN server unreachable

**Persistent** (requires configuration change):
- Invalid auth token (401)
- Malformed gateway URL
- Storage permission denied
- Invalid public key format

### Error Recovery Strategies

```rust
use std::time::Duration;
use tokio::time::sleep;

// Retry transient errors with exponential backoff
async fn connect_with_retry(
    gateway_url: &str,
    token: &str,
    max_attempts: u32,
) -> Result<HightowerConnection, ClientError> {
    let mut attempt = 0;

    loop {
        attempt += 1;

        match HightowerConnection::connect(gateway_url, token).await {
            Ok(conn) => return Ok(conn),
            Err(e) => {
                if attempt >= max_attempts {
                    return Err(e);
                }

                // Retry on transient errors
                match &e {
                    ClientError::Request(_) |
                    ClientError::NetworkDiscovery(_) |
                    ClientError::GatewayError { status: 503, .. } => {
                        let delay = Duration::from_secs(2u64.pow(attempt));
                        eprintln!("Attempt {} failed: {:?}. Retrying in {:?}", attempt, e, delay);
                        sleep(delay).await;
                    }
                    _ => return Err(e), // Don't retry persistent errors
                }
            }
        }
    }
}
```

## Getting Help

### Collecting Debug Information

When reporting issues, include:

1. **Version information**:
```bash
cargo tree | grep hightower
```

2. **Full error output**:
```bash
RUST_LOG=debug cargo run 2>&1 | tee debug.log
```

3. **Environment**:
- OS and version
- Network setup (behind NAT? firewall?)
- Gateway version and configuration

4. **Minimal reproduction**:
```rust
// Smallest code example that reproduces the issue
use hightower_client::HightowerConnection;

#[tokio::main]
async fn main() {
    let conn = HightowerConnection::connect(
        "http://localhost:8008",
        "test-token"
    ).await.unwrap();
}
```

### Useful Log Patterns

```bash
# Search for errors in logs
grep -i error debug.log

# Find WireGuard handshake issues
grep -i handshake debug.log

# Check STUN discovery
grep -i stun debug.log

# Gateway registration
grep -i "register" debug.log
```

## Related Documentation

- [ARCHITECTURE.md](./ARCHITECTURE.md) - System architecture and data flows
- [Client README](./client/README.md) - Client library API documentation
- [Gateway README](./gateway/README.md) - Gateway configuration guide
- [WireGuard README](./wireguard/README.md) - WireGuard implementation details
