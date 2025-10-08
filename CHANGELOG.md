# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2025-10-08

### Added
- **Connection persistence**: Connections are now automatically persisted to `~/.hightower/gateway/<gateway>/` by default
- Stored connections automatically restore on reconnect, maintaining the same WireGuard identity and node ID
- New connection methods:
  - `connect_ephemeral()` - connect without persistence
  - `connect_with_storage()` - use custom storage directory
  - `connect_fresh()` - force new registration, bypassing stored connection
- Storage module using `hightower-kv` for reliable key-value persistence
- New examples:
  - `connection_persistence.rs` - demonstrates connection restoration across restarts
  - `storage_modes.rs` - shows all available storage modes
- Gateway-specific storage directories (different gateways have separate storage)
- Filesystem-safe URL sanitization for storage directory names
- `Storage(String)` error variant for storage-related errors

### Changed
- Default `connect()` and `connect_with_auth_token()` now include automatic persistence
- Storage location structure: `~/.hightower/gateway/<sanitized-gateway-url>/`
- Examples updated to support `HT_GATEWAY_URL` environment variable

### Technical Details
- Dependencies added: `hightower-kv = "0.1.3"`, `sha2 = "0.10"`
- Storage uses log-structured KV engine with O(1) lookups
- Connection state includes: node_id, token, WireGuard keys, assigned IP, timestamps
- Storage operations are gracefully degraded - connection continues without persistence if storage fails

## [0.1.0] - 2025-10-03

### Added
- Initial release
- Integrated WireGuard transport with automatic setup
- Automatic network discovery via STUN
- Gateway registration and deregistration
- Connection management with `HightowerConnection`
- Support for custom gateway URLs
- Automatic peer configuration
- Examples: simple_register, simple_deregister, https_gateway, custom_endpoint, remote_gateway
- Comprehensive error handling with `ClientError`
- Full test suite
