# Changelog

## [0.2.1] - 2025-10-11

### Changed
- **Major transport refactor**: Completely redesigned transport API for simplicity and ergonomics
  - Replaced `Server`, `Listener`, and `Conn` with streamlined `Connection` and `Stream` types
  - Consolidated implementation from multiple files into single `connection.rs` module
  - Flattened module structure: moved from `transport::` to root-level `connection::` module
- Improved session management with ability to remove sessions by public key
- Enhanced rekey behavior: only initiator triggers automatic session rekeying
- Added clearer debug tracing throughout transport layer

### Added
- Comprehensive test suite for transport layer including:
  - Connection lifecycle tests
  - Bidirectional communication tests
  - Multi-stream and concurrent connection tests
  - Edge case handling (empty messages, rapid bursts, varying sizes)
  - Error handling and timeout scenarios
  - Keep-alive and automatic rekey testing

### Fixed
- Memory leak in session management
- Session cleanup and timeout handling

## [0.1.3] - 2025-10-06

### Added
- Message serialization and deserialization support
  - `HandshakeInitiation::to_bytes()` and `HandshakeInitiation::from_bytes()` for 148-byte wire format
  - `HandshakeResponse::to_bytes()` and `HandshakeResponse::from_bytes()` for 92-byte wire format
  - `TransportData::to_bytes()` and `TransportData::from_bytes()` for variable-length wire format
- Comprehensive validation in deserialization methods
- Round-trip serialization tests for all message types

## [0.1.2] - 2025-10-04

### Added
- Initial WireGuard Noise_IK handshake implementation
- Core cryptographic primitives (X25519, ChaCha20-Poly1305, BLAKE2s, HKDF)
- Pre-shared key support
- Session management
- Protocol state machines for initiator and responder

## [0.1.1] - 2025-10-03

### Changed
- Documentation improvements

## [0.1.0] - 2025-10-02

### Added
- Initial release
