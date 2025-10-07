# Changelog

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
