# TODO

## Thread Safety

- KVStore is now thread-safe with mutex protection on all operations
- Gateway HTTP server is currently single-threaded (handles requests sequentially)
- Future work: Make HTTP handler concurrent for better performance
  - Consider thread pool for handling multiple requests in parallel
  - Current mutex implementation will protect against race conditions
- Future work: Distributed Raft setup for multi-node gateway
  - Current single-node Raft acts as write-ahead log
  - Multi-node setup would provide true distributed consensus

## Authentication

- Gateway now uses KV-based API key authentication
- Initial auth key (via --default-auth-key or HT_DEFAULT_AUTH) is saved as API key on first run
- API keys are associated with users and support:
  - Expiration dates
  - Last used tracking
  - Metadata
  - Revocation
- Timing-safe comparison prevents timing attacks

## Peer Registration

- Registration endpoint validates API keys via KV store
- Peer information is logged but not yet persisted to KV store
- Future work: Store peer information for coordination between peers
- Future work: Implement peer discovery and public key sharing
