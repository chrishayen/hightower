/// Authentication service implementation.
pub mod auth_service;
/// Authentication-related types.
pub mod auth_types;
/// Command definitions for the key-value store.
pub mod command;
/// Background compaction coordinator.
pub mod compactor;
/// Configuration structures.
pub mod config;
/// Cryptographic utilities for hashing and encryption.
pub mod crypto;
/// Key-value engine traits and implementations.
pub mod engine;
/// Error types and result aliases.
pub mod error;
/// Distributed ID generation.
pub mod id_generator;
/// In-memory index for fast lookups.
pub mod index;
/// Log segment management.
pub mod log_segment;
/// Prefix index for efficient prefix queries.
pub mod prefix_index;
/// Metrics collection and reporting.
pub mod metrics;
/// Replication protocol implementation.
pub mod replication;
/// Snapshot persistence.
pub mod snapshot;
/// In-memory key-value state.
pub mod state;
/// Log-structured storage layer.
pub mod storage;

#[cfg(test)]
pub mod tests;

/// Re-export of the authentication service.
pub use auth_service::AuthService;
/// Re-export of the store configuration.
pub use config::StoreConfig;
/// Re-export of engine traits and implementations.
pub use engine::{KvEngine, SingleNodeEngine};
/// Re-export of error types.
pub use error::{Error, Result};
