use std::io;

use thiserror::Error;

/// Result type alias using the crate's Error type
pub type Result<T> = std::result::Result<T, Error>;

/// Error types for the key-value store
#[derive(Debug, Error)]
pub enum Error {
    /// Feature not yet implemented
    #[error("feature unimplemented: {0}")]
    Unimplemented(&'static str),
    /// Validation failed for input data
    #[error("validation failed: {0}")]
    Validation(&'static str),
    /// Conflict occurred (e.g., duplicate key)
    #[error("conflict: {0}")]
    Conflict(&'static str),
    /// Requested item was not found
    #[error("not found: {0}")]
    NotFound(&'static str),
    /// Internal invariant was violated
    #[error("invariant violated: {0}")]
    Invariant(&'static str),
    /// Cryptographic operation failed
    #[error("crypto error: {0}")]
    Crypto(String),
    /// I/O operation failed
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    /// Serialization or deserialization failed
    #[error("serialization error: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn unimplemented_error_message_is_stable() {
        let err = Error::Unimplemented("test");
        assert_eq!(format!("{err}"), "feature unimplemented: test");
    }

    #[test]
    fn validation_error_message_is_stable() {
        let err = Error::Validation("missing field");
        assert_eq!(format!("{err}"), "validation failed: missing field");
    }

    #[test]
    fn conflict_error_message_is_stable() {
        let err = Error::Conflict("duplicate");
        assert_eq!(format!("{err}"), "conflict: duplicate");
    }

    #[test]
    fn not_found_error_message_is_stable() {
        let err = Error::NotFound("missing");
        assert_eq!(format!("{err}"), "not found: missing");
    }

    #[test]
    fn invariant_error_message_is_stable() {
        let err = Error::Invariant("stale");
        assert_eq!(format!("{err}"), "invariant violated: stale");
    }

    #[test]
    fn crypto_error_message_is_stable() {
        let err = Error::Crypto("boom".into());
        assert_eq!(format!("{err}"), "crypto error: boom");
    }

    #[test]
    fn io_error_display_is_prefixed() {
        let err = Error::Io(io::Error::new(io::ErrorKind::Other, "oops"));
        assert!(format!("{err}").contains("io error: oops"));
    }

    #[test]
    fn serialization_error_display_is_prefixed() {
        let err = Error::Serialization("bad".into());
        assert_eq!(format!("{err}"), "serialization error: bad");
    }
}
