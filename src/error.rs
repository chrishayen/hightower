use std::io;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("feature unimplemented: {0}")]
    Unimplemented(&'static str),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
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
