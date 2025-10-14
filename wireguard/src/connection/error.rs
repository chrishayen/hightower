#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    HandshakeFailed(String),
    EncryptionFailed,
    DecryptionFailed,
    ConnectionClosed,
    NoSession,
    NoEndpoint,
    ActorShutdown,
    ProtocolError(String),
    AlreadyRekeying,
    NotRekeying,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {}", e),
            Error::HandshakeFailed(msg) => write!(f, "Handshake failed: {}", msg),
            Error::EncryptionFailed => write!(f, "Encryption failed"),
            Error::DecryptionFailed => write!(f, "Decryption failed"),
            Error::ConnectionClosed => write!(f, "Connection closed"),
            Error::NoSession => write!(f, "No session found"),
            Error::NoEndpoint => write!(f, "No endpoint available"),
            Error::ActorShutdown => write!(f, "Actor has shut down"),
            Error::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
            Error::AlreadyRekeying => write!(f, "Already rekeying"),
            Error::NotRekeying => write!(f, "Not in rekey state"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}
