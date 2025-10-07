use std::io;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    InvalidAddress(String),
    InvalidNetwork(String),
    HandshakeFailed(String),
    EncryptionFailed,
    DecryptionFailed,
    PeerNotFound,
    ConnectionClosed,
    ListenerClosed,
    ProtocolError(String),
    Timeout,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {}", e),
            Error::InvalidAddress(addr) => write!(f, "Invalid address: {}", addr),
            Error::InvalidNetwork(net) => write!(f, "Invalid network type: {}", net),
            Error::HandshakeFailed(msg) => write!(f, "Handshake failed: {}", msg),
            Error::EncryptionFailed => write!(f, "Encryption failed"),
            Error::DecryptionFailed => write!(f, "Decryption failed"),
            Error::PeerNotFound => write!(f, "Peer not found"),
            Error::ConnectionClosed => write!(f, "Connection closed"),
            Error::ListenerClosed => write!(f, "Listener closed"),
            Error::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
            Error::Timeout => write!(f, "Operation timed out"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}
