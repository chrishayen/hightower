use std::error::Error;
use std::fmt;

/// Errors that can occur during Hightower client operations
///
/// These errors cover the full lifecycle of a connection: from initial configuration
/// validation, through network discovery and gateway registration, to transport
/// operations and storage management.
#[derive(Debug)]
pub enum ClientError {
    /// Invalid configuration provided (e.g., empty gateway URL, missing auth token)
    ///
    /// This error occurs before any network operations are attempted.
    /// Common causes:
    /// - Empty gateway_url or auth_token
    /// - Malformed URLs (missing http:// or https://)
    /// - Invalid bind addresses
    Configuration(String),

    /// HTTP request to gateway failed
    ///
    /// Wraps reqwest errors that occur during communication with the gateway API.
    /// Common causes:
    /// - Network connectivity issues
    /// - DNS resolution failures
    /// - TLS handshake failures
    /// - Connection timeouts
    Request(reqwest::Error),

    /// Gateway returned an error response
    ///
    /// The gateway API is reachable but returned an error status code.
    /// Common causes:
    /// - Invalid authentication token (401)
    /// - Endpoint not found (404)
    /// - Gateway at capacity (503)
    /// - Malformed request data (400)
    GatewayError {
        /// HTTP status code returned by gateway
        status: u16,
        /// Error message from gateway response body
        message: String
    },

    /// Gateway response was not in the expected format
    ///
    /// The gateway returned a 2xx status but the response body couldn't be parsed.
    /// This usually indicates a version mismatch between client and gateway.
    InvalidResponse(String),

    /// Failed to discover network information via STUN
    ///
    /// Network discovery is required for NAT traversal.
    /// Common causes:
    /// - STUN server unreachable
    /// - Firewall blocking UDP traffic
    /// - No internet connectivity
    /// - STUN server returned malformed response
    NetworkDiscovery(String),

    /// WireGuard transport operation failed
    ///
    /// Covers errors in WireGuard connection setup, peer management, or data transfer.
    /// Common causes:
    /// - Failed to bind UDP socket
    /// - Failed to add peer to WireGuard config
    /// - Connection handshake timeout
    /// - Invalid cryptographic keys
    Transport(String),

    /// Connection storage operation failed
    ///
    /// Errors related to persisting or loading connection state from disk.
    /// Common causes:
    /// - Insufficient disk space
    /// - Permission denied on storage directory
    /// - Corrupted storage files
    /// - Invalid stored key format
    Storage(String),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Configuration(msg) => write!(f, "configuration error: {}", msg),
            ClientError::Request(err) => write!(f, "request error: {}", err),
            ClientError::GatewayError { status, message } => {
                write!(f, "gateway error (status {}): {}", status, message)
            }
            ClientError::InvalidResponse(msg) => write!(f, "invalid response: {}", msg),
            ClientError::NetworkDiscovery(msg) => write!(f, "network discovery failed: {}", msg),
            ClientError::Transport(msg) => write!(f, "transport error: {}", msg),
            ClientError::Storage(msg) => write!(f, "storage error: {}", msg),
        }
    }
}

impl Error for ClientError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ClientError::Request(err) => Some(err),
            _ => None,
        }
    }
}

impl From<reqwest::Error> for ClientError {
    fn from(err: reqwest::Error) -> Self {
        ClientError::Request(err)
    }
}
