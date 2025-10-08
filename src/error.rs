use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum ClientError {
    Configuration(String),
    Request(reqwest::Error),
    GatewayError { status: u16, message: String },
    InvalidResponse(String),
    NetworkDiscovery(String),
    Transport(String),
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
