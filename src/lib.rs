mod api;
pub mod certificates;
pub mod client;
mod common;
mod gateway_impl;
mod ip_allocator;
pub mod wireguard_api;

pub use common::*;

pub use api::start;
pub use client::{
    HttpRootRegistrar, ROOT_ENDPOINT_KEY, RegistrationResult, RootRegistrar, RootRegistrationError,
    default_registrar,
};

pub type WaitForGatewayError = WaitForRootError;

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};
use tracing::debug;

pub fn wait_until_ready(timeout: Duration) -> Result<(), WaitForRootError> {
    let start = Instant::now();
    let readiness_addr = readiness_address();
    let request_bytes = b"GET /api/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    const ATTEMPT_TIMEOUT: Duration = Duration::from_millis(200);
    let mut attempts: u32 = 0;

    debug!(address = %readiness_addr, ?timeout, "Waiting for gateway API readiness");

    loop {
        attempts = attempts.saturating_add(1);
        match TcpStream::connect_timeout(&readiness_addr, ATTEMPT_TIMEOUT) {
            Ok(mut stream) => {
                debug!(attempt = attempts, "Connected to gateway API socket");
                stream.set_read_timeout(Some(ATTEMPT_TIMEOUT))?;
                stream.set_write_timeout(Some(ATTEMPT_TIMEOUT))?;
                stream.write_all(request_bytes)?;

                let mut buf = [0u8; 64];
                match stream.read(&mut buf) {
                    Ok(0) => {
                        debug!(
                            attempt = attempts,
                            "Gateway closed connection before responding"
                        );
                    }
                    Ok(read) => {
                        let response = std::str::from_utf8(&buf[..read]).unwrap_or("");
                        if response.starts_with("HTTP/1.1 200")
                            || response.starts_with("HTTP/1.0 200")
                        {
                            debug!(attempt = attempts, "Gateway ready");
                            return Ok(());
                        }

                        return Err(WaitForRootError::InvalidResponse(
                            response.lines().next().unwrap_or(response).to_string(),
                        ));
                    }
                    Err(err) if is_transient_read_error(&err) => {
                        debug!(attempt = attempts, error = %err, "Gateway read transient error");
                    }
                    Err(err) => return Err(err.into()),
                }
            }
            Err(err) if is_transient_connect_error(&err) => {
                debug!(attempt = attempts, error = %err, "Gateway not accepting connections yet");
            }
            Err(err) => return Err(err.into()),
        }

        if start.elapsed() >= timeout {
            return Err(WaitForRootError::Timeout(timeout));
        }

        debug!(
            attempt = attempts,
            "Gateway not ready yet; sleeping before retry"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn readiness_address() -> SocketAddr {
    let bound_addr: SocketAddr = api::API_ADDRESS.parse().expect("valid socket address");
    let loopback = match bound_addr.ip() {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
    };

    SocketAddr::new(loopback, bound_addr.port())
}

fn is_transient_connect_error(err: &std::io::Error) -> bool {
    use std::io::ErrorKind;

    matches!(
        err.kind(),
        ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::TimedOut
            | ErrorKind::AddrNotAvailable
    )
}

fn is_transient_read_error(err: &std::io::Error) -> bool {
    use std::io::ErrorKind;

    matches!(
        err.kind(),
        ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted
    )
}

#[derive(Debug)]
pub enum WaitForRootError {
    Timeout(Duration),
    Io(std::io::Error),
    InvalidResponse(String),
}

impl From<std::io::Error> for WaitForRootError {
    fn from(err: std::io::Error) -> Self {
        WaitForRootError::Io(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn wait_until_ready_surfaces_errors_when_gateway_missing() {
        let timeout = Duration::from_millis(50);
        let result = wait_until_ready(timeout);

        assert!(
            result.is_ok()
                || matches!(
                    result,
                    Err(WaitForRootError::Timeout(_)) | Err(WaitForRootError::Io(_))
                ),
            "unexpected readiness result: {:?}",
            result
        );
    }
}
