use crate::common::CommonContext;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::runtime::Builder;
use tracing::{debug, error, info};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const API_ADDRESS: &str = "0.0.0.0:8008";

static API_LAUNCH: OnceLock<()> = OnceLock::new();

pub fn run(_context: &CommonContext) {
    info!("Root API starting");

    API_LAUNCH.get_or_init(|| {
        thread::Builder::new()
            .name("root-api".into())
            .spawn(|| {
                let runtime = Builder::new_multi_thread()
                    .worker_threads(1)
                    .enable_all()
                    .build()
                    .expect("root api runtime");

                runtime.block_on(async {
                    if let Err(err) = start_server().await {
                        error!(?err, "Root API server terminated unexpectedly");
                    }
                });
            })
            .expect("spawn root api thread");
    });
}

async fn start_server() -> Result<(), BoxError> {
    let addr: SocketAddr = API_ADDRESS.parse().expect("valid socket address");
    let app = Router::new().route("/", get(root_health));
    let listener = TcpListener::bind(addr).await?;

    info!(address = %addr, "Root API ready");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn root_health(_request: Request<Body>) -> StatusCode {
    StatusCode::OK
}

pub fn wait_until_ready(timeout: Duration) -> Result<(), WaitForRootError> {
    let start = Instant::now();
    let readiness_addr = readiness_address();
    let request_bytes = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    const ATTEMPT_TIMEOUT: Duration = Duration::from_millis(200);
    let mut attempts: u32 = 0;

    debug!(address = %readiness_addr, ?timeout, "Waiting for root API readiness");

    loop {
        attempts = attempts.saturating_add(1);
        match TcpStream::connect_timeout(&readiness_addr, ATTEMPT_TIMEOUT) {
            Ok(mut stream) => {
                debug!(attempt = attempts, "Connected to root API socket");
                stream.set_read_timeout(Some(ATTEMPT_TIMEOUT))?;
                stream.set_write_timeout(Some(ATTEMPT_TIMEOUT))?;
                stream.write_all(request_bytes)?;

                let mut buf = [0u8; 64];
                match stream.read(&mut buf) {
                    Ok(0) => {
                        // Connection closed before a response; treat as not ready yet.
                        debug!(
                            attempt = attempts,
                            "Root API closed connection before responding"
                        );
                    }
                    Ok(read) => {
                        let response = std::str::from_utf8(&buf[..read]).unwrap_or("");
                        if response.starts_with("HTTP/1.1 200")
                            || response.starts_with("HTTP/1.0 200")
                        {
                            info!(attempt = attempts, "Root API ready");
                            return Ok(());
                        }

                        return Err(WaitForRootError::InvalidResponse(
                            response.lines().next().unwrap_or(response).to_string(),
                        ));
                    }
                    Err(err) if is_transient_read_error(&err) => {
                        // Retry while the API finishes booting.
                        debug!(attempt = attempts, error = %err, "Root API read transient error");
                    }
                    Err(err) => return Err(err.into()),
                }
            }
            Err(err) if is_transient_connect_error(&err) => {
                // Retry while the API finishes binding the socket.
                debug!(attempt = attempts, error = %err, "Root API not accepting connections yet");
            }
            Err(err) => return Err(err.into()),
        }

        if start.elapsed() >= timeout {
            return Err(WaitForRootError::Timeout(timeout));
        }

        debug!(
            attempt = attempts,
            "Root API not ready yet; sleeping before retry"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn readiness_address() -> SocketAddr {
    let bound_addr: SocketAddr = API_ADDRESS.parse().expect("valid socket address");
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
    use crate::kv;
    use std::time::Duration;
    use tempfile::TempDir;

    #[test]
    fn run_logs_message() {
        let temp = TempDir::new().expect("tempdir");
        let kv = kv::initialize(Some(temp.path())).expect("kv init");
        let ctx = CommonContext::new(kv);
        run(&ctx);

        wait_until_ready(Duration::from_secs(1)).expect("root ready");
    }

    #[tokio::test]
    async fn root_health_returns_ok() {
        let request = Request::builder()
            .method("GET")
            .uri("/")
            .body(Body::empty())
            .expect("request");
        assert_eq!(root_health(request).await, StatusCode::OK);
    }
}
