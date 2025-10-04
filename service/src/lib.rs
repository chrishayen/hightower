mod cli;
mod mode;
mod shutdown;

pub use cli::{Cli, ModeArg};
pub use mode::Mode;

use hightower_context::{self, CommonContext, ContextError, HT_AUTH_KEY};
use hightower_node;
use hightower_root::{self, WaitForRootError};
use std::error::Error;
use std::fmt;
use std::time::Duration;
use tracing::{debug, error, info};

pub fn run(cli: Cli) -> Result<(), AppError> {
    let mode = mode::resolve(&cli);
    let context = hightower_context::initialize_with_token_source(cli.kv.as_deref(), |key| {
        std::env::var(key)
    })
    .map_err(AppError::Context)?;

    run_mode(mode, &context)?;

    info!("Waiting for Ctrl-C to exit");
    shutdown::wait_for_ctrl_c().map_err(AppError::Shutdown)?;
    info!("Shutdown signal received");
    Ok(())
}

pub fn run_mode(mode: Mode, context: &CommonContext) -> Result<(), AppError> {
    match mode {
        Mode::Node => hightower_node::run(context),
        Mode::Root => hightower_root::start(context),
        Mode::Dev => run_dev_mode(context)?,
    }

    Ok(())
}

fn run_dev_mode(base_context: &CommonContext) -> Result<(), AppError> {
    let node_context = base_context.namespaced(b"node");
    let root_context = base_context.namespaced(b"root");

    replicate_token(base_context, &node_context);
    replicate_token(base_context, &root_context);

    debug!("Starting root API in dev mode");
    hightower_root::start(&root_context);
    let timeout = Duration::from_secs(5);

    debug!(?timeout, "Waiting for root API readiness in dev mode");
    match hightower_root::wait_until_ready(timeout) {
        Ok(()) => debug!("Root API readiness confirmed"),
        Err(err) => {
            match &err {
                WaitForRootError::Timeout(duration) => {
                    error!(
                        ?duration,
                        "Root API timed out before becoming ready in dev mode"
                    );
                }
                WaitForRootError::Io(io_err) => {
                    error!(error = %io_err, "Root API readiness check failed in dev mode");
                }
                WaitForRootError::InvalidResponse(line) => {
                    error!(%line, "Root API returned unexpected response during readiness check");
                }
            }
            return Err(AppError::RootReady(err));
        }
    }

    hightower_node::run(&node_context);
    Ok(())
}

fn replicate_token(source: &CommonContext, target: &CommonContext) {
    match source.kv.get_bytes(HT_AUTH_KEY) {
        Ok(Some(token)) => target.kv.put_secret(HT_AUTH_KEY, &token),
        Ok(None) => tracing::warn!("HT auth key missing; skipping namespace propagation"),
        Err(err) => tracing::error!(?err, "Failed to read HT auth key for namespace propagation"),
    }
}

#[derive(Debug)]
pub enum AppError {
    Context(ContextError),
    Shutdown(shutdown::ShutdownError),
    RootReady(WaitForRootError),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Context(err) => write!(f, "startup failed: {err}"),
            AppError::Shutdown(err) => write!(f, "shutdown failed: {err:?}"),
            AppError::RootReady(err) => write!(f, "root readiness failed: {err:?}"),
        }
    }
}

impl Error for AppError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mode::Mode;
    use hightower_context::{CommonContext, NODE_CERTIFICATE_KEY, NODE_NAME_KEY, initialize_kv};
    use hightower_node::NodeCertificate;
    use hightower_root_client::ROOT_ENDPOINT_KEY;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::time::Duration as StdDuration;
    use tempfile::TempDir;

    fn context() -> CommonContext {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        CommonContext::new(kv)
    }

    #[test]
    fn run_mode_invokes_node_mode() {
        let ctx = context();
        ctx.kv.put_secret(HT_AUTH_KEY, b"test-auth-key");

        run_mode(Mode::Node, &ctx).expect("node mode");
        let stored = ctx.kv.get_bytes(NODE_NAME_KEY).expect("kv read");
        assert!(stored.is_some());
    }

    #[test]
    fn run_mode_invokes_root_mode() {
        let ctx = context();
        ctx.kv.put_secret(HT_AUTH_KEY, b"test-auth-key");

        run_mode(Mode::Root, &ctx).expect("root mode");
    }

    #[test]
    fn run_mode_invokes_dev_mode_with_prefixed_keys() {
        let _guard = hightower_logging::init();
        let ctx = context();
        ctx.kv.put_secret(HT_AUTH_KEY, b"test-auth-key");

        run_mode(Mode::Dev, &ctx).expect("dev mode");

        let name_bytes = ctx
            .kv
            .get_bytes(b"node/nodes/name")
            .expect("kv read")
            .expect("value present");
        let name = String::from_utf8(name_bytes).expect("utf-8");
        assert!(name.starts_with("ht-"));

        let unprefixed = ctx.kv.get_bytes(NODE_NAME_KEY).expect("kv read");
        assert!(unprefixed.is_none());

        let certificate_bytes = ctx
            .kv
            .get_bytes(b"node/certificates/node")
            .expect("kv read")
            .expect("value present");
        let certificate: NodeCertificate =
            serde_json::from_slice(&certificate_bytes).expect("certificate");
        assert_eq!(certificate.public_key().len(), 32);

        let unprefixed_certificate = ctx.kv.get_bytes(NODE_CERTIFICATE_KEY).expect("kv read");
        assert!(unprefixed_certificate.is_none());

        let node_token = ctx
            .kv
            .get_bytes(b"node/secrets/ht_auth_key")
            .expect("kv read")
            .expect("node token present");
        assert_eq!(node_token, b"test-auth-key");

        let root_token = ctx
            .kv
            .get_bytes(b"root/secrets/ht_auth_key")
            .expect("kv read")
            .expect("root token present");
        assert_eq!(root_token, b"test-auth-key");

        // Registration is validated in integration tests; here we focus on namespace propagation.
    }

    #[test]
    fn run_mode_propagates_endpoint_override_in_node_mode() {
        let ctx = context();
        ctx.kv.put_secret(HT_AUTH_KEY, b"test-auth-key");
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind stub root api");
        let endpoint = format!("http://{}/nodes", listener.local_addr().expect("addr"));
        ctx.kv
            .put_bytes(ROOT_ENDPOINT_KEY, endpoint.as_bytes())
            .expect("store endpoint override");

        let (request_tx, request_rx) = mpsc::channel();
        std::thread::spawn(move || {
            listener.set_nonblocking(false).expect("blocking listener");
            if let Ok((mut stream, _)) = listener.accept() {
                stream
                    .set_read_timeout(Some(StdDuration::from_secs(1)))
                    .expect("read timeout");
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    match stream.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(read) => {
                            buffer.extend_from_slice(&chunk[..read]);
                            if let Some(expected) = expected_request_len(&buffer) {
                                if buffer.len() >= expected {
                                    break;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }

                let _ = request_tx.send(buffer);
                let response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
                let _ = stream.write_all(response);
            }
        });

        run_mode(Mode::Node, &ctx).expect("node mode");

        let request = request_rx
            .recv_timeout(StdDuration::from_secs(1))
            .expect("node registration request captured");
        let request = String::from_utf8_lossy(&request);
        assert!(request.contains("POST /nodes"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("x-ht-auth: test-auth-key")
        );
    }

    fn expected_request_len(buffer: &[u8]) -> Option<usize> {
        let text = std::str::from_utf8(buffer).ok()?;
        let header_end = text.find("\r\n\r\n")?;
        let headers = &text[..header_end];
        let content_length = headers
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        Some(header_end + 4 + content_length)
    }
}
