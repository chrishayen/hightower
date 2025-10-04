pub mod client;

pub use client::{
    default_registrar,
    HttpRootRegistrar,
    RootRegistrar,
    RootRegistrationError,
    ROOT_ENDPOINT_KEY,
};

use axum::{
    Router,
    body::Body,
    extract::{Json, State},
    http::{HeaderMap, Request, StatusCode, header::HeaderName},
    routing::{get, post},
};
use hex::FromHex;
use hightower_context::{CommonContext, HT_AUTH_KEY, NamespacedKv};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::{Arc, OnceLock, RwLock};
use std::thread;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::runtime::Builder;
use tracing::{debug, error, info};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const API_ADDRESS: &str = "0.0.0.0:8008";
const NODE_REGISTRATION_PREFIX: &str = "nodes/registry";
const AUTH_HEADER: &str = "x-ht-auth";

static API_SHARED_KV: OnceLock<Arc<RwLock<NamespacedKv>>> = OnceLock::new();
static API_LAUNCH: OnceLock<()> = OnceLock::new();

#[derive(Clone)]
struct ApiState {
    kv: Arc<RwLock<NamespacedKv>>,
}

pub fn start(context: &CommonContext) {
    info!("Root API starting");

    let shared_kv = API_SHARED_KV
        .get_or_init(|| Arc::new(RwLock::new(context.kv.clone())))
        .clone();

    {
        let mut guard = shared_kv.write().expect("root api shared kv write lock");
        *guard = context.kv.clone();
    }

    API_LAUNCH.get_or_init(|| {
        thread::Builder::new()
            .name("root-api".into())
            .spawn({
                let kv_for_thread = shared_kv.clone();
                move || {
                    let runtime = Builder::new_multi_thread()
                        .worker_threads(1)
                        .enable_all()
                        .build()
                        .expect("root api runtime");

                    runtime.block_on(async {
                        if let Err(err) = start_server(kv_for_thread).await {
                            error!(?err, "Root API server terminated unexpectedly");
                        }
                    });
                }
            })
            .expect("spawn root api thread");
    });
}

fn build_router(shared_kv: Arc<RwLock<NamespacedKv>>) -> Router {
    Router::new()
        .route("/", get(root_health))
        .route("/nodes", post(register_node))
        .with_state(ApiState { kv: shared_kv })
}

async fn start_server(shared_kv: Arc<RwLock<NamespacedKv>>) -> Result<(), BoxError> {
    let addr: SocketAddr = API_ADDRESS.parse().expect("valid socket address");
    let app = build_router(shared_kv);
    let listener = TcpListener::bind(addr).await?;

    info!(address = %addr, "Root API ready");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn root_health(_request: Request<Body>) -> StatusCode {
    StatusCode::OK
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct NodeRegistrationRequest {
    node_id: String,
    public_key_hex: String,
}

#[derive(Debug)]
enum RootApiError {
    Unauthorized,
    MissingAuthKey,
    InvalidPublicKey,
    Storage(String),
    Internal(String),
}

impl axum::response::IntoResponse for RootApiError {
    fn into_response(self) -> axum::response::Response {
        match self {
            RootApiError::Unauthorized | RootApiError::MissingAuthKey => {
                StatusCode::UNAUTHORIZED.into_response()
            }
            RootApiError::InvalidPublicKey => {
                (StatusCode::BAD_REQUEST, "invalid public key").into_response()
            }
            RootApiError::Storage(message) => {
                (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
            RootApiError::Internal(message) => {
                (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
        }
    }
}

async fn register_node(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(body): Json<NodeRegistrationRequest>,
) -> Result<StatusCode, RootApiError> {
    let kv = {
        let guard = state.kv.read().expect("root api shared kv read lock");
        guard.clone()
    };

    validate_auth(&kv, &headers)?;
    debug!(node_id = %body.node_id, "Root API received node registration request");
    ensure_public_key_valid(&body.public_key_hex)?;

    persist_registration(&kv, &body).map_err(|err| {
        RootApiError::Storage(format!("failed to persist node registration: {}", err))
    })?;

    info!(node_id = %body.node_id, "Registered node");
    Ok(StatusCode::NO_CONTENT)
}

fn validate_auth(kv: &NamespacedKv, headers: &HeaderMap) -> Result<(), RootApiError> {
    let header_name = HeaderName::from_lowercase(AUTH_HEADER.as_bytes())
        .expect("static header name is valid lowercase");
    let provided = headers
        .get(&header_name)
        .and_then(|value| value.to_str().ok())
        .ok_or(RootApiError::Unauthorized)?;

    let stored = kv
        .get_bytes(HT_AUTH_KEY)
        .map_err(|err| RootApiError::Internal(format!("failed to read auth key: {}", err)))?
        .ok_or(RootApiError::MissingAuthKey)?;

    let stored = String::from_utf8(stored)
        .map_err(|_| RootApiError::Internal("stored auth key is not valid UTF-8".into()))?;

    if provided.as_bytes().ct_eq(stored.as_bytes()).into() {
        Ok(())
    } else {
        Err(RootApiError::Unauthorized)
    }
}

fn ensure_public_key_valid(public_key_hex: &str) -> Result<(), RootApiError> {
    let bytes = Vec::from_hex(public_key_hex).map_err(|_| RootApiError::InvalidPublicKey)?;
    if bytes.len() == 32 {
        Ok(())
    } else {
        Err(RootApiError::InvalidPublicKey)
    }
}

fn persist_registration(
    kv: &NamespacedKv,
    registration: &NodeRegistrationRequest,
) -> Result<(), hightower_kv::Error> {
    let key = registration_storage_key(&registration.node_id);
    let serialized = serde_json::to_vec(registration)
        .expect("NodeRegistrationRequest serialization should not fail");
    kv.put_bytes(&key, &serialized)
}

fn registration_storage_key(node_id: &str) -> Vec<u8> {
    format!("{}/{}", NODE_REGISTRATION_PREFIX, node_id).into_bytes()
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
                        debug!(attempt = attempts, error = %err, "Root API read transient error");
                    }
                    Err(err) => return Err(err.into()),
                }
            }
            Err(err) if is_transient_connect_error(&err) => {
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
pub fn current_kv_for_tests() -> Option<NamespacedKv> {
    API_SHARED_KV
        .get()
        .map(|shared| shared.read().expect("shared kv read").clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use hightower_context::{CommonContext, HT_AUTH_KEY, initialize_kv};
    use std::sync::mpsc;
    use std::sync::{Arc, RwLock};
    use tempfile::TempDir;

    #[test]
    fn start_initializes_server() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let ctx = CommonContext::new(kv);
        ctx.kv.put_secret(HT_AUTH_KEY, b"test-auth-key");

        start(&ctx);

        wait_until_ready(Duration::from_secs(1)).expect("root ready");
    }

    #[test]
    fn http_root_registrar_registers_against_running_api() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);
        context.kv.put_secret(HT_AUTH_KEY, b"super-secret");

        let shared_kv = Arc::new(RwLock::new(context.kv.clone()));
        let (ready_tx, ready_rx) = mpsc::channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let server_thread = std::thread::spawn({
            let shared_kv = Arc::clone(&shared_kv);
            move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("runtime");

                runtime.block_on(async move {
                    let router = build_router(shared_kv);
                    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                        .await
                        .expect("bind api listener");
                    let addr = listener.local_addr().expect("listener address");
                    ready_tx.send(addr).expect("announce listener address");

                    axum::serve(listener, router)
                        .with_graceful_shutdown(async {
                            let _ = shutdown_rx.await;
                        })
                        .await
                        .expect("serve api");
                });
            }
        });

        let addr = ready_rx.recv().expect("receive listener address");
        let endpoint = format!("http://{addr}/nodes");
        context
            .kv
            .put_bytes(ROOT_ENDPOINT_KEY, endpoint.as_bytes())
            .expect("store custom root endpoint");

        let registrar = HttpRootRegistrar::default();
        let node_id = "ht-node-integration";
        let public_key_hex =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        registrar
            .register(&context, node_id, public_key_hex)
            .expect("http registrar registers against api");

        let key = registration_storage_key(node_id);
        let stored = context
            .kv
            .get_bytes(key.as_ref())
            .expect("kv read")
            .expect("registration stored");
        let decoded: NodeRegistrationRequest =
            serde_json::from_slice(&stored).expect("decode registration");
        assert_eq!(decoded.node_id, node_id);
        assert_eq!(decoded.public_key_hex, public_key_hex);

        shutdown_tx.send(()).expect("shutdown api server");
        server_thread.join().expect("server thread join");
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

    #[tokio::test]
    async fn register_node_persists_entry_when_authenticated() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);
        context.kv.put_secret(HT_AUTH_KEY, b"super-secret");

        let state = ApiState {
            kv: Arc::new(RwLock::new(context.kv.clone())),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_lowercase(AUTH_HEADER.as_bytes()).expect("static header"),
            HeaderValue::from_static("super-secret"),
        );

        let body = NodeRegistrationRequest {
            node_id: "ht-node-1".into(),
            public_key_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
        };

        let status = register_node(State(state), headers, Json(body.clone()))
            .await
            .expect("registration succeeds");

        assert_eq!(status, StatusCode::NO_CONTENT);

        let stored = context
            .kv
            .get_bytes(registration_storage_key(&body.node_id).as_ref())
            .expect("kv read")
            .expect("value present");
        let decoded: NodeRegistrationRequest =
            serde_json::from_slice(&stored).expect("deserialize");

        assert_eq!(decoded.node_id, body.node_id);
        assert_eq!(decoded.public_key_hex, body.public_key_hex);
    }

    #[tokio::test]
    async fn register_node_rejects_missing_auth() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);
        context.kv.put_secret(HT_AUTH_KEY, b"super-secret");

        let state = ApiState {
            kv: Arc::new(RwLock::new(context.kv.clone())),
        };
        let headers = HeaderMap::new();
        let body = NodeRegistrationRequest {
            node_id: "ht-node-1".into(),
            public_key_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
        };

        let response = register_node(State(state), headers, Json(body)).await;
        assert!(matches!(response, Err(RootApiError::Unauthorized)));
    }
}
