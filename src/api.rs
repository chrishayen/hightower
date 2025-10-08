use askama::Template;
use axum::{
    Router,
    body::Body,
    extract::{Json, Path as AxumPath, State},
    http::{
        HeaderMap, Request, StatusCode,
        header::{CONTENT_TYPE, COOKIE, HeaderName, HeaderValue, SET_COOKIE},
    },
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use crate::certificates::NodeCertificate;
use crate::context::{CommonContext, GatewayAuthService, GATEWAY_CERTIFICATE_KEY, HT_AUTH_KEY, NamespacedKv};
use hex::FromHex;
use rand::RngCore;
use std::sync::{Arc, OnceLock, RwLock};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::runtime::Builder;
use tracing::dispatcher;
use tracing::{debug, error};

use crate::ip_allocator::IpAllocator;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub(crate) const API_ADDRESS: &str = "0.0.0.0:8008";
const NODE_REGISTRATION_PREFIX: &str = "nodes/registry";
const NODE_TOKEN_PREFIX: &str = "nodes/tokens";
const AUTH_HEADER: &str = "x-ht-auth";
const SESSION_NAMESPACE: &[u8] = b"sessions";
const SESSION_COOKIE: &str = "ht_session";

pub(crate) static API_SHARED_KV: OnceLock<Arc<RwLock<NamespacedKv>>> = OnceLock::new();
pub(crate) static API_LAUNCH: OnceLock<()> = OnceLock::new();

#[derive(Clone)]
struct ApiState {
    kv: Arc<RwLock<NamespacedKv>>,
    auth: Arc<GatewayAuthService>,
}

pub fn start(context: &CommonContext) {
    debug!("Gateway starting");

    let certificate = crate::startup::startup();
    persist_certificate(context, &certificate);

    let shared_kv = API_SHARED_KV
        .get_or_init(|| Arc::new(RwLock::new(context.kv.clone())))
        .clone();

    {
        let mut guard = shared_kv.write().expect("gateway shared kv write lock");
        *guard = context.kv.clone();
    }

    // Set KV for WireGuard API
    crate::wireguard_api::set_kv(shared_kv.clone());

    let auth = Arc::clone(&context.auth);

    API_LAUNCH.get_or_init(|| {
        let dispatcher = dispatcher::get_default(|current| current.clone());
        let cert_for_thread = certificate.clone();
        std::thread::Builder::new()
            .name("gateway".into())
            .spawn({
                let kv_for_thread = shared_kv.clone();
                let auth_for_thread = Arc::clone(&auth);
                let dispatcher = dispatcher.clone();
                move || {
                    dispatcher::with_default(&dispatcher, || {
                        let runtime = Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .expect("gateway runtime");

                        runtime.block_on(async {
                            // Initialize WireGuard transport before starting HTTP server
                            crate::wireguard_api::initialize(&cert_for_thread).await;

                            if let Err(err) = start_server(kv_for_thread, auth_for_thread).await {
                                error!(?err, "Gateway server terminated unexpectedly");
                            }
                        });
                    });
                }
            })
            .expect("spawn gateway thread");
    });
}

fn build_router(shared_kv: Arc<RwLock<NamespacedKv>>, auth: Arc<GatewayAuthService>) -> Router {
    let api_routes = Router::new()
        .route("/health", get(root_health))
        .route("/nodes", post(register_node))
        .route("/nodes/:token", axum::routing::delete(deregister_node))
        .route("/session", post(create_session))
        .route("/dashboard/nodes", get(dashboard_nodes));

    let console_routes = Router::new()
        .route("/", get(console_root))
        .route("/dashboard", get(console_dashboard));

    Router::new()
        .nest("/api", api_routes)
        .merge(console_routes)
        .with_state(ApiState {
            kv: shared_kv,
            auth,
        })
}

async fn console_root() -> Response {
    match LoginTemplate.render() {
        Ok(html) => (StatusCode::OK, Html(html)).into_response(),
        Err(err) => {
            error!(?err, "Failed to render login template");
            (StatusCode::INTERNAL_SERVER_ERROR, "failed to render page").into_response()
        }
    }
}

async fn console_dashboard(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    match has_valid_session(&state, &headers) {
        Ok(true) => match DashboardTemplate.render() {
            Ok(html) => (StatusCode::OK, Html(html)).into_response(),
            Err(err) => {
                error!(?err, "Failed to render dashboard template");
                (StatusCode::INTERNAL_SERVER_ERROR, "failed to render page").into_response()
            }
        },
        Ok(false) => Redirect::to("/").into_response(),
        Err(err) => {
            error!(?err, "Failed to validate session for dashboard");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to validate session",
            )
                .into_response()
        }
    }
}

async fn start_server(
    shared_kv: Arc<RwLock<NamespacedKv>>,
    auth: Arc<GatewayAuthService>,
) -> Result<(), BoxError> {
    let addr: std::net::SocketAddr = API_ADDRESS.parse().expect("valid socket address");
    let app = build_router(shared_kv, auth);
    let listener = TcpListener::bind(addr).await?;

    debug!(address = %addr, "Gateway ready");
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Debug, serde::Deserialize)]
struct SessionRequest {
    username: String,
    password: String,
}

#[derive(Debug)]
enum SessionApiError {
    Internal(String),
}

impl IntoResponse for SessionApiError {
    fn into_response(self) -> Response {
        match self {
            SessionApiError::Internal(message) => {
                (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
        }
    }
}

async fn create_session(
    State(state): State<ApiState>,
    Json(body): Json<SessionRequest>,
) -> Result<Response, SessionApiError> {
    let SessionRequest { username, password } = body;
    let username = username.trim().to_owned();

    if username.is_empty() || password.is_empty() {
        return build_login_alert("error", "Username and password are required.");
    }

    let authenticated = state
        .auth
        .verify_password(&username, &password)
        .map_err(|err| {
            SessionApiError::Internal(format!("failed to verify credentials: {}", err))
        })?;

    if !authenticated {
        return build_login_alert("error", "Invalid username or password.");
    }

    let token = generate_session_token();
    persist_session(&state, &token, &username)?;
    let cookie = build_session_cookie(&token);
    let cookie_value = HeaderValue::from_str(&cookie)
        .map_err(|err| SessionApiError::Internal(format!("invalid cookie header: {}", err)))?;

    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(SET_COOKIE, cookie_value)
        .header(
            HeaderName::from_static("hx-redirect"),
            HeaderValue::from_static("/dashboard"),
        )
        .body(Body::empty())
        .map_err(|err| SessionApiError::Internal(format!("failed to build response: {}", err)))
}

fn build_login_alert(kind: &str, message: &str) -> Result<Response, SessionApiError> {
    let template = LoginAlertTemplate { kind, message };
    let markup = template.render().map_err(|err| {
        SessionApiError::Internal(format!("failed to render login alert: {}", err))
    })?;

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(markup))
        .map_err(|err| {
            SessionApiError::Internal(format!("failed to build alert response: {}", err))
        })
}

async fn dashboard_nodes(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    match has_valid_session(&state, &headers) {
        Ok(true) => match fetch_registered_nodes(&state) {
            Ok(nodes) => match render_nodes_partial(&nodes) {
                Ok(markup) => match Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "text/html; charset=utf-8")
                    .body(Body::from(markup))
                {
                    Ok(response) => response,
                    Err(err) => {
                        error!(?err, "Failed to build dashboard table response");
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "failed to render dashboard",
                        )
                            .into_response()
                    }
                },
                Err(err) => {
                    error!(?err, "Failed to render dashboard table template");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "failed to render dashboard",
                    )
                        .into_response()
                }
            },
            Err(err) => {
                error!(?err, "Failed to fetch node registrations");
                (StatusCode::INTERNAL_SERVER_ERROR, "failed to load nodes").into_response()
            }
        },
        Ok(false) => unauthorized_redirect(),
        Err(err) => {
            error!(?err, "Failed to validate session for dashboard nodes");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to validate session",
            )
                .into_response()
        }
    }
}

fn persist_session(state: &ApiState, token: &str, username: &str) -> Result<(), SessionApiError> {
    let kv = {
        let guard = state.kv.read().expect("gateway shared kv read lock");
        guard.clone()
    };

    let sessions = kv.clone_with_additional_prefix(SESSION_NAMESPACE);
    sessions
        .put_bytes(token.as_bytes(), username.as_bytes())
        .map_err(|err| SessionApiError::Internal(format!("failed to persist session: {}", err)))
}

fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn build_session_cookie(token: &str) -> String {
    format!(
        "{}={}; HttpOnly; Path=/; SameSite=Strict; Max-Age=86400",
        SESSION_COOKIE, token
    )
}

fn has_valid_session(state: &ApiState, headers: &HeaderMap) -> Result<bool, hightower_kv::Error> {
    match extract_session_token(headers) {
        Some(token) => session_exists(state, &token),
        None => Ok(false),
    }
}

fn session_exists(state: &ApiState, token: &str) -> Result<bool, hightower_kv::Error> {
    let kv = {
        let guard = state.kv.read().expect("gateway shared kv read lock");
        guard.clone()
    };

    let sessions = kv.clone_with_additional_prefix(SESSION_NAMESPACE);
    sessions
        .get_bytes(token.as_bytes())
        .map(|value| value.is_some())
}

fn extract_session_token(headers: &HeaderMap) -> Option<String> {
    let header = headers.get(COOKIE)?;
    let value = header.to_str().ok()?;
    let needle = format!("{}=", SESSION_COOKIE);

    value.split(';').find_map(|part| {
        let trimmed = part.trim();
        trimmed.strip_prefix(&needle).map(|token| token.to_string())
    })
}

fn render_nodes_partial(nodes: &[NodeRegistrationRequest]) -> Result<String, askama::Error> {
    let template = NodesTableTemplate { nodes };
    template.render()
}

fn unauthorized_redirect() -> Response {
    match Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(
            HeaderName::from_static("hx-redirect"),
            HeaderValue::from_static("/"),
        )
        .body(Body::empty())
    {
        Ok(response) => response,
        Err(err) => {
            error!(?err, "Failed to build unauthorized redirect response");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to build response",
            )
                .into_response()
        }
    }
}

fn fetch_registered_nodes(state: &ApiState) -> Result<Vec<NodeRegistrationRequest>, String> {
    let kv = {
        let guard = state.kv.read().expect("gateway shared kv read lock");
        guard.clone()
    };

    let entries = kv
        .list_by_prefix(NODE_REGISTRATION_PREFIX.as_bytes())
        .map_err(|err| format!("failed to read node registrations: {}", err))?;

    let mut nodes = Vec::new();
    for (_key, value) in entries {
        if value == b"__DELETED__" {
            continue;
        }
        let mut node: NodeRegistrationRequest = serde_json::from_slice(&value)
            .map_err(|err| format!("failed to decode node registration: {}", err))?;

        // Find the token for this node
        if let Some(ref node_id) = node.node_id {
            node.token = find_token_for_node(&kv, node_id);
        }

        nodes.push(node);
    }

    nodes.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    Ok(nodes)
}

fn find_token_for_node(kv: &NamespacedKv, node_id: &str) -> Option<String> {
    let token_entries = kv.list_by_prefix(NODE_TOKEN_PREFIX.as_bytes()).ok()?;

    for (key, value) in token_entries {
        if value == b"__DELETED__" {
            continue;
        }
        if value == node_id.as_bytes() {
            // The key returned by list_by_prefix has the prefix stripped already
            let token = String::from_utf8(key).ok()?;
            return Some(token);
        }
    }

    None
}

async fn root_health(_request: Request<Body>) -> StatusCode {
    StatusCode::OK
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct NodeRegistrationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    node_id: Option<String>,
    public_key_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    assigned_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_port: Option<u16>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct NodeRegistrationResponse {
    node_id: String,
    token: String,
    gateway_public_key_hex: String,
    assigned_ip: String,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate;

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate;

#[derive(Template)]
#[template(path = "login_alert.html")]
struct LoginAlertTemplate<'a> {
    kind: &'a str,
    message: &'a str,
}

#[derive(Template)]
#[template(path = "nodes_table.html")]
struct NodesTableTemplate<'a> {
    nodes: &'a [NodeRegistrationRequest],
}

#[derive(Debug)]
enum RootApiError {
    Unauthorized,
    MissingAuthKey,
    InvalidPublicKey,
    Storage(String),
    Internal(String),
}

impl IntoResponse for RootApiError {
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
) -> Result<Json<NodeRegistrationResponse>, RootApiError> {
    let kv = {
        let guard = state.kv.read().expect("gateway shared kv read lock");
        guard.clone()
    };

    validate_auth(&kv, &headers)?;

    // Always generate node_id - nodes never provide their own name
    let node_id = generate_node_name();

    debug!(node_id = %node_id, "Gateway received node registration request");
    ensure_public_key_valid(&body.public_key_hex)?;

    // Allocate IP address for the node
    let assigned_ip = IpAllocator::allocate_ip(&kv, &node_id)
        .map_err(|err| RootApiError::Storage(format!("failed to allocate IP: {}", err)))?;
    debug!(node_id = %node_id, assigned_ip = %assigned_ip, "Assigned IP to node");

    let gateway_public_key_hex = load_gateway_public_key(&kv)?;
    let token = generate_registration_token();

    // Store the assigned IP in the registration
    let mut registration = body.clone();
    registration.node_id = Some(node_id.clone());
    registration.assigned_ip = Some(assigned_ip.clone());

    persist_registration(&kv, &registration, &token).map_err(|err| {
        RootApiError::Storage(format!("failed to persist node registration: {}", err))
    })?;

    // Add node as peer to transport layer
    if let Some(transport) = crate::wireguard_api::get_transport_server() {
        debug!(node_id = %node_id, "gateway: Adding node as WireGuard peer");
        let peer_public_key = hex::decode(&body.public_key_hex)
            .map_err(|_| RootApiError::InvalidPublicKey)?;
        if peer_public_key.len() != 32 {
            return Err(RootApiError::InvalidPublicKey);
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&peer_public_key);

        // We don't know the node's endpoint yet - they'll connect to us
        if let Err(e) = transport.add_peer(key_array, None).await {
            tracing::error!(
                error = ?e,
                node_id = %node_id,
                "gateway: Failed to add node as WireGuard peer"
            );
        } else {
            debug!(
                node_id = %node_id,
                public_key = &body.public_key_hex[..8],
                "gateway: Successfully added node as WireGuard peer"
            );
        }
    } else {
        debug!(node_id = %node_id, "gateway: WireGuard transport not initialized yet");
    }

    debug!(node_id = %node_id, assigned_ip = %assigned_ip, "Registered node");
    Ok(Json(NodeRegistrationResponse {
        node_id,
        token,
        gateway_public_key_hex,
        assigned_ip,
    }))
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
    token: &str,
) -> Result<(), hightower_kv::Error> {
    let node_id = registration.node_id.as_ref().expect("node_id must be set before persist");
    let key = registration_storage_key(node_id);
    let serialized = serde_json::to_vec(registration)
        .expect("NodeRegistrationRequest serialization should not fail");
    kv.put_bytes(&key, &serialized)?;

    let token_key = token_storage_key(token);
    kv.put_bytes(&token_key, node_id.as_bytes())
}

fn registration_storage_key(node_id: &str) -> Vec<u8> {
    format!("{}/{}", NODE_REGISTRATION_PREFIX, node_id).into_bytes()
}

fn token_storage_key(token: &str) -> Vec<u8> {
    format!("{}/{}", NODE_TOKEN_PREFIX, token).into_bytes()
}

fn generate_registration_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn generate_node_name() -> String {
    const PREFIX: &str = "ht";
    const SUFFIX_LEN: usize = 5;
    hightower_naming::generate_random_name_with_prefix(Some(PREFIX), Some(SUFFIX_LEN))
}

fn persist_certificate(context: &CommonContext, certificate: &NodeCertificate) {
    let payload = serde_json::to_vec(certificate).unwrap_or_else(|err| {
        tracing::error!(?err, "Failed to serialize gateway certificate");
        std::process::exit(1);
    });

    context
        .kv
        .put_bytes(GATEWAY_CERTIFICATE_KEY, &payload)
        .unwrap_or_else(|err| {
            tracing::error!(?err, "Failed to store gateway certificate");
            std::process::exit(1);
        });
}

fn load_gateway_public_key(kv: &NamespacedKv) -> Result<String, RootApiError> {
    let cert_bytes = kv
        .get_bytes(GATEWAY_CERTIFICATE_KEY)
        .map_err(|err| {
            RootApiError::Internal(format!("failed to read gateway certificate: {}", err))
        })?
        .ok_or_else(|| {
            RootApiError::Internal("gateway certificate not found in storage".to_string())
        })?;

    let certificate: NodeCertificate = serde_json::from_slice(&cert_bytes).map_err(|err| {
        RootApiError::Internal(format!("failed to deserialize gateway certificate: {}", err))
    })?;

    Ok(certificate.public_key_hex())
}

async fn deregister_node(
    State(state): State<ApiState>,
    AxumPath(token): AxumPath<String>,
) -> Result<StatusCode, RootApiError> {
    let kv = {
        let guard = state.kv.read().expect("gateway shared kv read lock");
        guard.clone()
    };

    let token_key = token_storage_key(&token);
    let node_id = kv
        .get_bytes(&token_key)
        .map_err(|err| RootApiError::Storage(format!("failed to read token: {}", err)))?
        .ok_or(RootApiError::Unauthorized)?;

    let node_id = String::from_utf8(node_id)
        .map_err(|_| RootApiError::Internal("invalid node_id encoding".into()))?;

    debug!(node_id = %node_id, "Gateway received node deregistration request");

    let registration_key = registration_storage_key(&node_id);
    kv.put_bytes(&registration_key, b"__DELETED__")
        .map_err(|err| RootApiError::Storage(format!("failed to mark registration deleted: {}", err)))?;

    kv.put_bytes(&token_key, b"__DELETED__")
        .map_err(|err| RootApiError::Storage(format!("failed to mark token deleted: {}", err)))?;

    IpAllocator::release_ip(&kv, &node_id)
        .map_err(|err| RootApiError::Storage(format!("failed to release IP: {}", err)))?;

    debug!(node_id = %node_id, "Deregistered node");
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::RootRegistrar;
    use axum::http::HeaderValue;
    use crate::context::{CommonContext, HT_AUTH_KEY, initialize_kv};
    use crate::fixtures;
    use std::sync::mpsc;
    use std::sync::{Arc, RwLock};
    use std::time::Duration;
    use tempfile::TempDir;


    #[test]
    fn start_initializes_server() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let ctx = CommonContext::new(kv);
        ctx.kv.put_secret(HT_AUTH_KEY, b"test-auth-key");

        start(&ctx);

        crate::wait_until_ready(Duration::from_secs(1)).expect("gateway ready");
    }

    #[test]
    fn http_root_registrar_registers_against_running_api() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);
        context.kv.put_secret(HT_AUTH_KEY, b"super-secret");

        let certificate = crate::startup::startup();
        persist_certificate(&context, &certificate);

        let shared_kv = Arc::new(RwLock::new(context.kv.clone()));
        let shared_auth = Arc::clone(&context.auth);
        let dispatcher = dispatcher::get_default(|current| current.clone());
        let (ready_tx, ready_rx) = mpsc::channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let server_thread = std::thread::spawn({
            let shared_kv = Arc::clone(&shared_kv);
            let shared_auth = Arc::clone(&shared_auth);
            let dispatcher = dispatcher.clone();
            move || {
                dispatcher::with_default(&dispatcher, || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("runtime");

                    runtime.block_on(async move {
                        let router = build_router(shared_kv, shared_auth);
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
                });
            }
        });

        let addr = ready_rx.recv().expect("receive listener address");
        let endpoint = format!("http://{addr}/api/nodes");
        context
            .kv
            .put_bytes(crate::client::ROOT_ENDPOINT_KEY, endpoint.as_bytes())
            .expect("store custom root endpoint");

        let registrar = crate::client::HttpRootRegistrar::default();
        let public_key_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let result = registrar
            .register(&context, public_key_hex, None)
            .expect("http registrar registers against api");

        // Gateway should have assigned a node_id (for now, still accepts the old one)
        let assigned_node_id = result.node_id;
        assert!(!assigned_node_id.is_empty());

        let key = registration_storage_key(&assigned_node_id);
        let stored = context
            .kv
            .get_bytes(key.as_ref())
            .expect("kv read")
            .expect("registration stored");
        let decoded: NodeRegistrationRequest =
            serde_json::from_slice(&stored).expect("decode registration");
        assert_eq!(decoded.node_id, Some(assigned_node_id));
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

        let certificate = crate::startup::startup();
        persist_certificate(&context, &certificate);

        let state = ApiState {
            kv: Arc::new(RwLock::new(context.kv.clone())),
            auth: Arc::clone(&context.auth),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_lowercase(AUTH_HEADER.as_bytes()).expect("static header"),
            HeaderValue::from_static("super-secret"),
        );

        let body = NodeRegistrationRequest {
            node_id: None,
            public_key_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            token: None,
            assigned_ip: None,
            public_ip: None,
            public_port: None,
            local_ip: None,
            local_port: None,
        };

        let response = register_node(State(state), headers, Json(body.clone()))
            .await
            .expect("registration succeeds");

        assert!(!response.0.node_id.is_empty());
        assert!(response.0.node_id.starts_with("ht-"));
        assert!(!response.0.token.is_empty());
        assert!(!response.0.gateway_public_key_hex.is_empty());
        assert_eq!(response.0.gateway_public_key_hex.len(), 64);
        assert!(!response.0.assigned_ip.is_empty());
        assert_eq!(response.0.assigned_ip, "100.64.0.1");

        let stored = context
            .kv
            .get_bytes(registration_storage_key(&response.0.node_id).as_ref())
            .expect("kv read")
            .expect("value present");
        let decoded: NodeRegistrationRequest =
            serde_json::from_slice(&stored).expect("deserialize");

        assert_eq!(decoded.node_id, Some(response.0.node_id));
        assert_eq!(decoded.public_key_hex, body.public_key_hex);
    }

    #[tokio::test]
    async fn register_node_rejects_missing_auth() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);
        context.kv.put_secret(HT_AUTH_KEY, b"super-secret");

        let certificate = crate::startup::startup();
        persist_certificate(&context, &certificate);

        let state = ApiState {
            kv: Arc::new(RwLock::new(context.kv.clone())),
            auth: Arc::clone(&context.auth),
        };
        let headers = HeaderMap::new();
        let body = NodeRegistrationRequest {
            node_id: None,
            public_key_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            token: None,
            assigned_ip: None,
            public_ip: None,
            public_port: None,
            local_ip: None,
            local_port: None,
        };

        let response = register_node(State(state), headers, Json(body)).await;
        assert!(matches!(response, Err(RootApiError::Unauthorized)));
    }

    #[tokio::test]
    async fn deregister_node_removes_registration() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);
        context.kv.put_secret(HT_AUTH_KEY, b"super-secret");

        let certificate = crate::startup::startup();
        persist_certificate(&context, &certificate);

        let state = ApiState {
            kv: Arc::new(RwLock::new(context.kv.clone())),
            auth: Arc::clone(&context.auth),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_lowercase(AUTH_HEADER.as_bytes()).expect("static header"),
            HeaderValue::from_static("super-secret"),
        );

        let body = NodeRegistrationRequest {
            node_id: None,
            public_key_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            token: None,
            assigned_ip: None,
            public_ip: None,
            public_port: None,
            local_ip: None,
            local_port: None,
        };

        let response = register_node(State(state.clone()), headers, Json(body.clone()))
            .await
            .expect("registration succeeds");

        let node_id = response.0.node_id;
        let token = response.0.token;
        assert!(!node_id.is_empty());
        assert!(!token.is_empty());

        // Verify token was stored
        let token_before = context
            .kv
            .get_bytes(token_storage_key(&token).as_ref())
            .expect("kv read token before deregister")
            .expect("token should exist");
        assert_eq!(token_before, node_id.as_bytes());

        let status = deregister_node(State(state), AxumPath(token))
            .await
            .expect("deregistration succeeds");

        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn create_session_returns_no_content_for_valid_credentials() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);
        context
            .auth
            .create_user("console-admin", "super-secret")
            .expect("create default user");

        let state = ApiState {
            kv: Arc::new(RwLock::new(context.kv.clone())),
            auth: Arc::clone(&context.auth),
        };

        let body = SessionRequest {
            username: "console-admin".into(),
            password: "super-secret".into(),
        };

        let response = create_session(State(state.clone()), Json(body))
            .await
            .expect("session creation succeeds");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let cookie_header = response
            .headers()
            .get(SET_COOKIE)
            .expect("set-cookie present")
            .to_str()
            .expect("cookie header str");
        assert!(cookie_header.contains(SESSION_COOKIE));

        let redirect_header = response
            .headers()
            .get(HeaderName::from_static("hx-redirect"))
            .expect("hx-redirect present")
            .to_str()
            .expect("hx redirect str");
        assert_eq!(redirect_header, "/dashboard");

        let token = cookie_header
            .split(';')
            .next()
            .and_then(|segment| segment.strip_prefix(&format!("{}=", SESSION_COOKIE)))
            .expect("session token present")
            .to_string();

        let sessions = context.kv.clone_with_additional_prefix(SESSION_NAMESPACE);
        let stored = sessions
            .get_bytes(token.as_bytes())
            .expect("read session store")
            .expect("session stored");
        assert_eq!(stored, b"console-admin");
    }

    #[tokio::test]
    async fn create_session_rejects_invalid_credentials() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);
        context
            .auth
            .create_user("console-admin", "super-secret")
            .expect("create default user");

        let state = ApiState {
            kv: Arc::new(RwLock::new(context.kv.clone())),
            auth: Arc::clone(&context.auth),
        };

        let body = SessionRequest {
            username: "console-admin".into(),
            password: "not-it".into(),
        };

        let response = create_session(State(state), Json(body))
            .await
            .expect("session response");

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let rendered = String::from_utf8(body_bytes.into()).expect("body utf8");
        assert!(rendered.contains("Invalid username or password."));
        assert!(rendered.contains("login-alert"));
    }

    #[tokio::test]
    async fn dashboard_redirects_without_session() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);

        let state = ApiState {
            kv: Arc::new(RwLock::new(context.kv.clone())),
            auth: Arc::clone(&context.auth),
        };

        let response = console_dashboard(State(state), HeaderMap::new()).await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get(axum::http::header::LOCATION)
            .expect("location header")
            .to_str()
            .expect("location str");
        assert_eq!(location, "/");
    }

    #[tokio::test]
    async fn dashboard_renders_when_session_valid() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);
        context
            .auth
            .create_user("console-admin", "super-secret")
            .expect("create default user");

        let state = ApiState {
            kv: Arc::new(RwLock::new(context.kv.clone())),
            auth: Arc::clone(&context.auth),
        };

        let response = create_session(
            State(state.clone()),
            Json(SessionRequest {
                username: "console-admin".into(),
                password: "super-secret".into(),
            }),
        )
        .await
        .expect("session creation succeeds");

        let cookie_header = response
            .headers()
            .get(SET_COOKIE)
            .expect("set-cookie present")
            .to_str()
            .expect("cookie str");
        let token = cookie_header
            .split(';')
            .next()
            .and_then(|segment| segment.strip_prefix(&format!("{}=", SESSION_COOKIE)))
            .expect("session token present")
            .to_string();

        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("{}={}", SESSION_COOKIE, token))
                .expect("cookie header value"),
        );

        let response = console_dashboard(State(state), headers).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let rendered = String::from_utf8(body_bytes.into()).expect("body utf8");
        assert!(rendered.contains("Dashboard"));
        assert!(rendered.contains("hx-get=\"/api/dashboard/nodes\""));
    }

    #[tokio::test]
    async fn dashboard_lists_registered_nodes() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);
        context
            .auth
            .create_user("console-admin", "super-secret")
            .expect("create default user");

        let shared_kv = Arc::new(RwLock::new(context.kv.clone()));

        let state = ApiState {
            kv: Arc::clone(&shared_kv),
            auth: Arc::clone(&context.auth),
        };

        let registration = NodeRegistrationRequest {
            node_id: Some("ht-node-1".into()),
            public_key_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            token: None,
            assigned_ip: None,
            public_ip: None,
            public_port: None,
            local_ip: None,
            local_port: None,
        };

        let kv = {
            let guard = shared_kv.read().expect("shared kv read lock");
            guard.clone()
        };
        persist_registration(&kv, &registration, "test-token").expect("persist registration");

        let response = create_session(
            State(state.clone()),
            Json(SessionRequest {
                username: "console-admin".into(),
                password: "super-secret".into(),
            }),
        )
        .await
        .expect("session creation succeeds");

        let cookie_header = response
            .headers()
            .get(SET_COOKIE)
            .expect("set-cookie present")
            .to_str()
            .expect("cookie str");
        let token = cookie_header
            .split(';')
            .next()
            .and_then(|segment| segment.strip_prefix(&format!("{}=", SESSION_COOKIE)))
            .expect("session token present")
            .to_string();

        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("{}={}", SESSION_COOKIE, token))
                .expect("cookie header value"),
        );

        let response = dashboard_nodes(State(state), headers).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let rendered = String::from_utf8(body_bytes.into()).expect("body utf8");
        assert!(rendered.contains("ht-node-1"));
    }

    #[test]
    fn gateway_start_initializes_without_panic() {
        let ctx = fixtures::context();
        ctx.kv.put_secret(HT_AUTH_KEY, b"test-auth-key");

        start(&ctx);
    }

    #[test]
    fn gateway_start_generates_and_persists_certificate() {
        let ctx = fixtures::context();
        ctx.kv.put_secret(HT_AUTH_KEY, b"test-auth-key");

        start(&ctx);

        let cert_bytes = ctx
            .kv
            .get_bytes(GATEWAY_CERTIFICATE_KEY)
            .expect("kv read")
            .expect("certificate stored");
        let certificate: NodeCertificate =
            serde_json::from_slice(&cert_bytes).expect("certificate deserializes");
        assert_eq!(certificate.public_key().len(), 32);
        assert_eq!(certificate.private_key().len(), 32);
    }
}
