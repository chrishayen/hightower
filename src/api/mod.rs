mod certificates;
mod handlers;
mod static_assets;
mod types;

pub(crate) use certificates::persist_certificate;

use crate::context::{CommonContext, GatewayAuthService, NamespacedKv, HT_AUTH_KEY};
use crate::tls::SniResolver;
use axum::{
    routing::{get, post},
    Router,
};
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use std::sync::{Arc, OnceLock, RwLock};
use tokio::net::TcpListener;
use tokio::runtime::Builder;
use tracing::dispatcher;
use tracing::{debug, error};

use handlers::{
    acme_challenge, change_password, console_dashboard, console_nodes, console_root, console_settings,
    create_session, dashboard_nodes, deregister_node, delete_session, generate_auth_key,
    list_auth_keys, register_node, revoke_auth_key, root_health, store_legacy_key,
};
use types::ApiState;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn get_http_port() -> u16 {
    std::env::var("HTTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80)
}

fn is_https_disabled() -> bool {
    std::env::var("DISABLE_HTTPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(false)
}

pub(crate) const HTTPS_ADDRESS: &str = "0.0.0.0:443";

fn http_address() -> String {
    format!("0.0.0.0:{}", get_http_port())
}

pub(crate) fn api_address() -> String {
    format!("127.0.0.1:{}", get_http_port())
}

pub(crate) static API_SHARED_KV: OnceLock<Arc<RwLock<NamespacedKv>>> = OnceLock::new();
pub(crate) static API_LAUNCH: OnceLock<()> = OnceLock::new();
pub(crate) static ACME_CLIENT: OnceLock<Arc<crate::acme::AcmeClient>> = OnceLock::new();

fn migrate_legacy_auth_key(kv: &NamespacedKv) {
    // Check if there's a legacy auth key stored
    if let Ok(Some(legacy_bytes)) = kv.get_bytes(HT_AUTH_KEY) {
        // Don't migrate if already migrated or if it's the migration marker
        if legacy_bytes == b"__MIGRATED__" {
            return;
        }

        if let Ok(legacy_key) = String::from_utf8(legacy_bytes) {
            debug!("Migrating legacy HT_AUTH_KEY to new auth key system");

            // Store as new format with key_id "default"
            if let Err(err) = store_legacy_key(kv, &legacy_key) {
                error!(?err, "Failed to migrate legacy auth key");
            } else {
                // Keep the legacy key in place for client-side reads (nodes use it to authenticate)
                // Only server-side validation now uses the new auth/keys location
                debug!("Successfully migrated legacy auth key to new system while keeping legacy location for client compatibility");
            }
        }
    }
}

pub fn start(context: &CommonContext) {
    start_with_email(context, None);
}

pub fn start_with_email(context: &CommonContext, email: Option<String>) {
    debug!("Gateway starting");

    let certificate = crate::startup::startup();
    persist_certificate(context, &certificate);

    let shared_kv = API_SHARED_KV
        .get_or_init(|| Arc::new(RwLock::new(context.kv.clone())))
        .clone();

    // Migrate legacy HT_AUTH_KEY to new auth key system
    migrate_legacy_auth_key(&context.kv);

    // Initialize ACME client
    let _acme_client = ACME_CLIENT.get_or_init(|| {
        Arc::new(crate::acme::AcmeClient::new(
            shared_kv.clone(),
            email.clone(),
        ))
    });

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

                            if let Err(err) = start_servers(kv_for_thread, auth_for_thread).await {
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
        .route("/dashboard/nodes", get(dashboard_nodes))
        .route("/auth/keys", post(generate_auth_key).get(list_auth_keys))
        .route("/auth/keys/:key_id", axum::routing::delete(revoke_auth_key))
        .route("/settings/password", post(change_password));

    let logout_routes = Router::new()
        .route("/logout", get(delete_session));

    let console_routes = Router::new()
        .route("/", get(console_root))
        .route("/dashboard", get(console_dashboard))
        .route("/nodes", get(console_nodes))
        .route("/settings", get(console_settings));

    // ACME HTTP-01 challenge handler
    let acme_routes =
        Router::new().route("/.well-known/acme-challenge/:token", get(acme_challenge));

    // Static file serving (embedded)
    let static_routes = Router::new()
        .route("/static/*path", get(static_assets::serve_static));

    Router::new()
        .nest("/api", api_routes)
        .merge(static_routes)
        .merge(console_routes)
        .merge(logout_routes)
        .merge(acme_routes)
        .with_state(ApiState {
            kv: shared_kv,
            auth,
        })
}

async fn start_servers(
    shared_kv: Arc<RwLock<NamespacedKv>>,
    auth: Arc<GatewayAuthService>,
) -> Result<(), BoxError> {
    // Install default crypto provider for rustls (required in rustls 0.23+)
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let app = build_router(shared_kv.clone(), auth.clone());

    let https_disabled = is_https_disabled();

    // Try to bind both servers first to provide better error messages
    let http_addr: std::net::SocketAddr = http_address().parse().expect("valid http address");
    let https_addr: std::net::SocketAddr = HTTPS_ADDRESS.parse().expect("valid https address");

    let http_listener = TcpListener::bind(http_addr).await;
    let https_listener = if https_disabled {
        debug!("HTTPS disabled via DISABLE_HTTPS environment variable");
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "HTTPS disabled",
        ))
    } else {
        TcpListener::bind(https_addr).await
    };

    // Check if at least one server can start
    match (&http_listener, &https_listener) {
        (Err(http_err), Err(https_err)) => {
            if https_disabled {
                error!(?http_err, address = %http_addr, "Failed to bind HTTP server");
                error!("HTTP server failed to bind and HTTPS is disabled. Gateway requires at least one working server.");
            } else {
                error!(?http_err, address = %http_addr, "Failed to bind HTTP server");
                error!(?https_err, address = %https_addr, "Failed to bind HTTPS server");
                error!("Both HTTP and HTTPS servers failed to bind. Gateway requires at least one working server.");
                error!("Ports 80 and 443 are privileged - try running with sudo or CAP_NET_BIND_SERVICE capability.");
            }
            return Err("Failed to bind any server".into());
        }
        (Err(err), Ok(_)) => {
            error!(?err, address = %http_addr, "HTTP server failed to bind, continuing with HTTPS only");
        }
        (Ok(_), Err(err)) => {
            if !https_disabled {
                error!(?err, address = %https_addr, "HTTPS server failed to bind, continuing with HTTP only");
            } else {
                debug!("HTTPS disabled, running HTTP only");
            }
        }
        (Ok(_), Ok(_)) => {
            debug!("Both HTTP and HTTPS servers bound successfully");
        }
    }

    // Start HTTP server if bound successfully
    let http_server = if let Ok(listener) = http_listener {
        let http_app = app.clone();
        Some(tokio::spawn(async move {
            debug!(address = %http_addr, "HTTP server ready");
            axum::serve(listener, http_app).await?;
            Ok::<_, BoxError>(())
        }))
    } else {
        None
    };

    // Start HTTPS server if bound successfully
    let https_server: Option<tokio::task::JoinHandle<Result<(), BoxError>>> = if let Ok(listener) =
        https_listener
    {
        let https_app = app;
        Some(tokio::spawn(async move {
            // Configure TLS with SNI resolver (with ACME if available)
            let sni_resolver = if let Some(acme_client) = crate::api::ACME_CLIENT.get() {
                Arc::new(SniResolver::with_acme(shared_kv, Arc::clone(acme_client)))
            } else {
                Arc::new(SniResolver::new(shared_kv))
            };
            let mut tls_config = ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(sni_resolver);

            tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

            debug!(address = %https_addr, "HTTPS server ready");

            loop {
                let (stream, remote_addr) = match listener.accept().await {
                    Ok(x) => x,
                    Err(err) => {
                        error!(?err, "Failed to accept HTTPS connection");
                        continue;
                    }
                };
                let tls_acceptor = tls_acceptor.clone();
                let tower_service = https_app.clone();

                tokio::spawn(async move {
                    match tls_acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let hyper_service =
                                hyper_util::service::TowerToHyperService::new(tower_service);
                            // Use auto to support both HTTP/1.1 and HTTP/2
                            if let Err(err) = hyper_util::server::conn::auto::Builder::new(
                                hyper_util::rt::TokioExecutor::new(),
                            )
                            .serve_connection(TokioIo::new(tls_stream), hyper_service)
                            .await
                            {
                                error!(?err, remote_addr = ?remote_addr, "HTTPS connection error");
                            }
                        }
                        Err(err) => {
                            error!(?err, remote_addr = ?remote_addr, "TLS accept error");
                        }
                    }
                });
            }
        }))
    } else {
        None
    };

    // Wait for whichever server(s) are running
    match (http_server, https_server) {
        (Some(http), Some(https)) => {
            tokio::select! {
                result = http => {
                    match result {
                        Ok(Ok(())) => debug!("HTTP server exited"),
                        Ok(Err(err)) => error!(?err, "HTTP server failed"),
                        Err(err) => error!(?err, "HTTP server task panicked"),
                    }
                }
                result = https => {
                    match result {
                        Ok(Ok(())) => debug!("HTTPS server exited"),
                        Ok(Err(err)) => error!(?err, "HTTPS server failed"),
                        Err(err) => error!(?err, "HTTPS server task panicked"),
                    }
                }
            }
        }
        (Some(http), None) => {
            let result = http.await;
            match result {
                Ok(Ok(())) => debug!("HTTP server exited"),
                Ok(Err(err)) => error!(?err, "HTTP server failed"),
                Err(err) => error!(?err, "HTTP server task panicked"),
            }
        }
        (None, Some(https)) => {
            let result = https.await;
            match result {
                Ok(Ok(())) => debug!("HTTPS server exited"),
                Ok(Err(err)) => error!(?err, "HTTPS server failed"),
                Err(err) => error!(?err, "HTTPS server task panicked"),
            }
        }
        (None, None) => {
            unreachable!("At least one server should be running if we got here");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::RootRegistrar;
    use crate::context::{initialize_kv, CommonContext, HT_AUTH_KEY};
    use crate::fixtures;
    use handlers::nodes::registration_storage_key;
    use std::sync::mpsc;
    use tempfile::TempDir;
    use types::NodeRegistrationRequest;

    #[test]
    fn start_initializes_server() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let ctx = CommonContext::new(kv);
        ctx.kv.put_secret(HT_AUTH_KEY, b"test-auth-key");

        start(&ctx);

        // Note: Can't test wait_until_ready without root (ports 80/443 are privileged)
        // The fact that start() doesn't panic is sufficient for this test
    }

    #[test]
    fn http_root_registrar_registers_against_running_api() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);
        // Store in both old and new locations (simulating what migration does)
        context.kv.put_secret(HT_AUTH_KEY, b"super-secret");
        store_legacy_key(&context.kv, "super-secret").expect("store auth key");

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
            .get_bytes(crate::context::GATEWAY_CERTIFICATE_KEY)
            .expect("kv read")
            .expect("certificate stored");
        let certificate: crate::certificates::NodeCertificate =
            serde_json::from_slice(&cert_bytes).expect("certificate deserializes");
        assert_eq!(certificate.public_key().len(), 32);
        assert_eq!(certificate.private_key().len(), 32);
    }
}
