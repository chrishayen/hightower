use crate::common::CommonContext;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::thread;
use tokio::net::TcpListener;
use tokio::runtime::Builder;
use tracing::{error, info};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const API_ADDRESS: &str = "0.0.0.0:8008";

static API_LAUNCH: OnceLock<()> = OnceLock::new();

pub fn run(_context: &CommonContext) {
    info!("Running in root mode");

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

    info!(address = %addr, "Root API server listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn root_health(_request: Request<Body>) -> StatusCode {
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv;
    use tempfile::TempDir;

    #[test]
    fn run_logs_message() {
        let temp = TempDir::new().expect("tempdir");
        let kv = kv::initialize(Some(temp.path())).expect("kv init");
        let ctx = CommonContext::new(kv);
        run(&ctx);
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
