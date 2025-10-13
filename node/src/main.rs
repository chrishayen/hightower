use clap::Parser;
use node::context::{self, ContextError};
use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use tracing::{debug, error};
use tracing_subscriber::{EnvFilter, fmt as tracing_fmt};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to the key-value data directory
    #[arg(long = "kv", value_name = "DIR")]
    kv: Option<PathBuf>,
}

#[derive(Debug)]
enum AppError {
    Context(ContextError),
    Shutdown(std::io::Error),
    Runtime(std::io::Error),
    Node(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Context(err) => write!(f, "startup failed: {err}"),
            AppError::Shutdown(err) => write!(f, "shutdown failed: {err:?}"),
            AppError::Runtime(err) => write!(f, "runtime creation failed: {err}"),
            AppError::Node(err) => write!(f, "node connection failed: {err}"),
        }
    }
}

impl Error for AppError {}

fn main() {
    let rust_log = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    eprintln!("RUST_LOG: {}", rust_log);

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|e| {
        eprintln!("Failed to parse RUST_LOG: {:?}, using default 'info'", e);
        EnvFilter::new("info")
    });

    let subscriber = tracing_fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_target(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");

    let cli = Cli::parse();

    if let Err(err) = run(cli) {
        error!(?err, "Application error");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), AppError> {
    let context =
        context::initialize_with_token_source(cli.kv.as_deref().map(|s| s.as_ref()), |key| {
            std::env::var(key)
        })
        .map_err(AppError::Context)?;

    // Create a tokio runtime for async operations
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(AppError::Runtime)?;

    let connection = runtime
        .block_on(node::run(&context))
        .map_err(AppError::Node)?;

    debug!("Waiting for Ctrl-C to exit");
    wait_for_ctrl_c().map_err(AppError::Shutdown)?;
    debug!("Shutdown signal received");

    debug!("Deregistering node");
    let _ = runtime.block_on(node::deregister(connection));

    Ok(())
}

fn wait_for_ctrl_c() -> Result<(), std::io::Error> {
    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    rx.recv()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    Ok(())
}
