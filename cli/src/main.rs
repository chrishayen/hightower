mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "ht")]
#[command(about = "Hightower CLI tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Query a STUN server
    Stun {
        /// STUN server address (format: host:port or host, default port: 3478)
        address: String,
    },
    /// Fetch content from WireGuard peer endpoints via hightower
    Curl {
        /// The URL to fetch (e.g., http://<endpoint-id>/path or http://<assigned-ip>/path)
        url: String,

        /// Gateway URL (defaults to http://127.0.0.1:8008)
        #[arg(short, long)]
        gateway: Option<String>,

        /// Authentication token for gateway
        #[arg(short, long, env = "HIGHTOWER_AUTH_TOKEN")]
        auth_token: Option<String>,

        /// Show verbose output
        #[arg(short, long)]
        verbose: bool,
    },
    /// Run services
    Run {
        #[command(subcommand)]
        command: RunCommands,
    },
}

#[derive(Subcommand, Debug)]
enum RunCommands {
    /// Run STUN server
    Stun {
        /// Address to bind to (default: 0.0.0.0:3478)
        #[arg(short, long, default_value = "0.0.0.0:3478")]
        bind: String,
    },
    /// Run gateway server
    Gateway {
        /// Path to the key-value database (default: /var/lib/hightower/gateway/db)
        #[arg(long, default_value = "/var/lib/hightower/gateway/db")]
        kv_path: String,
    },
    /// Run node client
    Node,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Stun { address } => {
            commands::stun_client::query(&address)?;
        }
        Commands::Curl {
            url,
            gateway,
            auth_token,
            verbose,
        } => {
            commands::curl::run(
                &url,
                gateway.as_deref(),
                auth_token.as_deref(),
                verbose,
            )
            .await?;
        }
        Commands::Run { command } => match command {
            RunCommands::Stun { bind } => {
                commands::stun_server::run_stun(&bind)?;
            }
            RunCommands::Gateway { kv_path } => {
                commands::gateway::run_gateway(&kv_path)?;
            }
            RunCommands::Node => {
                commands::node::run_node()?;
            }
        },
    }

    Ok(())
}
