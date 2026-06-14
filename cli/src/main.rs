mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

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
    /// Run a STUN server
    StunServer {
        /// Address to bind to
        #[arg(short, long, default_value = "0.0.0.0:3478")]
        bind: String,
    },
    /// Run gateway server
    Gateway {
        /// Path to the key-value database
        #[arg(long = "kv", value_name = "DIR")]
        kv: Option<PathBuf>,

        /// Email address for Let's Encrypt certificate notifications
        #[arg(long, value_name = "EMAIL")]
        email: Option<String>,

        /// HTTP bind host
        #[arg(long, default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST))]
        http_host: IpAddr,

        /// HTTP bind port
        #[arg(long, default_value_t = 8008)]
        http_port: u16,

        /// Enable HTTPS listener on 0.0.0.0:443
        #[arg(long)]
        https: bool,
    },
    /// Run node client
    Node {
        /// Path to the key-value data directory
        #[arg(long = "kv", value_name = "DIR")]
        kv: Option<PathBuf>,
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Stun { address } => {
            commands::stun_client::query(&address)?;
        }
        Commands::StunServer { bind } => {
            commands::stun_server::run_stun(&bind)?;
        }
        Commands::Gateway {
            kv,
            email,
            http_host,
            http_port,
            https,
        } => {
            commands::gateway::run_gateway(kv.as_deref(), email, http_host, http_port, https)?;
        }
        Commands::Node { kv } => {
            commands::node::run_node(kv.as_deref()).await?;
        }
        Commands::Curl {
            url,
            gateway,
            auth_token,
            verbose,
        } => {
            commands::curl::run(&url, gateway.as_deref(), auth_token.as_deref(), verbose).await?;
        }
    }

    Ok(())
}
