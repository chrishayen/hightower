use anyhow::Result;
use clap::{Parser, Subcommand};
use hightower_stun::server::StunServer;

#[derive(Parser, Debug)]
#[command(name = "ht")]
#[command(about = "Hightower CLI tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run STUN server
    Stun {
        /// Address to bind to (default: 0.0.0.0:3478)
        #[arg(short, long, default_value = "0.0.0.0:3478")]
        bind: String,
    },
    /// Run gateway server
    Gateway,
    /// Run node client
    Node,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Stun { bind } => {
            println!("Starting STUN server on {}...", bind);
            let server = StunServer::bind(&bind)?;
            println!("STUN server listening on {}", server.local_addr()?);
            server.run()?;
        }
        Commands::Gateway => {
            println!("Running gateway...");
            // TODO: Import and run gateway command
        }
        Commands::Node => {
            println!("Running node...");
            // TODO: Import and run node command
        }
    }

    Ok(())
}
