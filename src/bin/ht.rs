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
    /// Run STUN server
    Stun,
    /// Run gateway server
    Gateway,
    /// Run node client
    Node,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Stun => {
            println!("Running STUN server...");
            // TODO: Import and run stun command
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
