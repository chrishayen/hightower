use clap::Parser;
use std::env;
use std::process;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(long, conflicts_with = "root")]
    node: bool,
    #[arg(long, conflicts_with = "node")]
    root: bool,
}

enum Mode {
    Node,
    Root,
}

fn main() {
    let cli = Cli::parse();
    let mode = if cli.root { Mode::Root } else { Mode::Node };

    let _token = require_token();

    match mode {
        Mode::Root => println!("Running in root mode"),
        Mode::Node => println!("Running in node mode"),
    }
}

fn require_token() -> String {
    env::var("HT_TOKEN").unwrap_or_else(|_| {
        eprintln!("HT_TOKEN environment variable must be set when running in root or node mode.");
        process::exit(1);
    })
}
