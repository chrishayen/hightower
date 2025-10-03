mod certificates;
mod cli;
mod mode;
mod node;
mod token;

use clap::Parser;

use crate::cli::Cli;
use crate::mode::Mode;

fn main() {
    let cli = Cli::parse();
    let mode = mode::resolve(&cli);

    let _token = token::fetch(|key| std::env::var(key)).unwrap_or_else(|err| {
        eprintln!("{}", err);
        std::process::exit(1);
    });

    match mode {
        Mode::Root => println!("Running in root mode"),
        Mode::Node => {
            let certificate = node::startup();
            println!(
                "Running in node mode. Certificate generated with public key length {}.",
                certificate.public_key().len()
            );
        }
    }
}
