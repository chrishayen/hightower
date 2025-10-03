use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(long, conflicts_with = "root")]
    node: bool,
    #[arg(long, conflicts_with = "node")]
    root: bool,
}

fn main() {
    let cli = Cli::parse();

    if cli.root {
        println!("Running in root mode");
    } else {
        println!("Running in node mode");
    }
}
