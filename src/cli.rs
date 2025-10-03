use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(long, conflicts_with = "root")]
    pub node: bool,
    #[arg(long, conflicts_with = "node")]
    pub root: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_from<I, T>(args: I) -> Cli
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        Cli::parse_from(args)
    }

    #[test]
    fn parse_from_defaults_to_node_flags() {
        let cli = parse_from(["hightower"]);

        assert!(!cli.root);
        assert!(!cli.node);
    }

    #[test]
    fn parse_from_allows_root_flag() {
        let cli = parse_from(["hightower", "--root"]);

        assert!(cli.root);
        assert!(!cli.node);
    }

    #[test]
    fn parse_from_allows_node_flag() {
        let cli = parse_from(["hightower", "--node"]);

        assert!(!cli.root);
        assert!(cli.node);
    }
}
