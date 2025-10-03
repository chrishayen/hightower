use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(long, conflicts_with = "root")]
    pub node: bool,
    #[arg(long, conflicts_with = "node")]
    pub root: bool,
    #[arg(long = "kv", value_name = "DIR")]
    pub kv: Option<PathBuf>,
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
    fn parse_from_defaults_flags_and_paths() {
        let cli = parse_from(["hightower"]);

        assert!(!cli.root);
        assert!(!cli.node);
        assert!(cli.kv.is_none());
    }

    #[test]
    fn parse_from_allows_root_flag() {
        let cli = parse_from(["hightower", "--root"]);

        assert!(cli.root);
        assert!(!cli.node);
        assert!(cli.kv.is_none());
    }

    #[test]
    fn parse_from_allows_node_flag() {
        let cli = parse_from(["hightower", "--node"]);

        assert!(!cli.root);
        assert!(cli.node);
        assert!(cli.kv.is_none());
    }

    #[test]
    fn parse_from_accepts_kv_path() {
        let cli = parse_from(["hightower", "--kv", "/tmp/store"]);

        assert_eq!(cli.kv.as_deref(), Some(std::path::Path::new("/tmp/store")));
    }
}
