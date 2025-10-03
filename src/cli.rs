use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(value_enum, value_name = "MODE", default_value_t = ModeArg::Node)]
    pub mode: ModeArg,
    #[arg(long = "kv", value_name = "DIR")]
    pub kv: Option<PathBuf>,
}

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum ModeArg {
    Node,
    Root,
    Dev,
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

        assert_eq!(cli.mode, ModeArg::Node);
        assert!(cli.kv.is_none());
    }

    #[test]
    fn parse_from_allows_root_mode() {
        let cli = parse_from(["hightower", "root"]);

        assert_eq!(cli.mode, ModeArg::Root);
        assert!(cli.kv.is_none());
    }

    #[test]
    fn parse_from_allows_node_mode() {
        let cli = parse_from(["hightower", "node"]);

        assert_eq!(cli.mode, ModeArg::Node);
        assert!(cli.kv.is_none());
    }

    #[test]
    fn parse_from_allows_dev_mode() {
        let cli = parse_from(["hightower", "dev"]);

        assert_eq!(cli.mode, ModeArg::Dev);
        assert!(cli.kv.is_none());
    }

    #[test]
    fn parse_from_accepts_kv_path() {
        let cli = parse_from(["hightower", "--kv", "/tmp/store"]);

        assert_eq!(cli.kv.as_deref(), Some(std::path::Path::new("/tmp/store")));
    }
}
