use crate::cli::{Cli, ModeArg};

#[derive(Debug, PartialEq, Eq)]
pub enum Mode {
    Node,
    Root,
    Dev,
}

pub fn resolve(cli: &Cli) -> Mode {
    match cli.mode {
        ModeArg::Node => Mode::Node,
        ModeArg::Root => Mode::Root,
        ModeArg::Dev => Mode::Dev,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_returns_node_when_root_flag_absent() {
        let cli = Cli {
            mode: ModeArg::Node,
            kv: None,
        };

        assert_eq!(resolve(&cli), Mode::Node);
    }

    #[test]
    fn resolve_prefers_root_when_flag_set() {
        let cli = Cli {
            mode: ModeArg::Root,
            kv: None,
        };

        assert_eq!(resolve(&cli), Mode::Root);
    }

    #[test]
    fn resolve_retains_node_when_flag_set() {
        let cli = Cli {
            mode: ModeArg::Node,
            kv: None,
        };

        assert_eq!(resolve(&cli), Mode::Node);
    }

    #[test]
    fn resolve_prefers_dev_when_flag_set() {
        let cli = Cli {
            mode: ModeArg::Dev,
            kv: None,
        };

        assert_eq!(resolve(&cli), Mode::Dev);
    }
}
